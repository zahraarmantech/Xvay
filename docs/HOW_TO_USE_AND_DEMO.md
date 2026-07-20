# XVAY — Complete Usage & Demo Guide (English)

## What XVay is (one paragraph)
XVay is an **Execution Gate for AI agents**: an enforceable checkpoint that
sits OUTSIDE the model, between an agent's decision and its execution. For
every proposed action it returns one of three decisions with a human-readable
reason: **COMMIT** (enough evidence to execute), **VERIFY** (evidence missing —
hold for approval), **BLOCK** (explicit contradiction — rare by design).
Because it lives outside the model, it cannot be "reasoned around" the way a
system prompt can.

## What it can do (capabilities)
1. **Three-state gating** with explainable reasons (never a bare yes/no).
2. **Auto allow-list** — derived from the tool schema your agent already has
   (8 connectors: OpenAI, Anthropic, MCP, LangGraph, CrewAI, AutoGen, OpenAPI, CLI).
3. **Capability ≠ permission** — a signed *execution envelope* scopes each run:
   `delete_database` in the schema doesn't make it allowed in a read-only task.
4. **Unforgeable permissions** — envelopes are Ed25519-signed by YOUR
   orchestrator; XVay holds only the public key (verifies, can never forge);
   action-bound (hash) and single-use (nonce). Tamper/replay -> BLOCK.
5. **Shadow pilot** — one command, read-only, zero system changes: replays your
   existing action log and reports what enforcement WOULD have decided.
6. **Board-ready report** — leads with "N irreversible actions stopped before
   execution", with the exact evidence behind every decision.

## Measured results (reproducible, on the included benchmark)
- Irreversible out-of-scope actions stopped: **10/10 (100%)**
- False-block on safe in-scope actions: **0%**
- Ambiguous-scope actions correctly held for VERIFY: **8/8**
- BLOCK rate: **11%** (blocking stays rare — it's a confidence gate, not a policy engine)
Never claim more than these numbers. We never claim to have prevented any
specific named past incident — only that XVay targets that failure class.

## Folder map
- `VALIDATED/` — the product core + runnable tools (everything here is tested)
- `LAUNCH_KIT/` — landing pages (A/B), public README, outreach email,
  messaging kit, meeting/objection/lost-deal templates, discovery dashboard
- `GOVERNANCE/` — decision history, findings, founding contract
- `RESEARCH_ARCHIVE/` — full experiment history (superseded files marked)

## Setup (once, ~1 minute)
```bash
cd VALIDATED
pip install -r requirements.txt        # only dependency: pynacl
```

## Run everything (each is one command)
```bash
# 1) The gate benchmark — prints the headline numbers above
python3 execution_gate.py

# 2) Shadow pilot on the included sample (read-only, writes only report.html)
python3 xvay_shadow.py --framework mcp --schema sample_mcp.json \
    --actions sample_actions.jsonl --public-key orchestrator.pub \
    --envelopes sample_envelopes.jsonl --output report.html
# open report.html in any browser

# 3) On a CUSTOMER's data: replace sample_mcp.json with their tool schema and
#    sample_actions.jsonl with their tool-call log (JSONL: {"action": "...",
#    "task_scope": "..."}). No other change. Envelopes are optional — without
#    them every uncertain action safely falls to VERIFY.
```


## Real-time enforcement (live gate)

```bash
# Beyond shadow mode: intercept a live MCP tools/call before it executes
python3 mcp_live_gate.py <mcp_calls.jsonl> <allowlist.json>
```
Each call is checked BEFORE reaching the tool: COMMIT forwards it, VERIFY/BLOCK
stop it and return the reason to the agent. This is the "live stop" — the demo
moment where a CTO sees a dangerous action blocked in real time.

## Consequence preview + protected resources
- `plan.py` prints reversibility / scope / environment for any action, computed
  from the action alone (no system connection) — terraform-plan style.
- Declare sensitive resources in the signed envelope; any non-read action on
  them is blocked. You declare sensitivity; XVay never guesses it.

## Run the full self-check (proves the whole chain works together)
```bash
python3 integration_benchmark.py    # expect: ALL PASS (exit 0)
```

## HOW TO GIVE THE DEMO (3 minutes, follow exactly)

**Open `VALIDATED/DEMO.html` in a browser. Then:**

1. **(30s) The hook — say this first, show scenario 1:**
   "Your AI agent is one mistake away from production disaster. Watch."
   Scenario 1: agent tries to delete the production database →
   **BLOCK**, with the reason on screen. Stop talking for 3 seconds.

2. **(30s) Scenario 2 — a rule the model ignored:**
   "A code freeze was declared. The model reasoned around it — because a
   prompt is advice. XVay is enforcement: it sits outside the model." → BLOCK.

3. **(30s) Scenario 3 — no friction:**
   "And normal work? Zero friction." → COMMIT with reason.
   Then the numbers line: 10/10 stopped, 0% false-block.

4. **(60s) The shadow pilot — the close:**
   Open `report.html` (or run command #2 live — it takes seconds).
   "This is the same gate replayed over an action log — read-only, one
   command, nothing in your system changes. Headline: N irreversible actions
   would have executed without it. We can run this on YOUR logs in 30 minutes."

5. **(30s) The golden question — always end with exactly this:**
   *"If this existed for Claude Code / Cursor / Copilot, would you turn it
   on? Why — or why not?"*
   Then: *"To be direct: I'm trying to find out whether there's a reason you
   would NOT deploy this. If there is, tell me bluntly."*

**After the meeting:** fill `LAUNCH_KIT/MEETING_NOTES_TEMPLATE.md` within 1
hour (their words, verbatim), update `OBJECTION_LOG.md` and the
`DISCOVERY_DASHBOARD.md`. Valid outcomes only: pilot / precise no / intro.

## The honest answer to "why not build this ourselves?"
"You can — the gate is 11 lines. What you can't build in a weekend is knowing
when your gate is WRONG: calibrated thresholds on your own logs, measured
false-friction, and our measured list of integrations that make agents worse.
Run the read-only shadow pilot; if the report shows nothing, build in-house —
you'll have lost 30 minutes."

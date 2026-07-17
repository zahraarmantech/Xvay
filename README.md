<h1 align="center">Xvay</h1>
<p align="center"><b>An execution gate for AI agents.</b><br>
Commit · Verify · Block — outside the model, so it can't be reasoned around.</p>

<p align="center">
<a href="#quickstart">Quickstart</a> ·
<a href="#how-it-works">How it works</a> ·
<a href="#benchmark">Benchmark</a> ·
<a href="#faq">FAQ</a>
</p>

---

## The problem

AI agents now execute real actions — they delete databases, run code, move
money. Their "safety layer" today is a system prompt: advice the model can
reason around. When it does, the action still runs. Xvay is the enforceable
version: a checkpoint **outside** the model that returns one of three decisions
before an action executes.

```text
Agent:  Deleting production database...

Xvay:   ❌ BLOCKED
        production environment · irreversible operation
        human approval required · never executed
```

- 🟢 **COMMIT** — enough evidence, let it run
- 🟡 **VERIFY** — evidence missing, hold for approval
- 🔴 **BLOCK** — explicit contradiction, refuse (rare by design)

## Quickstart

Read-only shadow mode on your own logs — changes nothing, one command:

```bash
pip install -r requirements.txt        # only dependency: pynacl
python xvay_shadow.py \
  --framework mcp \                     # openai | anthropic | mcp | langgraph | crewai | autogen | openapi | cli
  --schema your_tools.json \
  --actions your_log.jsonl \
  --output report.html
```

The report leads with how many irreversible actions would have executed
without a gate, and shows the reason behind every decision.

## Live enforcement

```python
from connectors import to_canonical
import mcp_live_gate as gate

catalog = to_canonical("mcp", "your_tools.json")     # allow-list from your schema
decision, reason, forward = gate.check(request, catalog, task_scope="staging")
if forward:                       # COMMIT
    run_the_tool(request)
else:                             # VERIFY / BLOCK — reason handed back to the agent
    gate.gate_response(request, decision, reason)
```

## How it works

```text
tool schema ──► connector (8 frameworks) ──► capability catalog
run metadata ─► signed envelope (Ed25519) ─► scope for THIS run
                Xvay holds only the PUBLIC key: it verifies permissions,
                it cannot forge them
catalog ∩ scope ──► normalizer (standardizes, never decides)
                ──► gate ──► COMMIT / VERIFY / BLOCK  + human-readable reason
```

- **Capability ≠ permission.** A tool being in your schema doesn't make it
  allowed in a read-only run.
- **Tamper-evident scope.** Envelopes are signed by your orchestrator,
  action-bound and single-use. Forged or replayed → BLOCK.
- **You declare what's sensitive.** Xvay never guesses danger; every block is
  auditable.

## Benchmark

Reproducible: `python execution_gate.py`

| metric | result |
|---|---|
| irreversible out-of-scope actions stopped | **10/10 (100%)** |
| false-block on safe in-scope actions | **0%** |
| VERIFY on ambiguous-scope actions | **8/8** |
| BLOCK rate (kept rare by design) | **11%** |

Full-chain self-check: `python integration_benchmark.py` → `ALL PASS`.

## What Xvay is not

- Not an IAM / policy engine — it never answers "is this allowed?", only
  "is there enough evidence to execute this, now?"
- Not a second LLM — decisions are mechanical and auditable.
- It does not guess what's dangerous — you declare it.

## FAQ

**Why not build this in-house?** The gate itself is small. What isn't small is
knowing when a gate is *wrong*: calibrated thresholds on your own traffic,
measured false-friction, and the integrations that make agents worse. Run the
read-only shadow pilot; if it shows nothing, build in-house — you'll have lost
30 minutes.

**What frameworks are supported?** OpenAI / Anthropic function-calling, MCP,
LangGraph, CrewAI, AutoGen, OpenAPI, and CLI tool schemas. Adding one is a
single connector function.

## License

MIT — see [LICENSE](LICENSE).

"""
XVAY LIVE GATE — real-time MCP interception shim.
Sits in front of an MCP server: every tools/call is checked by the FROZEN gate
BEFORE it reaches the real tool. COMMIT -> forward; VERIFY/BLOCK -> stop and
return the reason to the agent. This is the enforcement path (not shadow).

Input:  a real MCP tools/call request (JSON-RPC 2.0):
  {"jsonrpc":"2.0","id":N,"method":"tools/call",
   "params":{"name":"<tool>","arguments":{...}}}
The gate never sees a clean string — it sees structured name+arguments, exactly
what a real agent emits. This module flattens name+arguments into the canonical
action the frozen gate expects. It DECIDES NOTHING itself (Normalizer rule).
"""
import json, sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from normalizer import normalize
import envelope as E
import gate_with_envelope as gwe

def call_to_action(params):
    """Flatten an MCP tools/call into one canonical action string.
    name 'kubectl_delete' + args {'resource':'namespace','target':'production'}
    -> 'kubectl delete namespace production'. Mechanical; no decision."""
    name = (params.get("name") or "").replace("_"," ").replace("-"," ").strip()
    args = params.get("arguments", {}) or {}
    parts = [name]
    # append argument VALUES in a stable order (values carry the resource/env)
    for k in sorted(args.keys()):
        v = args[k]
        if isinstance(v, (str,int,float)):
            parts.append(str(v))
        elif isinstance(v, list):
            parts.extend(str(x) for x in v)
        elif isinstance(v, dict):
            parts.extend(str(x) for x in v.values())
    return " ".join(parts).strip()

def check(request, catalog, task_scope="", envelope=None):
    """Return (decision, reason, forward: bool)."""
    if request.get("method") != "tools/call":
        return "PASS", "not a tool call", True          # only gate tool calls
    action = call_to_action(request.get("params", {}))
    decision, reason = gwe.decide(task_scope, catalog, action, envelope)
    return decision, reason, decision == "COMMIT"

def check_with_plan(request, catalog, task_scope="", envelope=None):
    """Same as check() but also returns a terraform-plan-style consequence
    preview computed from the action alone (no system connection). This makes
    every decision self-explaining and auditable without manual review."""
    from plan import plan as _plan
    decision, reason, fwd = check(request, catalog, task_scope, envelope)
    action = call_to_action(request.get("params", {}))
    preview = _plan(action)
    return {"decision": decision, "reason": reason, "forward": fwd,
            "plan": preview}

def gate_response(request, decision, reason):
    """If blocked/held, return a JSON-RPC result the AGENT sees (not an error —
    so the model can reason about it and ask for approval)."""
    return {"jsonrpc":"2.0","id":request.get("id"),
            "result":{"content":[{"type":"text",
                "text":f"[XVAY {decision}] {reason}"}],
                "isError": decision=="BLOCK"}}

if __name__ == "__main__":
    # reads a JSONL of real MCP tools/call requests on argv[1]
    catalog = json.load(open(sys.argv[2]))["allow"] if len(sys.argv)>2 else []
    for line in open(sys.argv[1], encoding="utf-8"):
        line=line.strip()
        if not line: continue
        req = json.loads(line)
        d, reason, fwd = check(req, catalog, task_scope=req.get("_scope",""))
        arrow = "→ FORWARD to tool" if fwd else "→ STOPPED"
        print(f"{d:7s} {arrow:20s} {call_to_action(req.get('params',{}))}")

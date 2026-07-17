"""
XVAY GATE + ENVELOPE — the run-scoped entry point. Wraps the FROZEN gate with
envelope authenticity. Order of authority:
  1. envelope tampered (forged scope)  -> BLOCK   (explicit contradiction)
  2. otherwise: scope the catalog, call the UNCHANGED gate for COMMIT/VERIFY/BLOCK
Absence/expiry of envelope => no trusted scope => gate naturally yields VERIFY.
The gate's own logic is never modified; this only decides envelope authenticity
(which is not a safety decision about the action, but about the permission).
"""
import sys, json
sys.path.insert(0, __import__("os").path.dirname(__import__("os").path.abspath(__file__)))
_g = open(__import__("os").path.join(__import__("os").path.dirname(__import__("os").path.abspath(__file__)),
          "execution_gate.py")).read().split("def main")[0]
_ns={}; exec(_g,_ns); gate=_ns["gate"]
from normalizer import normalize
from envelope import load_envelope, scope_catalog

_DESTRUCTIVE = _ns["DESTRUCTIVE"]

def decide(task_scope, catalog, action, env):
    if env and env.get("_tampered"):
        return "BLOCK", f"Envelope authenticity failed: {env['_rejected']}. Forged run scope rejected."
    na = normalize(action)["normalized_action"]
    # customer-DECLARED sensitive resources (not gate guessing): any action that
    # names a protected resource and is NOT a plain read is an explicit
    # contradiction -> BLOCK. "read"-family verbs are allowed through.
    if env and not env.get("_rejected"):
        protected = env.get("protected_resources", [])
        toks = set(na.split())
        READ_OK = {"read","get","list","logs","select","describe","show","cat","view"}
        is_read = bool(toks & READ_OK) and not (toks & _DESTRUCTIVE)
        if not is_read:
            for res in protected:
                if all(p in na for p in res.lower().replace("-"," ").split()):
                    return "BLOCK", f"Non-read action on customer-declared protected resource '{res}': {na}"
    allow = scope_catalog(catalog, env)
    anchors = (env.get("anchors",[]) if env and not env.get("_rejected") else []) + ([task_scope] if task_scope else [])
    return gate(task_scope, allow, na, anchors=anchors)

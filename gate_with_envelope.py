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
import run_trace

_DESTRUCTIVE = _ns["DESTRUCTIVE"]

def decide(task_scope, catalog, action, env):
    if env and env.get("_tampered"):
        return "BLOCK", f"Envelope authenticity failed: {env['_rejected']}. Forged run scope rejected."
    na = normalize(action)["normalized_action"]
    live      = bool(env) and not env.get("_rejected")
    run_id    = (env or {}).get("run_id") if live else None
    protected = (env or {}).get("protected_resources", []) if live else []
    egress    = (env or {}).get("egress_tools", []) if live else []
    max_irrev = (env or {}).get("max_irreversible") if live else None

    toks = set(na.split())
    READ_OK = {"read","get","list","logs","select","describe","show","cat","view"}
    is_read = bool(toks & READ_OK) and not (toks & _DESTRUCTIVE)
    is_irreversible = bool(toks & _DESTRUCTIVE)
    hit_res = next((r for r in protected
                    if all(p in na for p in r.lower().replace("-"," ").split())), None)

    decision = reason = None
    # 1) customer-DECLARED protected resource, non-read -> explicit contradiction
    if hit_res and not is_read:
        decision, reason = "BLOCK", f"Non-read action on customer-declared protected resource '{hit_res}': {na}"
    # 2) CROSS-STEP checks (need the run's short memory)
    if decision is None and run_id:
        st = run_trace.get(run_id)
        hits_egress = any(all(p in na for p in t.lower().replace("_"," ").replace("-"," ").split())
                          for t in egress)
        if st["tainted"] and hits_egress:
            decision, reason = "BLOCK", (
                f"Cross-step violation: this run already read a declared protected resource "
                f"{st['touched']}; sending to a declared egress tool is not allowed ({na}).")
        elif max_irrev is not None and is_irreversible and st["irreversible"] >= max_irrev:
            decision, reason = "VERIFY", (
                f"Cross-step budget: this run already performed {st['irreversible']} "
                f"irreversible action(s), declared limit {max_irrev}. Approval required.")
    # 3) otherwise the FROZEN gate decides
    if decision is None:
        allow = scope_catalog(catalog, env)
        anchors = (env.get("anchors", []) if live else []) + ([task_scope] if task_scope else [])
        decision, reason = gate(task_scope, allow, na, anchors=anchors)
        # 3b) ARGUMENT-INTRODUCED DANGER (mechanical, no judgement):
        # the declared capability did not contain a destructive verb, but the
        # actual action does -> the arguments brought danger the schema never
        # declared. Evidence mismatch => VERIFY (never silently COMMIT).
        if decision == "COMMIT":
            act_destructive = toks & _DESTRUCTIVE
            if act_destructive:
                declared = set()
                for t in allow:
                    tt = set(normalize(t)["normalized_action"].split())
                    if tt and tt <= toks:            # this template matched the action
                        declared |= (tt & _DESTRUCTIVE)
                introduced = act_destructive - declared
                if introduced:
                    decision, reason = "VERIFY", (
                        f"Argument-introduced danger: action contains {sorted(introduced)} "
                        f"which the declared tool capability does not. Approval required.")

    # SINGLE recording point: stopped attempts are audit events too.
    # Taint only when the protected read ACTUALLY went through (COMMIT).
    if run_id:
        run_trace.record(run_id, na,
                         # taint if the protected access was NOT blocked: a VERIFY
                         # may still be approved out-of-band and executed, and XVay
                         # would never see it. Conservative on purpose.
                         touched_protected=(hit_res is not None and decision != "BLOCK"),
                         irreversible=is_irreversible,
                         committed=(decision == "COMMIT"),
                         resource=hit_res, decision=decision, reason=reason)
    return decision, reason

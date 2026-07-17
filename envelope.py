"""
XVAY EXECUTION ENVELOPE — scopes a capability catalog down to what THIS run
is allowed to touch. DECIDES NOTHING about safety; only filters the allow-list
to the declared run scope. Envelope comes from run metadata (orchestrator /
workflow config), never guessed by Xvay.

allow_for_run = capabilities whose operation is in envelope.operations
                AND (no environment restriction, or matches envelope.environment)
The gate still makes every COMMIT/VERIFY/BLOCK decision unchanged.
"""
import json
from envelope_auth import verify as _verify
def load_envelope(path, verify_key=None, action=None, now=None):
    """Load an envelope ONLY if authentic, action-bound, unexpired, unreplayed.
    EXPIRED/MISSING => no trusted scope (VERIFY). TAMPER/replay/unknown-key =>
    hard flag so the wrapper BLOCKs a forged permission."""
    if not path: return None
    d = json.load(open(path, encoding="utf-8"))
    if verify_key is not None:
        ok, reason, status = _verify(d, verify_key, action=action, now=now)
        if not ok:
            return {"_rejected": reason, "_tampered": status=="TAMPER"}
    return {"environment":set(map(str.lower,d.get("environment",[]))),
            "resources":set(map(str.lower,d.get("resources",[]))),
            "operations":set(map(str.lower,d.get("operations",[]))),
            "anchors":d.get("anchors",[]),
            "protected_resources":d.get("protected_resources",[])}
def scope_catalog(catalog, env):
    """Keep capabilities whose operation is permitted this run; emit variants
    binding the run's resources (alone and environment-prefixed). Mechanical."""
    if not env: return catalog
    if env.get("_rejected"): return []   # tampered/expired -> no trusted capability
    ops = env["operations"]; resources = env["resources"]; envs = env["environment"]
    kept=[]
    for action in catalog:
        toks = action.lower().replace("-"," ").replace("_"," ").split()
        hit_ops = [op for op in ops if op in toks]
        if not hit_ops: continue
        kept.append(action)
        prefix = " ".join(toks[:toks.index(hit_ops[0])+1])   # e.g. 'kubectl rollout restart'
        res_variants = set()
        for res in resources:
            r = res.replace("-"," ").replace("_"," ")
            res_variants.add(r)
            for e in envs: res_variants.add((e + " " + r).strip())   # env-prefixed resource
        for rv in res_variants:
            kept.append((prefix + " " + rv).strip())
            kept.append((hit_ops[0] + " " + rv).strip())
    return list(dict.fromkeys(kept))

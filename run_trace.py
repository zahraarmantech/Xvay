"""
XVAY RUN TRACE — the minimum memory needed to see ACROSS steps of one run.
NOT a transaction manager: no shadow execution, no effect outbox, no rollback.
It remembers only what XVay ALLOWED plus what it STOPPED, so chains that look
innocent step-by-step are caught and the orchestrator can compensate.

Backed by store.py — swap in a shared store (Redis/File) and cross-step
protection holds across workers. Decides nothing itself.
"""
import store

_MAX_RUNS = 10_000
_BLANK = {"tainted": False, "irreversible": 0, "steps": 0,
          "committed": [], "denied": [], "touched": []}

def _key(run_id): return "run:" + str(run_id)

def _evict_if_needed():
    ks = [k for k in store.current().keys() if k.startswith("run:")]
    while len(ks) >= _MAX_RUNS:
        store.current().delete(ks.pop(0))

def _blank():
    return {k: (list(v) if isinstance(v, list) else v) for k, v in _BLANK.items()}

def get(run_id):
    """READ-ONLY. Never writes, so it cannot race."""
    return store.current().get(_key(run_id)) or _blank()

def record(run_id, action=None, *, touched_protected=False, irreversible=False,
           committed=False, resource=None, decision=None, reason=None):
    """ATOMIC: the whole read-modify-write happens inside one store lock, so
    concurrent workers on the same run cannot lose each other's writes."""
    _evict_if_needed()
    def _mut(r):
        r = r or _blank()
        r["steps"] += 1
        if touched_protected:
            r["tainted"] = True
            if resource and resource not in r["touched"]: r["touched"].append(resource)
        if committed:
            r["committed"].append({"action": action, "irreversible": irreversible})
            if irreversible: r["irreversible"] += 1
        else:
            r["denied"].append({"action": action, "decision": decision, "reason": reason})
        return r
    return store.current().update(_key(run_id), _mut)

def manifest(run_id):
    r = get(run_id)
    return {"run_id": run_id, "committed": list(r["committed"]),
            "irreversible_committed": [c["action"] for c in r["committed"] if c["irreversible"]],
            "compensation_required": any(c["irreversible"] for c in r["committed"])}

def receipt(run_id):
    r = get(run_id)
    return {"run_id": run_id, "steps_seen": r["steps"], "committed": len(r["committed"]),
            "irreversible_committed": r["irreversible"], "stopped": len(r["denied"]),
            "stopped_detail": list(r["denied"]), "touched_protected": r["touched"],
            "tainted": r["tainted"]}

def reset(run_id=None):
    if run_id is None:
        for k in list(store.current().keys()):
            if k.startswith("run:"): store.current().delete(k)
    else:
        store.current().delete(_key(run_id))

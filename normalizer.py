"""
XVAY NORMALIZER — standardizes raw agent actions. DECIDES NOTHING.
Rule (locked): no code before XVay may make a decision; it may only
standardize data. This module ONLY: splits glued tokens, unifies plurals,
extracts the resource string for display. Output feeds the UNCHANGED gate.
"""
import re
def normalize(action: str):
    a = action.strip()
    # 1) remove CLI flags first (tokens starting with '-'), preserving real verbs like 'rm'
    raw = a.lower().split()
    flags = [t for t in raw if t.startswith("-")]           # e.g. -rf, -f, -n, --tail
    kept  = [t for t in raw if not t.startswith("-")]
    a = " ".join(kept)
    a = a.replace("-", " ").replace("/", " ")               # split any remaining glued tokens
    toks = a.split()
    toks = [t for t in toks if not t.startswith("tail")]    # drop --tail style modifiers
    # 2) preserve a bulk signal if a recursive/force flag was present (-rf, -r, --recursive)
    if any(("r" in f) for f in flags):
        toks.append("recursive")
    unified = []
    for t in toks:
        if t.endswith("s") and len(t) > 3 and t[:-1] in {"pod","node","volume","service","deployment","namespace","bucket","instance","table","database"}:
            unified.append(t[:-1])                    # pods->pod (display/consistency only)
        else:
            unified.append(t)
    norm_action = " ".join(unified)
    # resource extraction for DISPLAY ONLY (never used for the decision)
    resource = ""
    for t in toks:
        if any(k in t for k in ("prod","staging","dev","db","-data","backup")):
            resource = t; break
    return {"normalized_action": norm_action, "resource": resource, "raw": action}

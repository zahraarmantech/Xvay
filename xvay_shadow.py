#!/usr/bin/env python3
"""
XVAY SHADOW GATEWAY — single-command, read-only pilot entry point.
Chains: connector -> envelope verify -> normalizer -> frozen gate -> HTML report.
Shadow mode: stops NOTHING; records what enforcement mode WOULD decide.
No core file is modified; no write access beyond the report; no agent changes.

  xvay-shadow --framework mcp --schema tools.json --actions actions.jsonl \
               --public-key orchestrator.pub --envelopes envelopes.jsonl \
               --output report.html
"""
import argparse, json, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from connectors import to_canonical
from normalizer import normalize
import envelope as E
import gate_with_envelope as gwe
from shadow_pilot import render  # reuse the report renderer

def load_actions(path):
    rows=[]
    if path.endswith(".csv"):
        import csv
        for r in csv.DictReader(open(path,encoding="utf-8")):
            rows.append((r.get("task_scope","").strip(), r.get("action","").strip(), r))
    else:
        for line in open(path,encoding="utf-8"):
            line=line.strip()
            if not line: continue
            d=json.loads(line); rows.append((str(d.get("task_scope","")).strip(),
                                             str(d.get("action","")).strip(), d))
    return rows

def load_vk(path):
    if not path: return None
    from nacl.signing import VerifyKey
    data=open(path,"rb").read().strip()
    try: return VerifyKey(bytes.fromhex(data.decode()))
    except Exception: return VerifyKey(data)

def main():
    ap=argparse.ArgumentParser(prog="xvay-shadow")
    ap.add_argument("--framework", required=True)
    ap.add_argument("--schema", required=True)
    ap.add_argument("--actions", required=True)
    ap.add_argument("--public-key", dest="pub", default="")
    ap.add_argument("--envelopes", default="")   # optional JSONL: {action: envelope}
    ap.add_argument("--output", default="report.html")
    a=ap.parse_args()

    catalog = to_canonical(a.framework, a.schema)
    vk = load_vk(a.pub) if a.pub else None
    envmap={}
    if a.envelopes and os.path.exists(a.envelopes):
        for line in open(a.envelopes,encoding="utf-8"):
            if line.strip():
                d=json.loads(line); envmap[d.get("action","")]=d.get("envelope",d)

    from shadow_pilot import reversibility, is_destructive
    res=[]
    for scope, action, raw in load_actions(a.actions):
        env=None
        if action in envmap and vk is not None:
            json.dump(envmap[action], open("/tmp/_env.json","w"))
            env=E.load_envelope("/tmp/_env.json", verify_key=vk, action=action)
        decision, reason = gwe.decide(scope, catalog, action, env)
        na=normalize(action)["normalized_action"]
        res.append({"scope":scope,"action":action,"anchors":[],
                    "decision":decision,"reason":reason,
                    "destructive":is_destructive(na),
                    "reversibility":reversibility(na)})
    open(a.output,"w",encoding="utf-8").write(render(res, a.actions))
    c={"COMMIT":0,"VERIFY":0,"BLOCK":0}
    for r in res: c[r["decision"]]+=1
    print(f"[shadow] {len(res)} actions -> COMMIT {c['COMMIT']} / VERIFY {c['VERIFY']} / BLOCK {c['BLOCK']}")
    print(f"[shadow] report: {a.output}  (shadow mode: nothing was stopped)")

if __name__=="__main__":
    main()

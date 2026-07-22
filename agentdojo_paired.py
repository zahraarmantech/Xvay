"""
XVay vs AgentDojo — modelling the attack the way it actually happens:
the agent performs the BENIGN user task, and the injection hijacks it into ALSO
making the attacker's call. So each run = [user task calls...] + [attacker call].
That is the run XVay would see in production.
"""
import sys, json, itertools, os
sys.path.insert(0, ".")
from agentdojo.task_suite.load_suites import get_suites
import envelope_auth as EA, envelope as E, mcp_live_gate as mm, run_trace
from connectors import to_canonical

sk, vk = EA.keypair(); _n = itertools.count()

def mcp(c): return {"method":"tools/call","params":{"name":c.function,"arguments":dict(c.args)}}

def decide(c, allow, ops, prot, egr, run):
    req = mcp(c); action = mm.call_to_action(req["params"])
    env_d = {"run_id":run,"agent_id":"a","environment":["prod"],"resources":[],
             "operations":list(ops),"anchors":[],"protected_resources":list(prot),
             "egress_tools":list(egr),"max_irreversible":None,
             "action_hash":EA.action_hash(action),"nonce":f"p{next(_n)}",
             "issued_at":"2026-07-11T20:00:00Z","expires_at":"2999-01-01T00:00:00Z"}
    json.dump(EA.sign(env_d, sk), open("_p.json","w"))
    env = E.load_envelope("_p.json", verify_key=vk, action=action)
    return mm.check(req, allow, task_scope="prod", envelope=env)[0]

def run_mode(mode, pair_limit=6):
    suites = get_suites("v1.2.1")
    stopped = total = 0; ben_ok = ben_tot = 0; leak_tools = {}
    for name, s in suites.items():
        tools = [t.name for t in s.tools]
        json.dump({"tools":[{"name":t} for t in tools]}, open("_s.json","w"))
        allow = to_canonical("openai","_s.json")
        ops = sorted({t.split("_")[0].lower() for t in tools})
        if mode == "zero-config":
            prot, egr = [], []
        else:   # protective: reads are sensitive, outbound tools are egress
            prot = [t for t in tools if t.split("_")[0] in ("read","get","search","list")]
            egr  = [t for t in tools if t.split("_")[0] in ("send","post","invite","share","reserve","schedule","update")]
        env0 = s.load_and_inject_default_environment({})
        users = list(s.user_tasks.items())[:pair_limit]
        for tid, it in s.injection_tasks.items():
            try: atk = it.ground_truth(env0)
            except Exception: continue
            for uid, ut in users:
                try: ben = ut.ground_truth(env0)
                except Exception: continue
                rid = f"{name}-{tid}-{uid}"; run_trace.reset(rid)
                for c in ben:                      # benign steps first
                    ben_tot += 1
                    if decide(c, allow, ops, prot, egr, rid) == "COMMIT": ben_ok += 1
                for c in atk:                      # then the hijacked call
                    total += 1
                    d = decide(c, allow, ops, prot, egr, rid)
                    if d == "COMMIT": leak_tools[f"{name}:{c.function}"] = leak_tools.get(f"{name}:{c.function}",0)+1
                    else: stopped += 1
    return stopped, total, ben_ok, ben_tot, leak_tools

for mode in ("zero-config","protective"):
    st, tot, bok, btot, leaks = run_mode(mode)
    fr = 100 - 100*bok/max(btot,1)
    print(f"=== {mode} (attack injected into a real user task) ===")
    print(f"  attacker call stopped : {st}/{tot} = {100*st/max(tot,1):.0f}%")
    print(f"  benign steps allowed  : {bok}/{btot} = {100*bok/max(btot,1):.0f}%   (friction {fr:.0f}%)")
    if leaks:
        top = sorted(leaks.items(), key=lambda x:-x[1])[:5]
        print(f"  top leaked: {dict(top)}")
    print()
for f in ("_p.json","_s.json"):
    if os.path.exists(f): os.remove(f)

"""
Proof that cross-step protection survives MULTIPLE WORKERS.
Two SEPARATE OS processes share one run through FileStore:
  worker A: reads a protected resource  -> COMMIT (run becomes tainted)
  worker B: sends to a declared egress  -> must be BLOCK
Control: the same two steps WITHOUT a shared store must leak, proving the test
is real. Then 20 concurrent writers must lose nothing.

All paths are passed as ARGUMENTS, never embedded in generated source, so
Windows backslashes cannot become Python escape sequences.

Run:  python multiprocess_test.py
"""
import os, subprocess, sys, tempfile

HERE   = os.path.dirname(os.path.abspath(__file__))
TMP    = tempfile.gettempdir()
SHARED = os.path.join(TMP, "xvay_mp_shared.json")

WORKER_SRC = '''
import sys, os, json, tempfile
here, shared, which, seed_hex = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
sys.path.insert(0, here)
import store
if shared != "NONE":
    store.use(store.FileStore(shared))
import envelope_auth as EA, envelope as E, mcp_live_gate as mm
from nacl.signing import SigningKey
sk = SigningKey(bytes.fromhex(seed_hex)); vk = sk.verify_key
CAT = ["slack post message", "read file"]
if which == "A":
    action = "read file customer-records"
    params = {"name": "read_file", "arguments": {"path": "customer-records"}}
    nonce = "mp1"
else:
    action = "slack post message leak"
    params = {"name": "slack_post_message", "arguments": {"channel": "external"}}
    nonce = "mp2"
env_d = {"run_id": "SHARED-RUN", "agent_id": "a", "environment": ["staging"],
         "resources": [], "operations": ["read", "post", "get"], "anchors": [],
         "protected_resources": ["customer-records"],
         "egress_tools": ["slack_post_message"], "max_irreversible": None,
         "action_hash": EA.action_hash(action), "nonce": nonce,
         "issued_at": "2026-07-11T20:00:00Z", "expires_at": "2999-01-01T00:00:00Z"}
p = os.path.join(tempfile.gettempdir(), "_xvay_env_" + which + ".json")
json.dump(EA.sign(env_d, sk), open(p, "w"))
env = E.load_envelope(p, verify_key=vk, action=action)
d, reason, fwd = mm.check({"method": "tools/call", "params": params}, CAT,
                          task_scope="staging", envelope=env)
print(d)
'''

RACER_SRC = '''
import sys
here, shared, i = sys.argv[1], sys.argv[2], sys.argv[3]
sys.path.insert(0, here)
import store
store.use(store.FileStore(shared))
import run_trace
run_trace.record("RACE", "a" + i, committed=True, irreversible=True)
'''

def _write(name, src):
    p = os.path.join(TMP, name)
    with open(p, "w") as f: f.write(src)
    return p

def _clean():
    junk = [SHARED, SHARED + ".lock"]
    junk += [os.path.join(TMP, "_xvay_env_" + w + ".json") for w in ("A", "B")]
    for f in junk:
        try: os.remove(f)
        except OSError: pass

def main():
    sys.path.insert(0, HERE)
    from nacl.signing import SigningKey
    seed_hex = bytes(SigningKey.generate()._seed).hex()
    worker = _write("_xvay_worker.py", WORKER_SRC)
    racer  = _write("_xvay_racer.py",  RACER_SRC)
    ok = True

    def run(which, shared):
        r = subprocess.run([sys.executable, worker, HERE, shared, which, seed_hex],
                           capture_output=True, text=True)
        out = r.stdout.strip().splitlines()
        if not out:
            return "ERROR: " + (r.stderr.strip().splitlines() or ["no output"])[-1]
        return out[-1]

    _clean()
    a, b = run("A", SHARED), run("B", SHARED)
    print(f"WITH shared store   : A={a}  B={b}   (B must be BLOCK)")
    ok &= (a == "COMMIT" and b == "BLOCK")

    a2, b2 = run("A", "NONE"), run("B", "NONE")
    print(f"WITHOUT shared store: A={a2}  B={b2}   (B leaks — proves the test is real)")
    ok &= (b2 == "COMMIT")

    _clean()
    procs = [subprocess.Popen([sys.executable, racer, HERE, SHARED, str(i)],
                              stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
             for i in range(20)]
    errs = [p.communicate()[1] for p in procs]
    import store, run_trace
    store.use(store.FileStore(SHARED))
    n = run_trace.receipt("RACE")["committed"]
    print(f"20 concurrent writers: {n}/20 recorded   (must be 20 — no lost writes)")
    if n != 20:
        for e in errs:
            if e and e.strip():
                print("   first worker error:", e.strip().splitlines()[-1]); break
    ok &= (n == 20)

    _clean()
    print("\nMULTIPROCESS TEST:", "ALL PASS" if ok else "FAILED")
    sys.exit(0 if ok else 1)

if __name__ == "__main__":
    main()

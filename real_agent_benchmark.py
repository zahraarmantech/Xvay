"""
REAL-AGENT BENCHMARK — run XVay against real, recorded agent traffic.

This does NOT use traffic we invented. It replays actual agent trajectories
(real tool calls, on real GitHub issues) from public datasets through the
shipped gate, reporting:

  - COMPATIBILITY: does XVay produce a verdict for the agent's real tool shapes,
    or does it choke / mis-parse them?
  - FRICTION: how many ordinary, benign agent calls does it stop? (a high number
    on real dev traffic means the product would be uninstalled)
  - WHAT IT STOPPED: every VERIFY/BLOCK, with the reason, so you can eyeball
    whether each stop is justified or a false positive.

Three INDEPENDENT frameworks are supported, because a security tool that only
works on one agent's tool format — or one problem domain — is not a product.
They emit different tool shapes AND cover different domains on purpose:

  - openhands : SWE / bash. Tools declared as JSON objects (OpenAI function form)
  - sweagent  : SWE / bash. Tools declared as JSON *strings* (json.loads first),
                and file edits authored via `cat > file << EOF` heredocs
  - apigen    : airline / structured API, NON-bash. Tools are booking/lookup
                calls (book_reservation, cancel_reservation, ...); tool calls
                live in a `conversations` stream, not a `trajectory`

The first two are both coding agents; apigen is a different domain entirely, so
passing all three shows XVay is not merely tuned to one agent's bash habits.

XVay is deliberately honest about its scope: these trajectories are benign
work, so the RIGHT result is near-zero friction. A wall of BLOCKs here would
mean XVay is broken, not strong. The value XVay adds only shows up on traffic
that tries to leave scope — which these datasets mostly do not contain. So this
benchmark measures COMPATIBILITY + FRICTION honestly, and is NOT a claim that
XVay "caught attacks" (there are ~none here to catch).

Requires:  pip install datasets
Usage:     python real_agent_benchmark.py                     # openhands, 25 traj
           python real_agent_benchmark.py 100 sweagent        # sweagent, 100 traj
           python real_agent_benchmark.py 40 apigen           # apigen, 40 traj
"""
import sys, json
sys.path.insert(0, ".")
import mcp_live_gate as gate

# Each framework: the dataset, the split, and how its tools are declared.
FRAMEWORKS = {
    "openhands": {
        "dataset": "nebius/SWE-rebench-openhands-trajectories",
        "split": "train",
        "label": "OpenHands",
        "shape": "trajectory",   # tools=dicts, calls in trajectory[].tool_calls
        "domain": "SWE / bash",
    },
    "sweagent": {
        "dataset": "nvidia/Open-SWE-Traces",
        "config": "sweagent",
        "split": "qwen35_122b",
        "label": "SWE-agent",
        "shape": "trajectory",   # tools=JSON strings, calls in trajectory[].tool_calls
        "domain": "SWE / bash",
    },
    "apigen": {
        "dataset": "Salesforce/APIGen-MT-5k",
        "split": "train",
        "label": "APIGen",
        "shape": "conversations",  # tools=dicts, calls in conversations[] from=function_call
        "domain": "airline / structured API (non-bash)",
    },
}


def load_real(framework, n):
    from datasets import load_dataset
    fw = FRAMEWORKS[framework]
    if "config" in fw:
        ds = load_dataset(fw["dataset"], fw["config"], split=fw["split"], streaming=True)
    else:
        ds = load_dataset(fw["dataset"], split=fw["split"], streaming=True)
    out = []
    for i, row in enumerate(ds):
        if i >= n:
            break
        out.append(row)
    return out


def build_catalog(tools_field):
    """Turn the trajectory's declared tools into XVay's catalog form.

    Handles every shape seen across the three frameworks:
      - a list of dicts in OpenAI function form (OpenHands)
      - a list of JSON *strings* that must be parsed first (SWE-agent)
      - a list of dicts with a top-level `name` (APIGen)
      - the whole field given as one JSON string
    A connector that only understood one shape would report 100% friction on
    another framework purely because it never built a catalog — so this
    multi-shape parse is exactly what a real connector must do."""
    cat = []
    if not tools_field:
        return cat
    if isinstance(tools_field, str):
        try:
            tools_field = json.loads(tools_field)
        except Exception:
            return cat
    for t in tools_field:
        if isinstance(t, str):
            try:
                t = json.loads(t)
            except Exception:
                continue
        fn = t.get("function", t) if isinstance(t, dict) else {}
        name = fn.get("name")
        if name:
            cat.append(name.replace("_", " "))
    return cat


def derive_operations(catalog):
    """The operations the agent is authorised to perform = the leading verb of
    each of its own declared tools. This is the zero-config posture: the agent's
    own tool manifest defines its scope, nothing hand-declared."""
    ops = set()
    for c in catalog:
        for w in c.split():
            ops.add(w.lower())
    return sorted(ops)


def make_envelope(catalog):
    return {
        "environment": ["workspace"],
        "resources": ["workspace"],
        "operations": derive_operations(catalog),
        "anchors": [],
        "protected_resources": [],
        "egress_tools": [],
    }


def iter_tool_calls(traj_row, shape="trajectory"):
    """Yield (name, args) for every agent tool call in a trajectory,
    normalising the JSON-string arguments frameworks sometimes use.

    Two record shapes are supported:
      - "trajectory"   : OpenHands / SWE-agent. Calls live in
                         trajectory[].tool_calls[].function.
      - "conversations": APIGen. Calls live in conversations[] entries whose
                         `from` is "function_call", with a JSON body carrying
                         name + arguments. A different domain entirely (airline
                         API, not bash), which is the point of testing it."""
    if shape == "conversations":
        for msg in traj_row.get("conversations", []):
            if msg.get("from") != "function_call":
                continue
            body = msg.get("value", "")
            if isinstance(body, str):
                try:
                    body = json.loads(body)
                except Exception:
                    continue
            if isinstance(body, dict):
                yield body.get("name"), body.get("arguments")
        return
    for msg in traj_row.get("trajectory", []):
        if msg.get("role") != "assistant":
            continue
        for tc in (msg.get("tool_calls") or []):
            fn = tc.get("function", {})
            name = fn.get("name")
            args = fn.get("arguments")
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except Exception:
                    pass
            yield name, args


def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 25
    framework = sys.argv[2] if len(sys.argv) > 2 else "openhands"
    if framework not in FRAMEWORKS:
        print(f"Unknown framework '{framework}'. Choose one of: {', '.join(FRAMEWORKS)}")
        sys.exit(1)

    label = FRAMEWORKS[framework]["label"]
    dataset = FRAMEWORKS[framework]["dataset"]
    shape = FRAMEWORKS[framework].get("shape", "trajectory")
    domain = FRAMEWORKS[framework].get("domain", "")
    print(f"Loading {n} REAL {label} trajectories from {dataset} ...")
    if domain:
        print(f"  (domain: {domain})")
    traj = load_real(framework, n)
    print(f"Loaded {len(traj)} trajectories.\n")

    total = commit = verify = block = errors = 0
    stops = []       # (tool, decision, reason, args_preview)
    parse_fail = []

    for t in traj:
        catalog = build_catalog(t.get("tools"))
        envelope = make_envelope(catalog)   # zero-config: scope = agent's own tools
        task_scope = "workspace"
        for name, args in iter_tool_calls(t, shape=shape):
            req = {"method": "tools/call",
                   "params": {"name": name, "arguments": args}}
            total += 1
            try:
                d, reason, _ = gate.check(req, catalog,
                                          task_scope=task_scope, envelope=envelope)
            except Exception as e:
                errors += 1
                parse_fail.append((name, type(e).__name__, str(e)[:80]))
                continue
            if d == "COMMIT":
                commit += 1
            elif d == "VERIFY":
                verify += 1
                stops.append((name, d, reason, str(args)[:80]))
            elif d == "BLOCK":
                block += 1
                stops.append((name, d, reason, str(args)[:80]))

    print("=" * 70)
    print(f"REAL {label} TRAFFIC — {total} tool calls across {len(traj)} trajectories")
    print("=" * 70)
    print(f"  COMMIT (allowed) : {commit}/{total} = {100*commit/max(total,1):.1f}%")
    print(f"  VERIFY (held)    : {verify}/{total} = {100*verify/max(total,1):.1f}%")
    print(f"  BLOCK  (stopped) : {block}/{total} = {100*block/max(total,1):.1f}%")
    print(f"  ERRORS (couldn't parse) : {errors}/{total}")
    print(f"\n  FRICTION (held+stopped on benign dev traffic): "
          f"{verify+block}/{total} = {100*(verify+block)/max(total,1):.1f}%")

    if errors:
        print(f"\n  --- COMPATIBILITY PROBLEMS ({len(parse_fail)}) ---")
        seen = {}
        for name, etype, msg in parse_fail:
            k = (name, etype)
            if k in seen:
                continue
            seen[k] = 1
            print(f"    {name}: {etype}: {msg}")

    if stops:
        print(f"\n  --- EVERY STOP, WITH REASON (eyeball these) ---")
        from collections import Counter
        by_tool = Counter(s[0] for s in stops)
        print(f"  stops by tool: {dict(by_tool)}")
        print()
        shown = 0
        for name, d, reason, args in stops:
            print(f"    [{d}] {name}({args})")
            print(f"          -> {reason[:100]}")
            shown += 1
            if shown >= 20:
                print(f"    ... and {len(stops)-20} more")
                break

    print("\n" + "=" * 70)
    print("HOW TO READ THIS:")
    print("  - Near-zero friction  = XVay stays out of the way on real dev work. GOOD.")
    print("  - Zero parse errors   = XVay is COMPATIBLE with this agent's tool shapes.")
    print("  - A wall of BLOCKs    = something is WRONG (this traffic is benign).")
    print("  - This does NOT measure attack-catching: there are ~no attacks here.")
    others = [f for f in FRAMEWORKS if f != framework]
    print(f"  - Run the OTHER frameworks too, on independent domains:")
    for o in others:
        print(f"      python real_agent_benchmark.py {n} {o}    ({FRAMEWORKS[o]['domain']})")


if __name__ == "__main__":
    main()

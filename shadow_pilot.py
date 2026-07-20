#!/usr/bin/env python3
"""
XVAY SHADOW PILOT — read-only, offline, zero-integration.
Feed it an existing agent tool-call log; it runs the FROZEN execution gate on
every action and writes an HTML report. It never touches the agent, never
writes anywhere except the report, never intervenes in execution.

USAGE:  python3 shadow_pilot.py <log.jsonl|log.csv> [report.html]
LOG ROWS (any of): {"action": "...", "task_scope": "...", "anchors": [...]}
  CSV: columns action, task_scope, (optional) anchors  — anchors ';'-separated.

Report sections (exactly the five required):
  1. Total actions reviewed
  2. COMMIT / VERIFY / BLOCK counts
  3. Irreversible actions lacking evidence (VERIFY/BLOCK on destructive)
  4. False-block candidates (BLOCK the reviewer may want to inspect)
  5. Exact evidence behind every decision
Plus the without/with XVay summary line.
"""
import sys, json, csv, html, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
# reuse the FROZEN gate logic, unchanged
_g = open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "execution_gate.py")).read().split("def main")[0]
ns = {}; exec(_g, ns)
gate = ns["gate"]; DESTRUCTIVE = ns["DESTRUCTIVE"]; PROD_SCOPE = ns["PROD_SCOPE"]
from normalizer import normalize
from envelope import load_envelope, scope_catalog
IRREVERSIBLE_MARKERS = {"database","backup","namespace","volume","instance","table"}
def reversibility(na):
    w=set(na.split())
    if (w & DESTRUCTIVE) and (w & (IRREVERSIBLE_MARKERS | PROD_SCOPE)):
        return "IRREVERSIBLE"
    return "RECOVERABLE"

def load_allowlist(path):
    import os,json as _j
    if not path or not os.path.exists(path): return []
    if path.endswith(".json"):
        d=_j.load(open(path,encoding="utf-8")); return d.get("allow",d) if isinstance(d,dict) else d
    return [l.strip() for l in open(path,encoding="utf-8") if l.strip()]

def load(path):
    rows = []
    if path.endswith(".csv"):
        with open(path, encoding="utf-8") as f:
            for r in csv.DictReader(f):
                anc = (r.get("anchors") or "").split(";") if r.get("anchors") else []
                rows.append((r.get("task_scope","").strip(),
                             r.get("action","").strip(),
                             [a for a in anc if a]))
    else:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line=line.strip()
                if not line: continue
                d=json.loads(line)
                rows.append((str(d.get("task_scope","")).strip(),
                             str(d.get("action","")).strip(),
                             d.get("anchors",[]) or []))
    return rows

def is_destructive(action):
    a = action.lower().replace("/"," ").split()
    return any(w in DESTRUCTIVE for w in a)

def analyze(rows, allow, env=None):
    allow = scope_catalog(allow, env)
    env_anchors = env['anchors'] if env else []
    out=[]
    for scope, action, anchors in rows:
        norm = normalize(action)                       # standardize only, no decision
        na = norm["normalized_action"]
        decision, reason = gate(scope, allow, na,
                                anchors=(anchors or []) + env_anchors + ([scope] if scope else []))
        out.append({"scope":scope,"action":action,"anchors":anchors,
                    "resource":norm["resource"],
                    "decision":decision,"reason":reason,
                    "destructive":is_destructive(na),
                    "reversibility":reversibility(na)})
    return out

def esc(s): return html.escape(str(s))

def render(res, src):
    n=len(res)
    counts={"COMMIT":0,"VERIFY":0,"BLOCK":0}
    for r in res: counts[r["decision"]]+=1
    irreversible=[r for r in res if r.get("reversibility")=="IRREVERSIBLE" and r["decision"] in ("VERIFY","BLOCK")]
    falseblock=[r for r in res if r["decision"]=="BLOCK"]
    stopped=[r for r in res if r["decision"] in ("VERIFY","BLOCK")]
    C={"COMMIT":"#3fb950","VERIFY":"#d29922","BLOCK":"#f85149"}
    def rowhtml(r):
        return (f"<tr><td><code>{esc(r['action'])}</code></td>"
                f"<td>{esc(r['scope'])}</td>"
                f"<td style='color:{C[r['decision']]};font-weight:700'>{r['decision']}</td>"
                f"<td class='rsn'>{esc(r['reason'])}</td></tr>")
    return f"""<!DOCTYPE html><html><head><meta charset="UTF-8">
<title>XVay Shadow Pilot Report</title><style>
body{{background:#0d1117;color:#e6edf3;font:14px/1.6 -apple-system,Segoe UI,Roboto,sans-serif;max-width:1040px;margin:0 auto;padding:36px 20px}}
h1{{font-size:26px}} h2{{font-size:13px;color:#8b949e;text-transform:uppercase;letter-spacing:1px;margin:30px 0 10px}}
.sub{{color:#8b949e}} .big{{font-size:40px;font-weight:700}}
.cards{{display:flex;gap:14px;margin:14px 0}}
.card{{flex:1;background:#161b22;border:1px solid #30363d;border-radius:10px;padding:16px 18px;text-align:center}}
table{{width:100%;border-collapse:collapse;margin-top:8px}}
td,th{{border-bottom:1px solid #21262d;padding:8px 10px;text-align:left;vertical-align:top}}
th{{color:#8b949e;font-size:12px;text-transform:uppercase;letter-spacing:1px}}
code{{font-family:ui-monospace,Menlo,monospace;font-size:12px;color:#c9d1d9}}
.rsn{{color:#8b949e;font-size:12px}}
.flag{{background:#161b22;border:1px solid #f85149;border-radius:10px;padding:14px 18px;margin:10px 0}}
.summary{{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:18px;margin:22px 0}}
.foot{{color:#8b949e;font-size:12px;margin-top:26px;border-top:1px solid #30363d;padding-top:14px}}
</style></head><body>
<h1>XVay — Shadow Pilot Report</h1>
<div class="summary" style="border-color:#f85149"><div class="lbl" style="color:#f85149">HEADLINE</div>
<b style="font-size:22px">{len(irreversible)} irreversible action(s) stopped before execution.</b><br>
<span class="sub">Without XVay these would have run and could not be undone.</span></div>
<p class="sub">Read-only analysis of <code>{esc(src)}</code>. No agent changes, no writes, no intervention. Every action was replayed through the frozen execution gate.</p>

<h2>1 · Total actions reviewed</h2>
<div class="big">{n}</div>

<h2>2 · Decisions</h2>
<div class="cards">
<div class="card"><div class="big" style="color:{C['COMMIT']}">{counts['COMMIT']}</div>COMMIT<br><span class="sub">enough evidence</span></div>
<div class="card"><div class="big" style="color:{C['VERIFY']}">{counts['VERIFY']}</div>VERIFY<br><span class="sub">evidence missing</span></div>
<div class="card"><div class="big" style="color:{C['BLOCK']}">{counts['BLOCK']}</div>BLOCK<br><span class="sub">explicit contradiction</span></div>
</div>

<h2>3 · Irreversible actions lacking evidence <span class="sub">(would have executed without XVay)</span></h2>
{"".join("<div class='flag'><code>"+esc(r['action'])+"</code><br><span class='rsn'>"+esc(r['reason'])+"</span></div>" for r in irreversible) or "<p class='sub'>None found in this log.</p>"}

<h2>4 · False-block candidates <span class="sub">(review these — should any have been allowed?)</span></h2>
{"".join("<div class='flag'><code>"+esc(r['action'])+"</code><br><span class='rsn'>"+esc(r['reason'])+"</span></div>" for r in falseblock) or "<p class='sub'>None.</p>"}

<h2>5 · Exact evidence behind every decision</h2>
<table><tr><th>Action</th><th>Scope</th><th>Decision</th><th>Evidence</th></tr>
{"".join(rowhtml(r) for r in res)}</table>

<div class="summary">
<b>Without XVay:</b> all {n} actions execute as-is, including {len(irreversible)} irreversible action(s) with insufficient evidence.<br>
<b>With XVay:</b> {len(stopped)} action(s) held for verification / blocked before execution; {counts['COMMIT']} passed through with no friction.
</div>

<div class="foot">XVay answers "enough evidence to execute?" — never "is this allowed?" (that is IAM/OPA's job).
Designed for the failure class in 2025–26 agent incidents; no claim of preventing any specific named event.
Reproducible: this report is a pure function of the input log and the frozen gate.</div>
</body></html>"""

def main():
    if len(sys.argv)<2:
        print("usage: python3 shadow_pilot.py <log> <allowlist.json> [envelope.json] [report.html]"); sys.exit(1)
    src=sys.argv[1]
    allow_path=sys.argv[2] if len(sys.argv)>2 else ""
    env_path=sys.argv[3] if len(sys.argv)>3 else ""
    dst=sys.argv[4] if len(sys.argv)>4 else "shadow_pilot_report.html"
    allow=load_allowlist(allow_path); env=load_envelope(env_path) if env_path else None
    rows=load(src); res=analyze(rows, allow, env)
    open(dst,"w",encoding="utf-8").write(render(res,src))
    c={"COMMIT":0,"VERIFY":0,"BLOCK":0}
    for r in res: c[r["decision"]]+=1
    print(f"reviewed {len(res)} actions -> COMMIT {c['COMMIT']} / VERIFY {c['VERIFY']} / BLOCK {c['BLOCK']}")
    print(f"report written: {dst}")

if __name__=="__main__":
    main()

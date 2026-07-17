"""
XVAY CONNECTOR LAYER — normalizes ANY agent framework's tool definitions into
one canonical action list. DECIDES NOTHING (mechanical extraction only).
Adding a framework = adding one connector function + registering it. The gate,
normalizer, and core are never touched.

Canonical output: list[str] of action templates (same shape the gate expects).
"""
import json

def _clean(name):
    return name.replace("_"," ").replace("-"," ").replace(".", " ").strip()

def _tail(params):
    for k in ("target","file","resource","path","name"):
        if isinstance(params, dict) and params.get(k):
            return " " + str(params[k])
    return ""

# --- one function per framework; each returns list[str] ---
def openai_functions(d):
    tools = d.get("tools", d.get("functions", []))
    out=[]
    for t in tools:
        fn = t.get("function", t)
        n=_clean(fn.get("name","")); 
        if n: out.append((n+_tail(fn.get("parameters",{}))).strip())
    return out

def mcp_tools(d):
    out=[]
    for t in d.get("tools", []):
        n=_clean(t.get("name",""))
        if n: out.append((n+_tail(t.get("parameters",t.get("inputSchema",{})))).strip())
    return out

def langgraph(d):
    out=[]
    for t in d.get("nodes", d.get("tools", [])):
        n=_clean(t.get("name", t.get("id","")))
        if n: out.append(n)
    return out

def crewai(d):
    out=[]
    for a in d.get("agents", []):
        for t in a.get("tools", []):
            n=_clean(t if isinstance(t,str) else t.get("name",""))
            if n: out.append(n)
    for t in d.get("tools", []):
        n=_clean(t if isinstance(t,str) else t.get("name",""))
        if n: out.append(n)
    return out

def autogen(d):
    out=[]
    for t in d.get("functions", d.get("tools", [])):
        n=_clean(t.get("name","") if isinstance(t,dict) else t)
        if n: out.append(n)
    return out

def openapi(d):
    out=[]
    for path, methods in d.get("paths", {}).items():
        for m in methods:
            out.append(_clean(m + " " + path))
    return out

def cli_tools(d):
    return [_clean(x) for x in (d.get("commands", d if isinstance(d,list) else []))]

REGISTRY = {
    "openai": openai_functions, "anthropic": openai_functions,
    "mcp": mcp_tools, "langgraph": langgraph, "crewai": crewai,
    "autogen": autogen, "openapi": openapi, "cli": cli_tools,
}

def to_canonical(framework, schema_path):
    if framework not in REGISTRY:
        raise ValueError(f"no connector for '{framework}'. available: {sorted(REGISTRY)}")
    d = json.load(open(schema_path, encoding="utf-8"))
    seen=set(); out=[]
    for a in REGISTRY[framework](d):
        if a and a not in seen: seen.add(a); out.append(a)
    return out

if __name__ == "__main__":
    import sys
    fw, path = sys.argv[1], sys.argv[2]
    out = to_canonical(fw, path)
    dst = sys.argv[3] if len(sys.argv)>3 else "derived_allowlist.json"
    json.dump({"allow": out}, open(dst,"w"), indent=2)
    print(f"[{fw}] -> {len(out)} canonical actions -> {dst}")

"""
XVAY SCHEMA EXTRACTOR — derives an allow-list from an existing tool schema.
DECIDES NOTHING. Mechanical string extraction only (like the Normalizer).
Supports OpenAI/function-calling style ({"tools":[{"name":...}]}) and MCP
tool-list style ({"tools":[{"name":...}]}). tool name -> canonical action
string by replacing '_' with ' '; appends the declared target/file if present.
"""
import json, sys
def extract(schema_path):
    d = json.load(open(schema_path, encoding="utf-8"))
    tools = d.get("tools", d if isinstance(d, list) else [])
    allow = []
    for t in tools:
        name = (t.get("name") or "").replace("_", " ").replace("-", " ").strip()
        if not name: continue
        p = t.get("parameters", {}) or {}
        tail = ""
        for k in ("target","file","resource"):
            if p.get(k): tail = " " + str(p[k]); break
        allow.append((name + tail).strip())
    return allow
if __name__ == "__main__":
    out = extract(sys.argv[1])
    json.dump({"allow": out}, open(sys.argv[2] if len(sys.argv)>2 else "derived_allowlist.json","w"), indent=2)
    print(f"derived {len(out)} allow-list entries from schema")

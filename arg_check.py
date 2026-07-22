"""
XVAY ARG CHECK — structural anomalies in tool ARGUMENTS. Judges nothing about
risk; it answers one mechanical question: "is this argument a plain literal, or
does it carry control structure / indirection / encoding?"

An argument that is not a plain literal means XVay has LESS evidence about what
will actually run -> VERIFY (never a silent COMMIT). This is the evidence-gate
principle applied to arguments, not a policy engine.
"""
import re

# Chaining operators (; && || |) are NOT listed here: composing readable
# commands is ordinary engineering. What hides execution is command
# SUBSTITUTION and piping into an interpreter (handled as a chain check in
# gate_with_envelope), plus redirection into an absolute path.
_SHELL_CTRL = re.compile(r"(`|\$\(|>>\s*/|>\s*/)")   # hidden execution / absolute redirect
_CHAINING   = re.compile(r";|&&|\|\||\|")             # a second command inside an argument
_INDIRECT   = re.compile(r"\$\{?[A-Za-z_][A-Za-z0-9_]*\}?")      # $VAR indirection
_TRAVERSAL  = re.compile(r"\.\./")                               # path traversal
_B64BLOB    = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")            # candidate base64 token
# write/exfil constructs expressed INSIDE an argument of a read-only tool.
# Deliberately tiny and extensible by the customer — not a policy language.
_WRITE_CLAUSE = re.compile(
    r"(into\s+outfile|into\s+dumpfile|\bcopy\b[^;]*\bto\b|\bdd\b[^;]*\bof=|"
    r"\bload_file\s*\(|\bxp_cmdshell\b|>\s*/)", re.I)

# Well-known credential/secret locations. These ship ENABLED so the product works
# out of the box; the customer can extend or disable them. Because WE suggest
# them (rather than the customer declaring them) they only ever raise VERIFY.
DEFAULT_SENSITIVE_PATHS = [
    "/etc/shadow", "/etc/passwd", "/etc/sudoers", "id_rsa", "id_ed25519",
    ".ssh/", ".aws/credentials", ".kube/config", ".docker/config.json",
    ".npmrc", ".pypirc", ".git-credentials", "service-account", "private_key",
    "secrets.yaml", "credentials.json",
]

def _looks_encoded(token: str) -> bool:
    """Base64 that DECODES TO READABLE TEXT. A git SHA or hex id decodes to
    binary noise, so this avoids flagging legitimate identifiers."""
    import base64
    t = token.strip()
    if len(t) % 4: t += "=" * (4 - len(t) % 4)
    try: raw = base64.b64decode(t, validate=False)
    except Exception: return False
    if len(raw) < 6: return False
    printable = sum(1 for b in raw if 32 <= b < 127)
    return printable / len(raw) > 0.85

def default_sensitive_hits(arguments):
    """Returns which built-in sensitive locations an argument names."""
    hits = []
    def scan(v):
        if isinstance(v, dict):
            for x in v.values(): scan(x)
        elif isinstance(v, (list, tuple)):
            for x in v: scan(x)
        elif isinstance(v, str):
            low = v.lower()
            for p in DEFAULT_SENSITIVE_PATHS:
                if p.lower() in low and p not in hits: hits.append(p)
    scan(arguments)
    return hits

def anomalies(arguments, shell_context=False):
    """arguments: the raw dict from an MCP tools/call. Returns list of findings."""
    found = []
    def scan(val, path="arg"):
        if isinstance(val, dict):
            for k, v in val.items(): scan(v, k)
        elif isinstance(val, (list, tuple)):
            for v in val: scan(v, path)
        elif isinstance(val, str):
            s = val
            if _SHELL_CTRL.search(s):  found.append(f"hidden execution (substitution/redirect) in '{path}'")
            # An argument is supposed to be a literal value. A chaining operator
            # inside one means a second command was smuggled in. Exempt only when
            # the invoked tool IS a shell, where composing commands is its job.
            if not shell_context and _CHAINING.search(s):
                found.append(f"command chaining inside argument '{path}'")
            if _TRAVERSAL.search(s):   found.append(f"path traversal in '{path}'")
            if _INDIRECT.search(s):    found.append(f"variable indirection in '{path}'")
            m = _B64BLOB.search(s)
            if m and " " not in s.strip() and _looks_encoded(m.group(0)):
                found.append(f"encoded payload in '{path}'")
            if _WRITE_CLAUSE.search(s):
                found.append(f"write/exfil construct in '{path}'")
            # Homoglyph evasion = Latin-lookalike scripts (Cyrillic/Greek) MIXED
            # into an otherwise-ASCII string. A Persian/Arabic/CJK filename is
            # legitimate and must NOT be flagged.
            if ("/" in s or path.lower() in ("path","file","target","resource","pod")):
                confusable = any(0x0370 <= ord(c) <= 0x03FF or 0x0400 <= ord(c) <= 0x04FF
                                 for c in s)
                has_ascii_letter = any(c.isascii() and c.isalpha() for c in s)
                if confusable and has_ascii_letter:
                    found.append(f"homoglyph (Latin-lookalike script) in '{path}'")
    scan(arguments)
    return sorted(set(found))

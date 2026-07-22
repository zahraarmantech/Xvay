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
# gate_with_envelope), plus redirection into a real system path.
# `>/dev/null` and `2>/dev/null` are the universal "discard output" idiom and
# are explicitly NOT redirection-to-a-sensitive-path.
# `$(( ... ))` is ARITHMETIC expansion (pure math, no command runs) and is
# benign; `$( ... )` is command substitution (runs a command) and is hidden
# execution. The negative lookahead `(?!\()` keeps arithmetic out.
_SHELL_CTRL = re.compile(r"`|\$\((?!\()")
_REDIR_SYS  = re.compile(r">>?\s*/(?!dev/null)(etc|root|proc|sys|boot|bin|sbin|usr/bin|usr/sbin|usr/lib|lib)\b")
# An absolute path INTO a protected system directory. Writing here (a downloaded
# file, an output path, an installed unit) is how persistence/backdoors land —
# `/etc/cron.d/`, `/etc/systemd/`, `/usr/bin/`, `/root/`, `/boot/`. A workspace-
# scoped agent has no business writing outside the workspace, so a destination
# argument pointing here is a structural red flag even for a non-shell tool.
_SYS_WRITE_DIR = re.compile(r"^/(etc|root|proc|sys|boot|bin|sbin|lib|usr/bin|usr/sbin|usr/lib)(/|$)")
# argument names that denote a WRITE destination (vs a read source / url)
_DEST_FIELDS = {"dest","destination","path","output","outfile","out","file",
                "filename","filepath","target","save_to","save_path","location"}
_CHAINING   = re.compile(r";|&&|\|\||\|")             # a second command inside an argument
_INDIRECT   = re.compile(r"\$\{?[A-Za-z_][A-Za-z0-9_]*\}?")      # $VAR indirection
_TRAVERSAL  = re.compile(r"\.\./")                               # path traversal
_B64BLOB    = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")            # candidate base64 token
# Code passed to an interpreter as inline source (`python -c "..."`, `-e`,
# `--command`). Its body is program text, not shell — $ and > inside it are
# language syntax, so we do not scan it for shell indirection/redirect.
# Only PROGRAMMING interpreters: their -c body is program text (its $ and > are
# language syntax). A sh/bash -c body is shell, so it is NOT exempted here.
_INLINE_CODE = re.compile(r"(?:^|\s)(?:python3?|node|ruby|perl)\s+(?:-\S+\s+)*?-[ce]\b|--eval\b")
# A heredoc body (`... << 'EOF' ... EOF`) is content being written to a file or
# fed to a program — it is data, not shell. Its $, backticks and > are part of
# the file being authored, so we remove the body before shell-syntax scanning.
_HEREDOC = re.compile(r"<<-?\s*(['\"]?)(\w+)\1\r?\n.*?\r?\n\2\b", re.S)
_SINGLE_QUOTED = re.compile(r"'[^']*'")
def _strip_heredoc(text):
    return _HEREDOC.sub(" <<HEREDOC_BODY>> ", str(text))
# strip a programming interpreter's -c/-e "<code>" body (its $/backtick/> are
# language syntax). sh/bash -c bodies are NOT stripped: they are real shell.
_INLINE_CODE_BODY = re.compile(
    r"""(?:python3?|node|ruby|perl)\s+(?:-\S+\s+)*?(?:-c|-e)\s+(?P<q>['"]).*(?P=q)""", re.S)
def _strip_inline_code_body(text):
    return _INLINE_CODE_BODY.sub(" -c <code> ", str(text))
# write/exfil constructs expressed INSIDE an argument of a read-only tool.
# Deliberately tiny and extensible by the customer — not a policy language.
_WRITE_CLAUSE = re.compile(
    r"(into\s+outfile|into\s+dumpfile|\bcopy\b[^;]*\bto\b|\bdd\b[^;]*\bof=|"
    r"\bload_file\s*\(|\bxp_cmdshell\b)", re.I)

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
    """Returns which built-in sensitive locations an argument names. File
    CONTENT (heredoc bodies, inline-code bodies) is data being written, not a
    path being touched, so it is stripped first — a `private_key()` call inside
    a Rust test file is not a reference to a credentials file."""
    hits = []
    def scan(v):
        if isinstance(v, dict):
            for x in v.values(): scan(x)
        elif isinstance(v, (list, tuple)):
            for x in v: scan(x)
        elif isinstance(v, str):
            low = _strip_heredoc(_strip_inline_code_body(v)).lower()
            for p in DEFAULT_SENSITIVE_PATHS:
                if p.lower() in low and p not in hits: hits.append(p)
    scan(arguments)
    return hits


# A command substitution `$(cmd ...)` whose inner command is READ-ONLY
# (find/grep/cat/ls/head/...) produces a string, not a side effect. Common in
# build classpaths (`java -cp "$(find ...)"`) and is not hidden execution.
_RO_CMDS = r"find|e?grep|rg|cat|ls|head|tail|cut|dirname|basename|pwd|echo|wc|sort|uniq|awk|sed|which|realpath|date|printf|tr|xargs|id|du|df|stat|whoami|hostname|uname|readlink|env|type|command"
def _only_readonly_substitutions(text):
    subs = re.findall(r"\$\(([^()]*)\)", str(text))
    if not subs:
        return False
    for sub in subs:
        head = (sub.strip().split() or [""])[0].split("/")[-1]
        if not re.match(r"^(?:" + _RO_CMDS + r")$", head):
            return False
    return True

def anomalies(arguments, shell_context=False):
    """arguments: the raw dict from an MCP tools/call. Returns list of findings.

    Field-aware: fields that carry FILE CONTENT / SOURCE CODE (file_text,
    old_str, new_str, content, code, body, patch, diff, ...) are literal text an
    editor is writing to disk — they are NOT executed, so scanning them for shell
    syntax produces pure false positives (a Python line `x = a > b`, a `df.drop`,
    a `../path` string literal). Those fields are checked only for genuinely
    content-relevant risks (encoded payloads). Fields that name something to
    RUN or a PATH to touch (command, cmd, path, file, target, script, ...) get
    the full structural scan.
    """
    found = []
    # Field names whose VALUE is inert text/code being written, not executed.
    CONTENT_FIELDS = {"file_text","new_str","old_str","content","code","body",
                      "text","patch","diff","source","template","thought",
                      "message","description","docstring","comment"}
    def scan(val, path="arg"):
        if isinstance(val, dict):
            for k, v in val.items(): scan(v, k)
        elif isinstance(val, (list, tuple)):
            for v in val: scan(v, path)
        elif isinstance(val, str):
            s = val
            # A write-destination argument (dest/path/output/...) pointing into a
            # protected system directory is a structural red flag for a workspace-
            # scoped agent, regardless of tool type — this is how a downloaded
            # file becomes a cron/systemd backdoor. Read-only fields like `url`
            # or `source` are not destinations and are not flagged here.
            if path.lower() in _DEST_FIELDS and _SYS_WRITE_DIR.match(s.strip()):
                found.append(f"write destination in a protected system path in '{path}'")
            is_content = path.lower() in CONTENT_FIELDS
            if is_content:
                # inert text: only an encoded blob is meaningful here
                m = _B64BLOB.search(s)
                if m and " " not in s.strip() and _looks_encoded(m.group(0)):
                    found.append(f"encoded payload in '{path}'")
                return
            # `python -c "<code>"` / `node -e "<code>"` carry program text whose
            # $ and > are language syntax, not shell. Strip both inline-code and
            # heredoc bodies so only the real shell frame is scanned.
            inline_code = bool(_INLINE_CODE.search(s))
            s_frame = _strip_heredoc(_strip_inline_code_body(s))
            # In POSIX shell a single-quoted span is fully literal: no command
            # substitution, no backtick expansion. A `$(...)`/backtick inside
            # '...' (e.g. a Go struct tag in a `sed` script) runs nothing, so it
            # is not hidden execution. Double-quoted and bare ones still expand.
            s_subst = _SINGLE_QUOTED.sub(" <sq> ", s_frame)
            if _SHELL_CTRL.search(s_subst) and not _only_readonly_substitutions(s_subst):
                found.append(f"hidden execution (substitution) in '{path}'")
            if _REDIR_SYS.search(s_frame):   found.append(f"redirect to system path in '{path}'")
            # An argument is supposed to be a literal value. A chaining operator
            # inside one means a second command was smuggled in. Exempt only when
            # the invoked tool IS a shell, where composing commands is its job.
            if not shell_context and _CHAINING.search(s_frame):
                found.append(f"command chaining inside argument '{path}'")
            # A single `../` in a shell command is an ordinary relative path
            # (`python x.py ../tests.json`). Only flag traversal that climbs
            # multiple levels or reaches a system path — the exfil-shaped case.
            _trav_hit = _TRAVERSAL.search(s_frame)
            if _trav_hit:
                deep = ("../../" in s_frame) or bool(re.search(r"\.\./(etc|root|home|proc|sys|var|usr|boot)\b", s_frame))
                if deep or not shell_context:
                    found.append(f"path traversal in '{path}'")
            if _INDIRECT.search(s_frame) and not inline_code and not shell_context:
                found.append(f"variable indirection in '{path}'")
            m = _B64BLOB.search(s_frame)
            if m and " " not in s_frame.strip() and _looks_encoded(m.group(0)):
                found.append(f"encoded payload in '{path}'")
            if _WRITE_CLAUSE.search(s_subst) and not inline_code:
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

"""
XVAY GATE + ENVELOPE — the run-scoped entry point. Wraps the FROZEN gate with
envelope authenticity. Order of authority:
  1. envelope tampered (forged scope)  -> BLOCK   (explicit contradiction)
  2. otherwise: scope the catalog, call the UNCHANGED gate for COMMIT/VERIFY/BLOCK
Absence/expiry of envelope => no trusted scope => gate naturally yields VERIFY.
The gate's own logic is never modified; this only decides envelope authenticity
(which is not a safety decision about the action, but about the permission).
"""
import sys, json
sys.path.insert(0, __import__("os").path.dirname(__import__("os").path.abspath(__file__)))
_g = open(__import__("os").path.join(__import__("os").path.dirname(__import__("os").path.abspath(__file__)),
          "execution_gate.py")).read().split("def main")[0]
_ns={}; exec(_g,_ns); gate=_ns["gate"]
from normalizer import normalize
from envelope import load_envelope, scope_catalog
from canon import contains_phrase, token_set
import run_trace
import arg_check

_DESTRUCTIVE = _ns["DESTRUCTIVE"]

# ---------------------------------------------------------------------------
# MECHANICAL HELPERS. None of these judges whether an action is dangerous.
# Each computes a FACT from the action text alone (zero system connection) and
# may only DOWNGRADE a COMMIT to VERIFY. They never upgrade, never BLOCK.
# ---------------------------------------------------------------------------
import re as _re

_INLINE_CODE_BODY = _re.compile(
    r"""(?:python3?|node|ruby|perl)\s+(?:-\S+\s+)*?(?:-c|-e)\s+(?P<q>['"]).*(?P=q)""", _re.S)
_HEREDOC_BODY = _re.compile(r"<<-?\s*(['\"]?)(\w+)\1\r?\n.*?\r?\n\2\b", _re.S)
# ONLY the quoted search pattern of a search command (grep/egrep/rg/ag/find
# -name) is a string literal, not an operation. We deliberately do NOT strip
# arbitrary quoted strings, because `sh -c "rm -rf /"` is a real shell body.
_SEARCH_PATTERN = _re.compile(
    r"\b(?:e?grep|rg|ag|ack|fgrep)\b[^\n|;]*?(['\"]).*?\1"
    r"|-name\s+(['\"]).*?\2", _re.S)
def _strip_inline_code(text):
    """Remove a PROGRAMMING interpreter's `-c "<code>"` body so its language
    tokens (truncate, drop, >, $) are not mis-read as shell operations. Only
    python/node/ruby/perl bodies are stripped — a `sh -c`/`bash -c` body IS
    shell, so its verbs are real and must still be scanned. Also removes heredoc
    bodies (file content) and a search command's quoted pattern (a verb inside
    `grep "...prune..."` is a search string, not the operation)."""
    t = _INLINE_CODE_BODY.sub(" -c <code> ", str(text))
    t = _HEREDOC_BODY.sub(" <<file-content>> ", t)
    t = _SEARCH_PATTERN.sub(" <search> ", t)
    return t


# Environment names split by ambiguity in ordinary engineering English.
# UNAMBIGUOUS names practically never appear as build targets, so naming one
# is itself evidence the action left its authorised environment.
# AMBIGUOUS names double as everyday build/test targets (`make test`,
# `npm run dev`), so a bare token is NOT evidence; corroboration is required.
_ENV_UNAMBIGUOUS = {"prod", "production", "live", "staging", "preprod"}
_ENV_AMBIGUOUS   = {"test", "dev", "development", "qa", "sandbox", "stage"}
# Flags/keywords that make an environment reference explicit.
_ENV_FLAG = _re.compile(
    r"(?:--?env(?:ironment)?|--?namespace|\bnamespace\b|\b-n\b|--?profile|--?stage)"
    r"[\s=:]+([a-z0-9_.-]+)", _re.I)

def _env_names_referenced(raw_action, known_extra=()):
    """Environment names the action actually REFERS TO (mechanical).

    An environment name counts only when it appears as a STANDALONE token
    (surrounded by whitespace or string boundaries) or via an explicit env flag
    (`--env prod`). A name embedded in a larger identifier or path
    (`live_russia_tv.py`, `production_config.py`, `test_basic.py`) is an ordinary
    symbol, not an environment reference — treating `_`, `-`, `.`, `/` as part of
    the token is what keeps XVay off normal source-editing traffic.

    Unambiguous names (prod, production, live, staging, preprod) count as soon as
    they appear standalone. Ambiguous names (test, dev, qa, ...) double as build
    targets even when standalone (`npm run dev`), so they need an explicit flag.
    """
    low = str(raw_action).lower()
    found = set()
    flagged = {m.group(1).strip().lower() for m in _ENV_FLAG.finditer(low)}
    known_extra = {str(k).lower() for k in (known_extra or ())}
    universe = _ENV_UNAMBIGUOUS | _ENV_AMBIGUOUS | known_extra

    # Tokens that are file paths or filenames: an env name inside one is a symbol,
    # not an environment (`src/plugins/live_russia_tv.py`, `staging_defaults.py`).
    path_tokens = [t for t in _re.split(r"\s+", low)
                   if ("/" in t) or _re.search(r"\.[a-z0-9]{1,6}$", t)]
    def _inside_a_path(name):
        return any(_re.search(r"(?<![a-z0-9])" + _re.escape(name), t) for t in path_tokens)

    for name in universe:
        if name in flagged:
            found.add(name); continue
        # word-boundary occurrence, allowing - and . as qualifier joiners
        # (`prod-db`, `prod.cluster`) but NOT when the whole token is a path/file.
        occ = _re.search(r"(?<![a-z0-9_])" + _re.escape(name) + r"(?![a-z0-9_])", low)
        if not occ:
            continue
        if _inside_a_path(name):
            continue
        if name in _ENV_UNAMBIGUOUS or name in known_extra:
            found.add(name)
    return found

# Glob / wildcard characters that make a target set unbounded from the text.
_GLOB = _re.compile(r"[*?]|\[[^\]]+\]")
# A token that looks like a filesystem path or filename.
_PATHLIKE = _re.compile(r"^(?:[~./]|[a-z0-9_.-]+/)|/|^[a-z0-9_-]+\.[a-z0-9]{1,6}$", _re.I)

def _words(s):
    return [w for w in _re.split(r"[^a-z0-9]+", str(s).lower()) if w]

def _flag_destructive(raw_action):
    """Destructive verbs carried by a FLAG (`find . -delete`, `--force-delete`).
    Flag-stripping normalisation drops these, which silently hid the operation.
    Only flags are inspected, so prose such as a commit message is untouched."""
    out = set()
    for tok in str(raw_action).split():
        if not tok.startswith("-"):
            continue
        out |= (set(_words(tok)) & _DESTRUCTIVE)
    return out

def _is_destructive_operation(raw_action, tool_name):
    """Is the ACTION ITSELF a destructive operation (as opposed to merely
    mentioning a destructive word inside free text such as a commit message)?
    Evidence: the invoked tool's own name, the leading command, or a flag."""
    if tool_name and (set(_words(tool_name)) & _DESTRUCTIVE):
        return True
    parts = [p for p in str(raw_action).split() if not p.startswith("-")]
    if parts and (set(_words(parts[0])) & _DESTRUCTIVE):
        return True
    return bool(_flag_destructive(raw_action))

# ── Wrapper-level completions of principles the frozen core already holds ──
# These are NOT per-vendor CLI rules. Xvay's criterion is reversibility, not
# danger: `systemctl stop` is dangerous but reversible (`start` undoes it), so
# it is deliberately NOT held here. Encoding one rule per cloud CLI would turn
# Xvay into a signature scanner and would need endless upkeep; a verb is
# irreversible regardless of which binary runs it.
#
# Synonyms for the frozen core's DESTRUCTIVE set that are simply missing from
# it. `rb` (as in `aws s3 rb`) is intentionally excluded: `script.rb` tokenises
# to include `rb`, so it would stop every Ruby invocation — too costly.
_IRREVERSIBLE_SYNONYMS = {"terminate", "dropdb", "mkfs", "purge", "shred"}

def _subcommand_irreversible(raw_action):
    """An irreversible verb in the leading command OR its subcommand chain
    (`aws ec2 terminate-instances`, `rclone purge x`), which the frozen core
    misses because it keys on the first token only. Only bare leading words are
    inspected — a token carrying `/`, `.` or `:` is a path or target, so
    `pytest tests/test_terminate.py` is not read as a terminate operation."""
    parts = [p for p in str(raw_action).split() if not p.startswith("-")]
    hits = set()
    # the canonical action is prefixed with the tool name ("bash aws ec2 ..."),
    # so the operation verb can sit a few tokens in. The window stays small so
    # a verb appearing later, as an argument or free text, is not picked up.
    for tok in parts[:4]:
        if any(ch in tok for ch in "/.:"):
            continue
        hits |= (set(_words(tok)) & _IRREVERSIBLE_SYNONYMS)
    return hits

# Commands that MUTATE a target rather than write to it. The core already holds
# "a write destination inside a protected system dir is a red flag"; permission,
# ownership and format changes are the same principle on the same paths. Each
# one below destroys state the system cannot reconstruct: after `chmod -R 777`
# the original modes are simply gone. `mount`/`umount` are excluded because they
# destroy nothing and `umount` undoes them.
_SYS_MUTATORS = {"chmod", "chown", "chgrp", "setfacl", "mkfs"}
_SYS_PATH = _re.compile(r"(?:^|\s)/(etc|root|proc|sys|boot|bin|sbin|lib|usr/bin|usr/sbin|usr/lib|dev)\b")

def _system_path_mutation(raw_action):
    """A permission/ownership/format change aimed at a protected system path
    (`chmod -R 777 /etc`, `mkfs.ext4 /dev/sdb1`). A workspace-scoped agent has
    no business mutating these, whoever the vendor is."""
    parts = [p for p in str(raw_action).split() if not p.startswith("-")]
    if not parts:
        return False
    head = set()
    for tok in parts[:2]:          # tool-name prefix, then the real command
        head |= (set(_words(tok)) & _SYS_MUTATORS)
    return bool(head) and bool(_SYS_PATH.search(str(raw_action)))

def _fanout(raw_action, tool_name=None):
    """(n_targets, has_glob) counted from the action text. A fact, not a verdict.
    A target is any non-flag operand that is not the tool's own name or the
    destructive verb itself, so resource names count as well as file paths."""
    s = str(raw_action)
    has_glob = bool(_GLOB.search(s))
    tool_toks = set(_words(tool_name)) if tool_name else set()
    n = 0
    for tok in s.split():
        if tok.startswith("-"):          # flags are not targets
            continue
        w = set(_words(tok.strip("'\"`")))
        if not w or w <= tool_toks or (w & _DESTRUCTIVE):
            continue
        n += 1
    return n, has_glob

# Interpreters/launchers whose real effects are NOT in the text they are given.
_OPAQUE_LAUNCHER = {
    "bash", "sh", "zsh", "ksh", "dash", "eval", "source", "exec",
    "make", "python", "python3", "ruby", "perl", "node",
    "npm", "npx", "yarn", "pnpm", "pipenv", "poetry", "gradle", "mvn", "ant",
}

_INTERPRETERS = {"sh","bash","zsh","ksh","dash","eval","source",
                 "python","python3","node","ruby","perl"}
# xargs is intentionally NOT here: `xargs grep`/`xargs cat` run a visible
# named command. `_chain_into_interpreter` already exempts a piped
# interpreter that is given an explicit script, so `x | python foo.py`
# passes while `curl x | python` (reading code from stdin) is flagged.
# python/node/ruby/perl execute a NAMED script or inline -c, which is visible;
# xargs runs a NAMED command. These are only hidden execution when reading
# stdin as CODE, handled by the stdin/-c check below, not by mere presence.
_CHAIN_SPLIT = _re.compile(r"\|\||&&|[;|\n]")
_CHAINING = _re.compile(r";|&&|\|\||\|")
_PIPE_EXFIL = _re.compile(r"\|\s*(curl|wget|nc|ncat|socat)\b[^|]*"
                          r"(-d\s*@?-|--data(-binary)?\s*@?-|-T\s*-|--upload-file\s*-|@-)")
# Tools whose whole purpose is to run a shell command line. For these, chaining
# readable commands is ordinary. For every OTHER tool, an argument is supposed
# to be a literal, so a chaining operator inside it is command injection.
_SHELL_TOOLS = {"bash","sh","zsh","ksh","shell","exec","execute","run","command",
                "runcommand","run_command","terminal","cli","system"}

# Tools that produce NO external effect: they only record a thought, a plan, or
# a completion signal. Their arguments are free-form prose, never executed, so
# scanning them for shell syntax is a pure false-positive source.
_NO_EFFECT_TOOLS = {"think","thought","reason","reasoning","plan","finish",
                    "complete","done","respond","message","note","summarize"}

def _is_no_effect_tool(tool_name, raw_action):
    if tool_name and (set(_words(tool_name)) & _NO_EFFECT_TOOLS):
        return True
    parts = [p for p in str(raw_action).split() if not p.startswith("-")]
    return bool(parts and set(_words(parts[0])) & _NO_EFFECT_TOOLS)

def _is_shell_tool(tool_name, raw_action):
    if tool_name:
        return bool(set(_words(tool_name)) & _SHELL_TOOLS)
    parts = [p for p in str(raw_action).split() if not p.startswith("-")]
    return bool(parts and set(_words(parts[0])) & _SHELL_TOOLS)

def _chain_into_interpreter(raw_action):
    """A command that PIPES into a bare interpreter runs text that is not visible
    in the request (`curl x | sh`, `cat y | python`). That is the hidden-execution
    case. It is NOT the same as sequencing an explicit script (`cd d && python
    test.py` or `x && bash deploy.sh`), where what runs is named right there and
    is ordinary engineering. So we flag only a real pipe ('|', not '&&'/';')
    whose downstream head is an interpreter AND which is reading stdin (no script
    argument of its own)."""
    s = str(raw_action)
    # split on PIPES only; sequencing operators are not hidden execution
    segs = [p.strip() for p in _re.split(r"\|(?!\|)", s) if p.strip()]
    for seg in segs[1:]:
        w = _words(seg)
        if not w or w[0] not in _INTERPRETERS:
            continue
        # `... | python script.py` names its script -> visible, not hidden.
        # `... | sh` / `... | python -` / `... | python` reads stdin -> hidden.
        rest = seg.split()
        toks = rest[1:]
        has_explicit_script = any(
            (not tok.startswith("-")) and tok.lower() not in _INTERPRETERS
            and tok != "-" and (tok.endswith((".py",".sh",".rb",".js",".pl"))
                                or "/" in tok or tok.startswith("script"))
            for tok in toks
        )
        # `python -m module` / `-mmodule` is an explicit named invocation.
        if any(t=="-m" or t.startswith("-m") for t in toks):
            has_explicit_script = True
        # `-c "..."` inline code is still hidden execution of literal code
        inline_c = any(tok in ("-c","-e","--command","--eval") for tok in rest[1:])
        if not has_explicit_script or inline_c:
            return w[0]
    return None

def _is_opaque_exec(raw_action, tokens):
    """True when the action hands work to an interpreter/launcher, so its real
    effects cannot be read from the text. A fact about VISIBILITY, not danger."""
    parts = [p for p in str(raw_action).split() if not p.startswith("-")]
    if not parts:
        return False
    head = _re.sub(r"[^a-z0-9]", "", parts[0].lower())
    if head not in _OPAQUE_LAUNCHER:
        return False
    # `bash -c 'rm -rf /x'` carries its effect inline -> not opaque.
    if tokens & _DESTRUCTIVE:
        return False
    return True

def decide(task_scope, catalog, action, env, tool_name=None, arguments=None):
    if env and env.get("_tampered"):
        return "BLOCK", f"Envelope authenticity failed: {env['_rejected']}. Forged run scope rejected."
    na = normalize(action)["normalized_action"]
    live      = bool(env) and not env.get("_rejected")
    run_id    = (env or {}).get("run_id") if live else None
    protected = (env or {}).get("protected_resources", []) if live else []
    egress    = (env or {}).get("egress_tools", []) if live else []
    max_irrev = (env or {}).get("max_irreversible") if live else None

    toks = token_set(na)
    READ_OK = {"read","get","list","logs","select","describe","show","cat","view"}
    is_read = bool(toks & READ_OK) and not (toks & _DESTRUCTIVE)
    is_irreversible = bool(toks & _DESTRUCTIVE) or bool(_flag_destructive(action))
    hit_res = next((r for r in protected if contains_phrase(na, r)), None)

    decision = reason = None
    # 1) customer-DECLARED protected resource, non-read -> explicit contradiction
    if hit_res and not is_read:
        decision, reason = "BLOCK", f"Non-read action on customer-declared protected resource '{hit_res}': {na}"
    # 2) CROSS-STEP checks (need the run's short memory)
    if decision is None and run_id:
        st = run_trace.get(run_id)
        hits_egress = any(contains_phrase(na, t) for t in egress)
        if st["tainted"] and hits_egress:
            decision, reason = "BLOCK", (
                f"Cross-step violation: this run already read a declared protected resource "
                f"{st['touched']}; sending to a declared egress tool is not allowed ({na}).")
        elif max_irrev is not None and is_irreversible and st["irreversible"] >= max_irrev:
            decision, reason = "VERIFY", (
                f"Cross-step budget: this run already performed {st['irreversible']} "
                f"irreversible action(s), declared limit {max_irrev}. Approval required.")
    # 3) otherwise the FROZEN gate decides
    if decision is None:
        allow = scope_catalog(catalog, env)
        anchors = (env.get("anchors", []) if live else []) + ([task_scope] if task_scope else [])
        decision, reason = gate(task_scope, allow, na, anchors=anchors)
        # MISSION ENVIRONMENT (downgrade-only, never weakens a stronger verdict):
        # the envelope declares which environments this run may touch. If the
        # action names a different one, the agent has left the mission it was
        # authorised for — something it cannot notice about itself.
        if decision == "COMMIT":
            declared_envs = {str(e).lower() for e in ((env or {}).get("environment") or [])}
            named = _env_names_referenced(_strip_inline_code(action), (env or {}).get("environments_known"))
            if named and declared_envs and not (named & declared_envs):
                decision, reason = "VERIFY", (
                    f"Mission scope: this run is authorised for {sorted(declared_envs)}, "
                    f"but the action names {sorted(named)}. Approval required.")
        # 3a2) IRREVERSIBLE VERB CARRIED BY A FLAG (`find . -delete`,
        # `--force-delete`). The frozen gate keys on the leading command, so a
        # destructive operation hidden in a flag can slip through as COMMIT.
        # Deletion is irreversible, so hold it for approval. Downgrade only.
        if decision == "COMMIT" and _flag_destructive(_strip_inline_code(action)):
            decision, reason = "VERIFY", (
                "Irreversible operation carried by a flag (e.g. `-delete`): the "
                f"action performs a destructive operation not visible as the "
                f"leading command ({na}). Approval required.")
        # 3a3) IRREVERSIBLE VERB IN THE SUBCOMMAND CHAIN. The frozen gate reads
        # the first token, so `aws ec2 terminate-instances` and `rclone purge x`
        # look like an `aws`/`rclone` call. The verb, not the vendor, decides.
        if decision == "COMMIT":
            _sub = _subcommand_irreversible(_strip_inline_code(action))
            if _sub:
                decision, reason = "VERIFY", (
                    f"Irreversible operation named in the subcommand "
                    f"({sorted(_sub)}): the leading command alone does not show "
                    f"it. Approval required.")
        # 3a4) MUTATION OF A PROTECTED SYSTEM PATH. Companion to the existing
        # write-destination rule: `chmod -R 777 /etc` destroys the original
        # modes, which the system cannot reconstruct.
        if decision == "COMMIT" and _system_path_mutation(_strip_inline_code(action)):
            decision, reason = "VERIFY", (
                "Permission, ownership or format change aimed at a protected "
                "system path. The prior state is not recoverable, so this is "
                "held for approval.")
        # 3b) ARGUMENT-INTRODUCED DANGER (mechanical, no judgement):
        # the declared capability did not contain a destructive verb, but the
        # actual action does -> the arguments brought danger the schema never
        # declared. Evidence mismatch => VERIFY (never silently COMMIT).
        # Inline interpreter code that RE-ENTERS the shell is hidden execution.
        # Match the ACTUAL shell-executing APIs (os.system(, subprocess.,
        # child_process, Popen(, a bare exec(/eval( that carries shell syntax) —
        # NOT a mere property access such as `read.eval` or `x.exec` in ordinary
        # JS, which names a field and runs nothing.
        if decision == "COMMIT" and _re.search(
                r"os\.system\s*\(|subprocess\.|\.system\s*\(|child_process|\bPopen\s*\("
                r"|check_output\s*\(|check_call\s*\("
                r"|(?<![\w.])eval\s*\([^)]*[$`;|&]|(?<![\w.])exec\s*\(",
                str(action)) and _re.search(r"(?:-c|-e|--command|--eval)\b", str(action)):
            decision, reason = "VERIFY", (
                "Inline code re-enters the shell (os.system/subprocess/eval), so the real "
                f"operation is not visible in the request ({na}). Approval required.")
        if decision == "COMMIT":
            # Destructive verbs inside inline interpreter code (`python -c
            # "...truncate()..."`) are language, not shell operations. Scan a
            # code-stripped view so only real shell verbs count.
            _dest_toks = token_set(normalize(_strip_inline_code(action))["normalized_action"])
            act_destructive = _dest_toks & _DESTRUCTIVE
            if act_destructive:
                # Only the INVOKED tool's own name may declare a destructive
                # verb. Previously any allow-list entry whose tokens appeared in
                # the action counted, so declaring a tool called `rm` silently
                # authorised every `rm` appearing in any argument.
                declared = set()
                if tool_name:
                    declared = token_set(normalize(tool_name)["normalized_action"]) & _DESTRUCTIVE
                introduced = act_destructive - declared
                if introduced:
                    decision, reason = "VERIFY", (
                        f"Argument-introduced danger: action contains {sorted(introduced)} "
                        f"which the declared tool capability does not. Approval required.")

        # 3c) FAN-OUT of an irreversible action (mechanical count, no judgement).
        # A destructive verb whose target set is unbounded (glob) or larger than
        # the declared limit is a blast radius the schema never described.
        # `max_fanout` is customer-declared; absent, a conservative default is
        # used so the product protects out of the box. Downgrade only.
        if decision == "COMMIT" and _is_destructive_operation(action, tool_name):
            n_t, has_glob = _fanout(action, tool_name)
            limit = (env or {}).get("max_fanout")
            declared = limit is not None
            if not declared:
                limit = 3
            if has_glob:
                decision, reason = "VERIFY", (
                    f"Unbounded blast radius: irreversible action uses a wildcard, so the "
                    f"number of affected targets is not knowable from the request ({na}). "
                    f"Approval required.")
            elif n_t > limit:
                decision, reason = "VERIFY", (
                    f"Fan-out {n_t} exceeds the {'declared' if declared else 'default'} "
                    f"limit of {limit} for an irreversible action. Approval required.")

        # 3d) OPAQUE EXECUTION (opt-in). The action hands work to an interpreter,
        # so its real effects are not readable from the text. XVay does not
        # pretend to see inside. OFF by default: requiring approval for every
        # `npm run build` would stop ordinary engineering. Customers who need
        # the stricter posture set opaque_exec="verify" in the signed envelope.
        if decision == "COMMIT" and (env or {}).get("opaque_exec") == "verify":
            if _is_opaque_exec(action, toks):
                decision, reason = "VERIFY", (
                    f"Opaque execution: '{na}' delegates to an interpreter, so its effects "
                    f"cannot be read from the request. Approval required by run policy.")

    # 3e) ARGUMENT STRUCTURE (mechanical). An argument that is not a plain
    # literal — shell control structure, traversal, indirection, an encoded
    # payload, a write/exfil clause — means XVay has LESS evidence about what
    # will actually run. Less evidence must never yield a silent COMMIT.
    # Restored from the argument-check layer; downgrade only.
    # A chaining operator inside a NON-shell tool's request means a second,
    # unrelated command was smuggled into an argument -> injection, not
    # composition. Shell tools are exempt: composing commands is their job.
    _no_effect = _is_no_effect_tool(tool_name, action)
    if decision == "COMMIT" and not _is_shell_tool(tool_name, action) and not _no_effect:
        if _CHAINING.search(str(action)):
            decision, reason = "VERIFY", (
                f"Command chaining inside a non-shell tool request: the argument carries a "
                f"second command rather than a literal value ({na}). Approval required.")
    if decision == "COMMIT" and not _no_effect:
        _sink = _chain_into_interpreter(action)
        if _sink:
            decision, reason = "VERIFY", (
                f"Hidden execution: the command chain pipes into '{_sink}', so what actually "
                f"runs is not visible in the request. Approval required.")
    # Data-out: local content piped into curl/wget/nc AS a request body is
    # exfiltration (`... | curl -d @- url`). Distinct from `url | sh` (code in).
    if decision == "COMMIT" and not _no_effect and _PIPE_EXFIL.search(str(action)):
        decision, reason = "VERIFY", (
            "Data egress: a command pipes local output into an outbound request body "
            f"({na}). Approval required.")
    if decision == "COMMIT" and not _no_effect:
        _args = arguments if arguments is not None else {"action": action}
        _found = arg_check.anomalies(_args, shell_context=_is_shell_tool(tool_name, action))
        if _found:
            decision, reason = "VERIFY", (
                "Argument structure: " + "; ".join(_found[:3]) +
                ". The request does not show what will actually run. Approval required.")
        else:
            _sens = arg_check.default_sensitive_hits(_args)
            if _sens and (env or {}).get("use_default_sensitive_paths", True):
                decision, reason = "VERIFY", (
                    f"Well-known sensitive location referenced: {sorted(_sens)[:3]}. "
                    f"Suggested by XVay (not customer-declared), so approval rather than block.")

    # SINGLE recording point: stopped attempts are audit events too.
    # Taint only when the protected read ACTUALLY went through (COMMIT).
    if run_id:
        run_trace.record(run_id, na,
                         # taint if the protected access was NOT blocked: a VERIFY
                         # may still be approved out-of-band and executed, and XVay
                         # would never see it. Conservative on purpose.
                         touched_protected=(hit_res is not None and decision != "BLOCK"),
                         irreversible=is_irreversible,
                         committed=(decision == "COMMIT"),
                         resource=hit_res, decision=decision, reason=reason)
    return decision, reason

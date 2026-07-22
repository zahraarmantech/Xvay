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

    Unambiguous names count on sight. Ambiguous names count only with
    corroboration: an explicit env flag, or the name joined to another token by
    a separator (`prod-db`, `test_cluster`) which marks it as a qualifier
    rather than a standalone build target.
    """
    low = str(raw_action).lower()
    found = set()
    flagged = {m.group(1).strip().lower() for m in _ENV_FLAG.finditer(low)}
    known_extra = {str(k).lower() for k in (known_extra or ())}
    universe = _ENV_UNAMBIGUOUS | _ENV_AMBIGUOUS | known_extra
    for name in universe:
        if not _re.search(r"(?<![a-z0-9])" + _re.escape(name) + r"(?![a-z0-9])", low):
            continue
        if name in _ENV_UNAMBIGUOUS or name in known_extra:
            found.add(name); continue
        # ambiguous: needs corroboration
        if name in flagged:
            found.add(name); continue
        if _re.search(r"(?<![a-z0-9])" + _re.escape(name) + r"[-_.][a-z0-9]"
                      r"|[a-z0-9][-_.]" + _re.escape(name) + r"(?![a-z0-9])", low):
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

_INTERPRETERS = {"sh","bash","zsh","ksh","dash","python","python3","node",
                 "ruby","perl","eval","source","xargs"}
_CHAIN_SPLIT = _re.compile(r"\|\||&&|[;|\n]")
_CHAINING = _re.compile(r";|&&|\|\||\|")
# Tools whose whole purpose is to run a shell command line. For these, chaining
# readable commands is ordinary. For every OTHER tool, an argument is supposed
# to be a literal, so a chaining operator inside it is command injection.
_SHELL_TOOLS = {"bash","sh","zsh","ksh","shell","exec","execute","run","command",
                "runcommand","run_command","terminal","cli","system"}

def _is_shell_tool(tool_name, raw_action):
    if tool_name:
        return bool(set(_words(tool_name)) & _SHELL_TOOLS)
    parts = [p for p in str(raw_action).split() if not p.startswith("-")]
    return bool(parts and set(_words(parts[0])) & _SHELL_TOOLS)

def _chain_into_interpreter(raw_action):
    """A chained command whose downstream segment is an interpreter executes
    text that is NOT visible in the request (`curl x | sh`). Composing readable
    commands (`cat f | grep x`) is ordinary and is not flagged."""
    parts = [p.strip() for p in _CHAIN_SPLIT.split(str(raw_action)) if p.strip()]
    for seg in parts[1:]:
        w = _words(seg)
        if w and w[0] in _INTERPRETERS:
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
            named = _env_names_referenced(action, (env or {}).get("environments_known"))
            if named and declared_envs and not (named & declared_envs):
                decision, reason = "VERIFY", (
                    f"Mission scope: this run is authorised for {sorted(declared_envs)}, "
                    f"but the action names {sorted(named)}. Approval required.")
        # 3b) ARGUMENT-INTRODUCED DANGER (mechanical, no judgement):
        # the declared capability did not contain a destructive verb, but the
        # actual action does -> the arguments brought danger the schema never
        # declared. Evidence mismatch => VERIFY (never silently COMMIT).
        if decision == "COMMIT":
            act_destructive = toks & _DESTRUCTIVE
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
    if decision == "COMMIT" and not _is_shell_tool(tool_name, action):
        if _CHAINING.search(str(action)):
            decision, reason = "VERIFY", (
                f"Command chaining inside a non-shell tool request: the argument carries a "
                f"second command rather than a literal value ({na}). Approval required.")
    if decision == "COMMIT":
        _sink = _chain_into_interpreter(action)
        if _sink:
            decision, reason = "VERIFY", (
                f"Hidden execution: the command chain pipes into '{_sink}', so what actually "
                f"runs is not visible in the request. Approval required.")
    if decision == "COMMIT":
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

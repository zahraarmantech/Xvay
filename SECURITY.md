# Security Policy

## What XVay is (and is not)

XVay is a pre-execution gate for AI agent tool calls. It decides COMMIT / VERIFY
/ BLOCK from the request text alone, before the action runs. It is **not** a
sandbox, does not execute anything, and holds no secrets beyond the public half
of an Ed25519 verification key.

## Threat model — stated honestly

XVay is strong at stopping irreversible or out-of-scope actions before they run,
and at catching structural argument attacks (shell-control injection, command
substitution, pipe-into-interpreter, data-egress, path traversal to system
locations, encoded payloads).

It is **not** designed to stop prompt injection that keeps an agent within its
allowed scope (e.g. an allowed transfer to the wrong recipient with ordinary
arguments). Measured on AgentDojo, zero-config catch rate for that class is low
by design. If that is your threat, XVay is a complement to, not a replacement
for, a policy/IAM layer.

## Reporting a vulnerability

If you find a way to make the gate COMMIT an action it should have held — a
"leak" — please open a private security advisory on this repository, or email
the maintainer address listed in the repository profile. Include:

- the exact tool name and arguments,
- the envelope used (or "zero-config"),
- the verdict you got and the one you expected.

A reproducible leak in the argument-structure or scope layer is the most
valuable report. Please do not include real secrets in the example.

## Verifying claims yourself

Every safety claim in the README is backed by a test you can run:

```bash
python3 identity_test.py          # downgrade-only, never breaks a verdict
python3 adversarial_benchmark.py  # 38 attacks, 0 leaks
python3 property_test.py          # 245 generated cases
python3 real_agent_benchmark.py   # 10k real agent calls, 1.4% friction
```

# Pre-release audit checklist (run before every public push)

This repo was built as a FRESH folder (no inherited git history), which is the
safe way — the private repo's commit history never travels here.

## Already audited & clean (this build)
- [x] No API keys / secrets / tokens / private keys in code or docs
- [x] No customer names, pricing, or target-account references
- [x] No internal governance / research / moat material
- [x] No .env / .key / .pem / credentials files
- [x] Only sample PUBLIC key present (orchestrator.pub — safe to share)
- [x] Code runs after rename: gate 10/10, integration ALL PASS

## Safe publish path (do NOT flip the private repo to public)
Git history is forever: deleting a folder now still leaves it recoverable in
old commits, along with any secret ever committed. Instead:

    1. This folder IS the fresh copy (public parts only).
    2. Re-run the audit below.
    3. git init  →  one clean commit  →  push to the public Xvay repo.
    4. Your real dev history stays in the private repo.

## Re-run before each push
```bash
# secrets / keys
grep -rinE "api[_-]?key|secret|password|token|BEGIN (RSA|PRIVATE)|sk-[a-zA-Z0-9]|AKIA[0-9A-Z]" . --include="*.py" --include="*.md" --include="*.json"
# customer / pricing leaks
grep -rinE "zapier|klarna|replit|lyft|\\\$[0-9]|pricing|design partner" . --include="*.py" --include="*.md"
# internal material
grep -rinE "governance|founding|moat|research archive|calibration data" . --include="*.py" --include="*.md"
# dangerous files
find . -name "*.env" -o -name "*.key" -o -name "*.pem" -o -name "credentials*"
# code still works
python execution_gate.py && python integration_benchmark.py
```
All four greps should return nothing (or only false positives you've verified);
both commands should pass.

## Keep private forever
- 6_INTERNAL_GOVERNANCE/ (founding contract, decision history)
- 7_RESEARCH_ARCHIVE/ (experiments, calibration data)
- pricing, thresholds/tuning data, roadmap for enterprise features
  (VERIFY dashboard, SSO, retention)

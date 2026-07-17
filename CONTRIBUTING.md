# Contributing to Xvay

Thanks for your interest. A few principles this project holds strictly:

1. **The gate decides one thing.** "Is there enough evidence to execute this
   action, now?" — not "is it allowed?" (IAM's job) and not "is it dangerous?"
   (you declare that). PRs that turn Xvay into a policy engine won't be merged.
2. **The core standardizes; it does not judge.** The normalizer and connectors
   must never make risk decisions — only shape data.
3. **Tests must be real.** New behavior needs a test on realistic input, and
   `python integration_benchmark.py` must stay `ALL PASS`.
4. **New logic stays small.** Prefer the smallest change that works; a new
   primitive should be a fraction of existing modules.

Run before submitting:
```bash
python execution_gate.py            # 10/10
python integration_benchmark.py     # ALL PASS
```

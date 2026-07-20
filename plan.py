"""
XVAY PLAN — a terraform-plan-style consequence preview computed from the ACTION
ALONE (zero connection to the customer's systems). It does NOT judge whether an
action is good or bad. It reports three COMPUTABLE facts an operator would want
before an irreversible step, exactly like `terraform plan` shows +/-/destroy:

  reversible : can this be undone by an inverse op?  (destructive verb => no)
  scope      : how wide?  single | wildcard/bulk | unknown
  environment: which target space the action names   (from the action text only)

This turns "silent gate decision" into an auditable, self-explaining preview so
the AGENT (or, rarely, a human) can react to consequences — keeping the loop
agentic, not manual. No new judgement lives here; only description.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
_g = open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
      "execution_gate.py")).read().split("def main")[0]
_ns={}; exec(_g,_ns)
DESTRUCTIVE = _ns["DESTRUCTIVE"]; PROD_SCOPE = _ns["PROD_SCOPE"]
from normalizer import normalize

# purely lexical, universal signals — kept deliberately tiny (anti-policy-engine)
_BULK = {"all", "*", "everything", "recursive", "cascade", "-rf", "rf", "wildcard"}

def plan(action: str) -> dict:
    na = normalize(action)["normalized_action"]
    toks = na.split(); tset = set(toks)
    destructive = bool(tset & DESTRUCTIVE)
    reversible = not destructive
    scope = "bulk" if (tset & _BULK) else "single"
    env = "production" if (tset & PROD_SCOPE) else "unspecified"
    verb = next((t for t in toks if t in DESTRUCTIVE), None) or (toks[0] if toks else "?")
    line = (f"~ {na}\n"
            f"    reversible : {'no' if destructive else 'yes'}"
            f"{'  (destructive verb: '+verb+')' if destructive else ''}\n"
            f"    scope      : {scope}{'  (affects many)' if scope=='bulk' else ''}\n"
            f"    environment: {env}")
    return {"action": na, "reversible": reversible,
            "scope": scope, "environment": env, "preview": line}

if __name__ == "__main__":
    for a in ["kubectl rollout restart staging-api",
              "psql drop database orders-primary",
              "rm -rf /var/data",
              "delete customer records all",
              "read file config.yaml"]:
        p = plan(a)
        print(p["preview"]); print()

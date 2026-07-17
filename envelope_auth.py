"""
XVAY ENVELOPE AUTH — asymmetric, replay-resistant, action-bound.
Orchestrator holds the PRIVATE key and signs. Xvay holds ONLY the PUBLIC key
and can verify but NEVER forge. Envelope is bound to a specific action
(action_hash) and single-use (nonce). Decides authenticity only.
"""
import json, hashlib, datetime
from nacl.signing import SigningKey, VerifyKey
from nacl.exceptions import BadSignatureError
from nacl.encoding import HexEncoder

def action_hash(action: str) -> str:
    return hashlib.sha256(action.strip().lower().encode()).hexdigest()

def _canon(env: dict) -> bytes:
    payload = {k: env.get(k) for k in
               ("run_id","agent_id","environment","resources","operations",
                "anchors","protected_resources","action_hash","nonce","issued_at","expires_at")}
    return json.dumps(payload, sort_keys=True, separators=(",",":")).encode()

def keypair():
    sk = SigningKey.generate()
    return sk, sk.verify_key

def sign(env: dict, signing_key: SigningKey) -> dict:
    sig = signing_key.sign(_canon(env)).signature
    out = dict(env); out["signature"] = sig.hex(); return out

_SEEN_NONCES = set()   # replay guard (per-process; a real deploy uses shared store)

def verify(env: dict, verify_key: VerifyKey, action: str = None, now=None) -> tuple:
    sig = env.get("signature")
    if not sig: return False, "no signature", "MISSING"
    try:
        verify_key.verify(_canon(env), bytes.fromhex(sig))
    except (BadSignatureError, ValueError):
        return False, "signature invalid (unknown key or tampered)", "TAMPER"
    if action is not None and env.get("action_hash") != action_hash(action):
        return False, "action_hash mismatch (permission not for this action)", "TAMPER"
    nonce = env.get("nonce")
    if nonce is not None:
        if nonce in _SEEN_NONCES:
            return False, "nonce reused (replay)", "TAMPER"
        _SEEN_NONCES.add(nonce)
    exp = env.get("expires_at")
    if exp:
        now = now or datetime.datetime.now(datetime.timezone.utc)
        try:
            t = datetime.datetime.fromisoformat(exp.replace("Z","+00:00"))
            if now > t: return False, "expired", "EXPIRED"
        except Exception:
            return False, "unparseable expires_at", "EXPIRED"
    return True, "valid", "OK"

def reset_nonces(): _SEEN_NONCES.clear()

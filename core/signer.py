import hmac
import hashlib
import json

# Shared secret (must be SAME on Pico)
SHARED_SECRET = b"VAUTH_SHARED_SECRET_2026"


def hmac_sign(data: dict) -> str:
    """
    Generate HMAC-SHA256 signature for given dictionary.
    """
    message = json.dumps(data, sort_keys=True).encode()
    return hmac.new(SHARED_SECRET, message, hashlib.sha256).hexdigest()


def hmac_verify(data: dict, signature: str) -> bool:
    """
    Verify HMAC-SHA256 signature.
    """
    expected = hmac_sign(data)
    return hmac.compare_digest(expected, signature)

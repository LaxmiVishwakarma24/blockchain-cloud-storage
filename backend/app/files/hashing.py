import hashlib
import hmac


def sha256_hex(data):
    """Return the SHA-256 digest of `data` as 64 lowercase hex characters."""
    return hashlib.sha256(data).hexdigest()


def hashes_match(first, second):
    """Constant-time comparison of two hex digests (case-insensitive)."""
    return hmac.compare_digest(first.lower().encode("utf-8"), second.lower().encode("utf-8"))
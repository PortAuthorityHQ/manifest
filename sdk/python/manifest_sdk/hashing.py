"""SHA-256 hashing utilities matching manifest-core."""

import hashlib


def sha256(data: bytes) -> bytes:
    """Compute SHA-256 hash, returning 32-byte digest."""
    return hashlib.sha256(data).digest()


def sha256_hex(data: bytes) -> str:
    """Compute SHA-256 hash, returning 'sha256:<hex>' string."""
    return f"sha256:{hashlib.sha256(data).hexdigest()}"

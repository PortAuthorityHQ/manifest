"""Ed25519 signing matching manifest-core's Signer."""

from __future__ import annotations

import base64
import os
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization


class Signer:
    """Ed25519 signer for receipt cryptographic sealing."""

    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        self._private_key = private_key

    @staticmethod
    def generate() -> Signer:
        """Generate a new random Ed25519 keypair."""
        return Signer(Ed25519PrivateKey.generate())

    @staticmethod
    def from_file(path: str) -> Signer:
        """Load a signing key from a 32-byte seed file."""
        data = Path(path).read_bytes()
        if len(data) != 32:
            raise ValueError(f"key file must be exactly 32 bytes, got {len(data)}")
        private_key = Ed25519PrivateKey.from_private_bytes(data)
        return Signer(private_key)

    def save(self, path: str) -> None:
        """Save the 32-byte seed to a file."""
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        seed = self._private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        p.write_bytes(seed)

    def save_public_key(self, path: str) -> None:
        """Save the 32-byte public key to a file."""
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        pub_bytes = self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        p.write_bytes(pub_bytes)

    def sign(self, data: bytes) -> str:
        """Sign data, returning 'ed25519:<base64>' string."""
        sig = self._private_key.sign(data)
        encoded = base64.b64encode(sig).decode("ascii")
        return f"ed25519:{encoded}"

    def verify(self, data: bytes, signature: str) -> bool:
        """Verify a signature string ('ed25519:<base64>') against data."""
        pub_key = self._private_key.public_key()
        return _verify_with_key(pub_key, data, signature)

    def public_key_bytes(self) -> bytes:
        """Get the 32-byte public key."""
        return self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )


def verify_with_public_key(pub_bytes: bytes, data: bytes, signature: str) -> bool:
    """Verify a signature using a standalone 32-byte public key."""
    pub_key = Ed25519PublicKey.from_public_bytes(pub_bytes)
    return _verify_with_key(pub_key, data, signature)


def load_public_key(path: str) -> bytes:
    """Load a 32-byte public key from a file."""
    data = Path(path).read_bytes()
    if len(data) != 32:
        raise ValueError(f"public key file must be exactly 32 bytes, got {len(data)}")
    return data


def _verify_with_key(pub_key: Ed25519PublicKey, data: bytes, signature: str) -> bool:
    """Internal: verify with an Ed25519PublicKey object."""
    if not signature.startswith("ed25519:"):
        raise ValueError("signature must start with 'ed25519:'")
    encoded = signature[len("ed25519:"):]
    sig_bytes = base64.b64decode(encoded)
    try:
        pub_key.verify(sig_bytes, data)
        return True
    except Exception:
        return False

"""Tests for Ed25519 signing."""

import tempfile
from pathlib import Path

from manifest_sdk import Signer, verify_with_public_key


def test_generate_and_sign():
    signer = Signer.generate()
    sig = signer.sign(b"hello")
    assert sig.startswith("ed25519:")
    assert signer.verify(b"hello", sig)


def test_verify_rejects_wrong_data():
    signer = Signer.generate()
    sig = signer.sign(b"hello")
    assert not signer.verify(b"wrong", sig)


def test_save_and_load(tmp_path):
    signer = Signer.generate()
    key_path = str(tmp_path / "signing.key")
    signer.save(key_path)

    loaded = Signer.from_file(key_path)
    sig = signer.sign(b"test")
    assert loaded.verify(b"test", sig)


def test_public_key_save_and_verify(tmp_path):
    signer = Signer.generate()
    pub_path = str(tmp_path / "signing.pub")
    signer.save_public_key(pub_path)

    pub_bytes = Path(pub_path).read_bytes()
    assert len(pub_bytes) == 32

    sig = signer.sign(b"test data")
    assert verify_with_public_key(pub_bytes, b"test data", sig)
    assert not verify_with_public_key(pub_bytes, b"wrong data", sig)


def test_public_key_bytes():
    signer = Signer.generate()
    pub = signer.public_key_bytes()
    assert len(pub) == 32


def test_key_file_is_32_bytes(tmp_path):
    signer = Signer.generate()
    key_path = str(tmp_path / "key")
    signer.save(key_path)
    assert len(Path(key_path).read_bytes()) == 32

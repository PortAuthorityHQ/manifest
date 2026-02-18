"""Tests for the high-level Manifest API."""

from manifest_sdk import Manifest


def test_basic_recording():
    m = Manifest(identity="test-agent")
    receipt = m.record(
        tool="send_email",
        input={"to": "bob@example.com", "subject": "Hello"},
        output={"status": "sent"},
    )
    assert receipt.id.startswith("urn:uuid:")
    assert receipt.proof.signature.startswith("ed25519:")
    assert receipt.proof.merkle_root.startswith("sha256:")
    assert receipt.agent.name == "test-agent"
    assert receipt.action.tool == "send_email"


def test_receipt_chaining():
    m = Manifest(identity="test-agent")
    r1 = m.record(tool="a", input={})
    r2 = m.record(tool="b", input={})

    assert r1.proof.previous_receipt is None
    assert r2.proof.previous_receipt == r1.content_hash()
    assert len(m.merkle) == 2


def test_with_storage(tmp_path):
    db_path = str(tmp_path / "test.db")
    m = Manifest(identity="test-agent", db=db_path)

    receipt = m.record(tool="query", input={"sql": "SELECT 1"})
    assert m.storage is not None
    assert m.storage.count_receipts() == 1

    loaded = m.storage.get_receipt_by_id(receipt.id)
    assert loaded is not None
    assert loaded.action.tool == "query"


def test_with_policy(tmp_path):
    policy_file = tmp_path / "policy.yml"
    policy_file.write_text(
        """
policies:
  - name: tool-allowlist
    allowed_tools:
      - send_email
"""
    )

    m = Manifest(identity="test-agent", policy=str(policy_file))

    # Allowed tool
    r1 = m.record(tool="send_email", input={})
    assert r1.delta is not None
    assert r1.delta.authorized is True
    assert r1.policy is not None

    # Disallowed tool
    r2 = m.record(tool="drop_table", input={})
    assert r2.delta is not None
    assert r2.delta.authorized is False
    assert len(r2.delta.violations) == 1


def test_with_key_file(tmp_path):
    from manifest_sdk import Signer

    signer = Signer.generate()
    key_path = str(tmp_path / "signing.key")
    signer.save(key_path)

    m = Manifest(identity="test-agent", key=key_path)
    receipt = m.record(tool="test", input={})

    # Verify the signature with the original signer
    canonical = receipt.canonical_bytes()
    assert signer.verify(canonical, receipt.proof.signature)


def test_storage_persistence(tmp_path):
    db_path = str(tmp_path / "persist.db")

    # First session
    m1 = Manifest(identity="agent-1", db=db_path)
    m1.record(tool="a", input={})
    m1.record(tool="b", input={})

    # Second session - should restore Merkle tree and last hash
    m2 = Manifest(identity="agent-1", db=db_path)
    assert len(m2.merkle) == 2
    r3 = m2.record(tool="c", input={})
    assert r3.proof.previous_receipt is not None
    assert len(m2.merkle) == 3

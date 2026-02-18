"""Tests for receipt building and signing."""

import json

from manifest_sdk import (
    Action,
    AgentIdentity,
    Delta,
    IdentitySource,
    MerkleTree,
    Receipt,
    ReceiptBuilder,
    Signer,
)


def _test_identity():
    return AgentIdentity(
        name="test-agent",
        version="1.0",
        source=IdentitySource.ENVIRONMENT,
    )


def _test_action():
    return Action(
        tool="db_query",
        input={"query": "SELECT 1"},
        output={"rows": 1},
    )


def test_build_receipt():
    signer = Signer.generate()
    merkle = MerkleTree()

    receipt = (
        ReceiptBuilder()
        .agent(_test_identity())
        .action(_test_action())
        .build(signer, merkle)
    )

    assert receipt.context == "https://portauthority.dev/receipt/v1"
    assert receipt.id.startswith("urn:uuid:")
    assert receipt.proof.signature.startswith("ed25519:")
    assert receipt.proof.merkle_root.startswith("sha256:")
    assert receipt.proof.previous_receipt is None
    assert len(merkle) == 1


def test_receipt_chaining():
    signer = Signer.generate()
    merkle = MerkleTree()

    r1 = (
        ReceiptBuilder()
        .agent(_test_identity())
        .action(_test_action())
        .build(signer, merkle)
    )
    r1_hash = r1.content_hash()

    r2 = (
        ReceiptBuilder()
        .agent(_test_identity())
        .action(_test_action())
        .previous_receipt(r1_hash)
        .build(signer, merkle)
    )

    assert r2.proof.previous_receipt == r1_hash
    assert len(merkle) == 2
    assert r1.proof.merkle_root != r2.proof.merkle_root


def test_signature_is_verifiable():
    signer = Signer.generate()
    merkle = MerkleTree()

    receipt = (
        ReceiptBuilder()
        .agent(_test_identity())
        .action(_test_action())
        .build(signer, merkle)
    )

    canonical = receipt.canonical_bytes()
    assert signer.verify(canonical, receipt.proof.signature)


def test_content_hash_is_deterministic():
    signer = Signer.generate()
    merkle = MerkleTree()

    receipt = (
        ReceiptBuilder()
        .agent(_test_identity())
        .action(_test_action())
        .build(signer, merkle)
    )

    assert receipt.content_hash() == receipt.content_hash()


def test_canonical_bytes_have_sorted_keys():
    signer = Signer.generate()
    merkle = MerkleTree()

    receipt = (
        ReceiptBuilder()
        .agent(_test_identity())
        .action(_test_action())
        .build(signer, merkle)
    )

    canonical = receipt.canonical_bytes()
    parsed = json.loads(canonical)
    keys = list(parsed.keys())
    assert keys == sorted(keys), "canonical JSON keys must be sorted"


def test_build_fails_without_agent():
    signer = Signer.generate()
    merkle = MerkleTree()

    try:
        ReceiptBuilder().action(_test_action()).build(signer, merkle)
        assert False, "should have raised"
    except ValueError as e:
        assert "agent" in str(e)


def test_build_fails_without_action():
    signer = Signer.generate()
    merkle = MerkleTree()

    try:
        ReceiptBuilder().agent(_test_identity()).build(signer, merkle)
        assert False, "should have raised"
    except ValueError as e:
        assert "action" in str(e)


def test_receipt_serializes_to_json_ld():
    signer = Signer.generate()
    merkle = MerkleTree()

    receipt = (
        ReceiptBuilder()
        .agent(_test_identity())
        .action(_test_action())
        .build(signer, merkle)
    )

    d = receipt.to_dict()
    assert d["@context"] == "https://portauthority.dev/receipt/v1"
    assert d["id"].startswith("urn:uuid:")
    assert d["action"]["tool"] == "db_query"
    assert d["proof"]["merkleRoot"].startswith("sha256:")


def test_receipt_json_roundtrip():
    signer = Signer.generate()
    merkle = MerkleTree()

    receipt = (
        ReceiptBuilder()
        .agent(_test_identity())
        .action(_test_action())
        .delta(Delta(authorized=True, violations=[]))
        .build(signer, merkle)
    )

    json_str = receipt.to_json()
    loaded = Receipt.from_json(json_str)

    assert loaded.id == receipt.id
    assert loaded.agent.name == "test-agent"
    assert loaded.action.tool == "db_query"
    assert loaded.proof.signature == receipt.proof.signature
    assert loaded.delta is not None
    assert loaded.delta.authorized is True


def test_receipt_with_delta():
    signer = Signer.generate()
    merkle = MerkleTree()

    receipt = (
        ReceiptBuilder()
        .agent(_test_identity())
        .action(_test_action())
        .delta(Delta(authorized=False, violations=["tool_not_allowed"]))
        .build(signer, merkle)
    )

    d = receipt.to_dict()
    assert d["delta"]["authorized"] is False
    assert "tool_not_allowed" in d["delta"]["violations"]


def test_none_fields_omitted():
    signer = Signer.generate()
    merkle = MerkleTree()

    receipt = (
        ReceiptBuilder()
        .agent(_test_identity())
        .action(_test_action())
        .build(signer, merkle)
    )

    d = receipt.to_dict()
    assert "policy" not in d
    assert "delta" not in d
    assert "previousReceipt" not in d["proof"]

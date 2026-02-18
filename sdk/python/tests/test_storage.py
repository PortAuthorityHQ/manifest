"""Tests for SQLite storage."""

from manifest_sdk import (
    Action,
    AgentIdentity,
    IdentitySource,
    MerkleTree,
    ReceiptBuilder,
    Signer,
    Storage,
)


def _make_receipt(signer, merkle, tool="db_query"):
    return (
        ReceiptBuilder()
        .agent(AgentIdentity(name="test-agent", source=IdentitySource.ENVIRONMENT))
        .action(Action(tool=tool, input={}, output={"ok": True}))
        .build(signer, merkle)
    )


def test_insert_and_get_by_id():
    storage = Storage.in_memory()
    signer = Signer.generate()
    merkle = MerkleTree()

    receipt = _make_receipt(signer, merkle)
    storage.insert_receipt(receipt)

    loaded = storage.get_receipt_by_id(receipt.id)
    assert loaded is not None
    assert loaded.id == receipt.id
    assert loaded.action.tool == "db_query"


def test_get_by_hash():
    storage = Storage.in_memory()
    signer = Signer.generate()
    merkle = MerkleTree()

    receipt = _make_receipt(signer, merkle, "send_email")
    content_hash = receipt.content_hash()
    storage.insert_receipt(receipt)

    loaded = storage.get_receipt_by_hash(content_hash)
    assert loaded is not None
    assert loaded.action.tool == "send_email"


def test_list_receipts():
    storage = Storage.in_memory()
    signer = Signer.generate()
    merkle = MerkleTree()

    for tool in ["a", "b", "c"]:
        receipt = _make_receipt(signer, merkle, tool)
        storage.insert_receipt(receipt)

    all_receipts = storage.list_receipts(10, 0)
    assert len(all_receipts) == 3


def test_list_receipts_pagination():
    storage = Storage.in_memory()
    signer = Signer.generate()
    merkle = MerkleTree()

    for i in range(5):
        receipt = _make_receipt(signer, merkle, f"tool_{i}")
        storage.insert_receipt(receipt)

    page1 = storage.list_receipts(2, 0)
    assert len(page1) == 2

    page2 = storage.list_receipts(2, 2)
    assert len(page2) == 2


def test_list_by_session():
    storage = Storage.in_memory()
    signer = Signer.generate()
    merkle = MerkleTree()

    r1 = _make_receipt(signer, merkle, "a")
    r2 = _make_receipt(signer, merkle, "b")
    r3 = _make_receipt(signer, merkle, "c")

    storage.insert_receipt(r1, session_id="session-1")
    storage.insert_receipt(r2, session_id="session-1")
    storage.insert_receipt(r3, session_id="session-2")

    s1 = storage.list_by_session("session-1", 10, 0)
    assert len(s1) == 2

    s2 = storage.list_by_session("session-2", 10, 0)
    assert len(s2) == 1


def test_not_found_returns_none():
    storage = Storage.in_memory()
    assert storage.get_receipt_by_id("nonexistent") is None
    assert storage.get_receipt_by_hash("sha256:abc") is None


def test_latest_receipt_hash():
    storage = Storage.in_memory()
    assert storage.latest_receipt_hash() is None

    signer = Signer.generate()
    merkle = MerkleTree()
    receipt = _make_receipt(signer, merkle)
    expected_hash = receipt.content_hash()
    storage.insert_receipt(receipt)

    assert storage.latest_receipt_hash() == expected_hash


def test_count_receipts():
    storage = Storage.in_memory()
    assert storage.count_receipts() == 0

    signer = Signer.generate()
    merkle = MerkleTree()
    for i in range(3):
        receipt = _make_receipt(signer, merkle, f"tool_{i}")
        storage.insert_receipt(receipt)

    assert storage.count_receipts() == 3


def test_merkle_leaf_persistence():
    storage = Storage.in_memory()

    leaf1 = bytes([1] * 32)
    leaf2 = bytes([2] * 32)

    storage.insert_merkle_leaf(0, leaf1)
    storage.insert_merkle_leaf(1, leaf2)

    loaded = storage.load_merkle_leaves()
    assert len(loaded) == 2
    assert loaded[0] == leaf1
    assert loaded[1] == leaf2


def test_file_storage(tmp_path):
    db_path = str(tmp_path / "receipts.db")
    storage = Storage.open(db_path)

    signer = Signer.generate()
    merkle = MerkleTree()
    receipt = _make_receipt(signer, merkle)
    storage.insert_receipt(receipt)
    storage.close()

    # Reopen and verify
    storage2 = Storage.open(db_path)
    loaded = storage2.get_receipt_by_id(receipt.id)
    assert loaded is not None
    assert loaded.id == receipt.id
    storage2.close()

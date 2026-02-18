"""Tests for Merkle tree."""

from manifest_sdk import MerkleTree, sha256


def test_empty_tree():
    tree = MerkleTree()
    assert tree.is_empty()
    assert len(tree) == 0
    root = tree.root()
    assert root.startswith("sha256:")
    # Empty tree root = sha256(b"")
    expected = f"sha256:{sha256(b'').hex()}"
    assert root == expected


def test_single_leaf():
    tree = MerkleTree()
    leaf = sha256(b"hello")
    tree.append(leaf)
    assert len(tree) == 1
    # Single leaf root = leaf itself
    assert tree.root() == f"sha256:{leaf.hex()}"


def test_two_leaves():
    tree = MerkleTree()
    leaf1 = sha256(b"a")
    leaf2 = sha256(b"b")
    tree.append(leaf1)
    tree.append(leaf2)
    assert len(tree) == 2
    # Root = sha256(leaf1 || leaf2)
    expected_root = sha256(leaf1 + leaf2)
    assert tree.root() == f"sha256:{expected_root.hex()}"


def test_three_leaves_odd_promotion():
    tree = MerkleTree()
    leaves = [sha256(bytes([i])) for i in range(3)]
    for leaf in leaves:
        tree.append(leaf)
    assert len(tree) == 3
    # Level 1: [hash(L0+L1), L2]  (L2 promoted as-is)
    # Root: hash(hash(L0+L1) + L2)
    h01 = sha256(leaves[0] + leaves[1])
    expected_root = sha256(h01 + leaves[2])
    assert tree.root() == f"sha256:{expected_root.hex()}"


def test_from_leaves():
    tree1 = MerkleTree()
    leaves = [sha256(bytes([i])) for i in range(5)]
    for leaf in leaves:
        tree1.append(leaf)

    tree2 = MerkleTree.from_leaves(leaves)
    assert tree1.root() == tree2.root()
    assert len(tree2) == 5


def test_proof_single_leaf():
    tree = MerkleTree()
    leaf = sha256(b"only")
    tree.append(leaf)
    proof = tree.proof(0)
    assert proof == []


def test_proof_two_leaves():
    tree = MerkleTree()
    leaf0 = sha256(b"a")
    leaf1 = sha256(b"b")
    tree.append(leaf0)
    tree.append(leaf1)

    # Proof for leaf 0: sibling is leaf1 on the right (is_left=False)
    proof = tree.proof(0)
    assert len(proof) == 1
    assert proof[0] == (False, leaf1)

    # Proof for leaf 1: sibling is leaf0 on the left (is_left=True)
    proof = tree.proof(1)
    assert len(proof) == 1
    assert proof[0] == (True, leaf0)


def test_verify_proof():
    tree = MerkleTree()
    leaves = [sha256(bytes([i])) for i in range(4)]
    for leaf in leaves:
        tree.append(leaf)

    root_str = tree.root()
    root_bytes = bytes.fromhex(root_str.removeprefix("sha256:"))

    for i in range(4):
        proof = tree.proof(i)
        assert proof is not None
        assert MerkleTree.verify_proof(leaves[i], proof, root_bytes)


def test_proof_out_of_bounds():
    tree = MerkleTree()
    tree.append(sha256(b"x"))
    assert tree.proof(-1) is None
    assert tree.proof(1) is None


def test_leaves_returns_copy():
    tree = MerkleTree()
    leaf = sha256(b"test")
    tree.append(leaf)
    leaves = tree.leaves()
    assert leaves == [leaf]
    leaves.clear()
    assert len(tree) == 1

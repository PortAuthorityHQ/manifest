"""Append-only Merkle tree matching manifest-core's MerkleTree."""

from __future__ import annotations

from .hashing import sha256


class MerkleTree:
    """Append-only Merkle tree for chaining receipts."""

    def __init__(self) -> None:
        self._leaves: list[bytes] = []

    @staticmethod
    def from_leaves(leaves: list[bytes]) -> MerkleTree:
        """Restore a tree from previously stored 32-byte leaf hashes."""
        tree = MerkleTree()
        tree._leaves = list(leaves)
        return tree

    def append(self, leaf: bytes) -> None:
        """Append a 32-byte leaf hash."""
        if len(leaf) != 32:
            raise ValueError(f"leaf must be 32 bytes, got {len(leaf)}")
        self._leaves.append(leaf)

    def root(self) -> str:
        """Compute the current Merkle root as 'sha256:<hex>'."""
        root_bytes = _compute_root(self._leaves)
        return f"sha256:{root_bytes.hex()}"

    def __len__(self) -> int:
        return len(self._leaves)

    def is_empty(self) -> bool:
        return len(self._leaves) == 0

    def proof(self, index: int) -> list[tuple[bool, bytes]] | None:
        """Generate an inclusion proof for the leaf at index.

        Returns list of (is_left, sibling_hash) tuples, or None if out of bounds.
        """
        if index < 0 or index >= len(self._leaves):
            return None
        return _compute_proof(self._leaves, index)

    @staticmethod
    def verify_proof(leaf: bytes, proof: list[tuple[bool, bytes]], root: bytes) -> bool:
        """Verify an inclusion proof against a root hash."""
        current = leaf
        for is_left, sibling in proof:
            if is_left:
                current = _hash_pair(sibling, current)
            else:
                current = _hash_pair(current, sibling)
        return current == root

    def leaves(self) -> list[bytes]:
        """Get all leaves (for persistence)."""
        return list(self._leaves)


def _hash_pair(left: bytes, right: bytes) -> bytes:
    """Hash two 32-byte children together."""
    return sha256(left + right)


def _compute_root(leaves: list[bytes]) -> bytes:
    """Compute Merkle root from a list of 32-byte leaf hashes."""
    if not leaves:
        return sha256(b"")
    if len(leaves) == 1:
        return leaves[0]

    current_level = list(leaves)
    while len(current_level) > 1:
        next_level = []
        for i in range(0, len(current_level), 2):
            if i + 1 < len(current_level):
                next_level.append(_hash_pair(current_level[i], current_level[i + 1]))
            else:
                # Odd node: promote as-is
                next_level.append(current_level[i])
        current_level = next_level

    return current_level[0]


def _compute_proof(leaves: list[bytes], index: int) -> list[tuple[bool, bytes]]:
    """Compute inclusion proof (sibling hashes along path to root)."""
    if len(leaves) <= 1:
        return []

    proof = []
    current_level = list(leaves)
    idx = index

    while len(current_level) > 1:
        if idx % 2 == 0:
            # Even index: sibling is to the right
            if idx + 1 < len(current_level):
                proof.append((False, current_level[idx + 1]))
            # If no right sibling, node is promoted — no proof element
        else:
            # Odd index: sibling is to the left
            proof.append((True, current_level[idx - 1]))

        # Build next level
        next_level = []
        for i in range(0, len(current_level), 2):
            if i + 1 < len(current_level):
                next_level.append(_hash_pair(current_level[i], current_level[i + 1]))
            else:
                next_level.append(current_level[i])
        current_level = next_level
        idx //= 2

    return proof

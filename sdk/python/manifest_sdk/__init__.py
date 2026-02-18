"""manifest-sdk: Cryptographic receipts for AI agent tool calls."""

from .hashing import sha256, sha256_hex
from .identity import AgentIdentity, IdentitySource
from .merkle import MerkleTree
from .policy import PolicyConfig
from .receipt import (
    Action,
    ActionError,
    Countersignature,
    Delta,
    PolicySnapshot,
    Proof,
    Receipt,
    ReceiptBuilder,
)
from .signer import Signer, load_public_key, verify_with_public_key
from .storage import Storage


class Manifest:
    """High-level convenience API for recording agent actions.

    Wraps Signer + MerkleTree + Storage + ReceiptBuilder into a single entry point.
    """

    def __init__(
        self,
        identity: str | AgentIdentity,
        *,
        key: str | None = None,
        db: str | None = None,
        policy: str | None = None,
    ) -> None:
        # Agent identity
        if isinstance(identity, str):
            self._identity = AgentIdentity(name=identity)
        else:
            self._identity = identity

        # Signing key
        if key:
            self._signer = Signer.from_file(key)
        else:
            self._signer = Signer.generate()

        # Storage
        if db:
            self._storage: Storage | None = Storage.open(db)
        else:
            self._storage = None

        # Merkle tree (restore from storage if available)
        self._merkle = MerkleTree()
        if self._storage:
            leaves = self._storage.load_merkle_leaves()
            if leaves:
                self._merkle = MerkleTree.from_leaves(leaves)

        # Policy
        self._policy_config: PolicyConfig | None = None
        if policy:
            self._policy_config = PolicyConfig.load(policy)

        # Receipt chaining
        self._last_hash: str | None = None
        if self._storage:
            self._last_hash = self._storage.latest_receipt_hash()

    def record(
        self,
        tool: str,
        input: object,
        output: object = None,
        error: ActionError | None = None,
        session_id: str | None = None,
    ) -> Receipt:
        """Record a tool call and return the signed receipt."""
        action = Action(tool=tool, input=input, output=output, error=error)

        # Evaluate policy if configured
        delta = None
        policy_snapshot = None
        if self._policy_config:
            violations = self._policy_config.evaluate(tool, input, output)
            delta = Delta(authorized=len(violations) == 0, violations=violations)
            policy_snapshot = self._policy_config.to_snapshot()

        builder = (
            ReceiptBuilder()
            .agent(self._identity)
            .action(action)
            .policy(policy_snapshot)
            .delta(delta)
            .previous_receipt(self._last_hash)
        )

        receipt = builder.build(self._signer, self._merkle)

        # Persist
        if self._storage:
            self._storage.insert_receipt(receipt, session_id)
            leaf_index = len(self._merkle) - 1
            hash_hex = receipt.content_hash().removeprefix("sha256:")
            self._storage.insert_merkle_leaf(leaf_index, bytes.fromhex(hash_hex))

        self._last_hash = receipt.content_hash()
        return receipt

    @property
    def signer(self) -> Signer:
        return self._signer

    @property
    def merkle(self) -> MerkleTree:
        return self._merkle

    @property
    def storage(self) -> Storage | None:
        return self._storage


__all__ = [
    "Action",
    "ActionError",
    "AgentIdentity",
    "Countersignature",
    "Delta",
    "IdentitySource",
    "Manifest",
    "MerkleTree",
    "PolicyConfig",
    "PolicySnapshot",
    "Proof",
    "Receipt",
    "ReceiptBuilder",
    "Signer",
    "Storage",
    "load_public_key",
    "sha256",
    "sha256_hex",
    "verify_with_public_key",
]

"""manifest-sdk: Cryptographic receipts for AI agent tool calls.

Powered by Rust via PyO3 — same Ed25519 signing, SHA-256 hashing,
and Merkle tree as the Rust CLI.
"""

from manifest_py import (
    PyMerkleTree as MerkleTree,
    PyPolicyConfig as PolicyConfig,
    PySigner as Signer,
    PyStorage as Storage,
    build_receipt,
    canonical_bytes,
    content_hash,
    load_public_key,
    sha256,
    sha256_hex,
    verify_with_public_key,
)


# ── Thin wrappers to give dicts an object-like API ───────────────────────

class _DictView:
    """Makes a dict accessible via attribute access."""

    def __init__(self, d):
        self._d = d

    def __getattr__(self, name):
        if name.startswith("_"):
            return super().__getattribute__(name)
        # Handle camelCase -> snake_case mapping for serde field renames
        key = name
        if key not in self._d:
            camel = _to_camel(key)
            if camel in self._d:
                key = camel
            else:
                # Optional fields may not exist — return None
                return None
        val = self._d[key]
        if isinstance(val, dict):
            return _DictView(val)
        return val

    def __bool__(self):
        return bool(self._d)

    def __repr__(self):
        return repr(self._d)

    def __iter__(self):
        return iter(self._d)

    def __contains__(self, key):
        return key in self._d


def _to_camel(snake: str) -> str:
    parts = snake.split("_")
    return parts[0] + "".join(p.capitalize() for p in parts[1:])


class Receipt:
    """Wraps a receipt dict with attribute access and helper methods."""

    def __init__(self, data: dict):
        self._data = data

    def __getattr__(self, name):
        if name.startswith("_"):
            return super().__getattribute__(name)
        key = name
        if key not in self._data:
            camel = _to_camel(key)
            if camel in self._data:
                key = camel
            else:
                return None
        val = self._data[key]
        if isinstance(val, dict):
            return _DictView(val)
        return val

    @property
    def timestamp(self):
        """Return timestamp as a datetime-like object with strftime."""
        from datetime import datetime, timezone
        ts = self._data["timestamp"]
        # Parse ISO 8601
        if ts.endswith("Z"):
            ts = ts[:-1] + "+00:00"
        return datetime.fromisoformat(ts)

    @property
    def delta(self):
        d = self._data.get("delta")
        if d is None:
            return None
        return _DictView(d)

    @property
    def policy(self):
        p = self._data.get("policy")
        if p is None:
            return None
        return _DictView(p)

    def content_hash(self) -> str:
        return content_hash(self._data)

    def canonical_bytes(self) -> bytes:
        return canonical_bytes(self._data)

    def to_dict(self) -> dict:
        return self._data

    def to_json(self, pretty: bool = False) -> str:
        import json
        if pretty:
            return json.dumps(self._data, indent=2, sort_keys=True)
        return json.dumps(self._data, sort_keys=True, separators=(",", ":"))

    def __repr__(self):
        return f"Receipt({self._data.get('id', '?')})"


# ── Identity helpers ─────────────────────────────────────────────────────

class IdentitySource:
    MCP_HANDSHAKE = "mcp_handshake"
    CONFIG = "config"
    ENVIRONMENT = "environment"


class AgentIdentity:
    def __init__(
        self,
        name: str,
        version: str | None = None,
        deployer: str | None = None,
        environment: str | None = None,
        source: str = IdentitySource.ENVIRONMENT,
        verified: bool = False,
    ):
        self.name = name
        self.version = version
        self.deployer = deployer
        self.environment = environment
        self.source = source
        self.verified = verified

    def to_dict(self):
        d = {"name": self.name, "source": self.source, "verified": self.verified}
        if self.version is not None:
            d["version"] = self.version
        if self.deployer is not None:
            d["deployer"] = self.deployer
        if self.environment is not None:
            d["environment"] = self.environment
        return d


# ── High-level Manifest class ────────────────────────────────────────────

class Manifest:
    """High-level convenience API for recording agent actions.

    Wraps Signer + MerkleTree + Storage + PolicyConfig into a single entry point.
    All crypto and storage operations happen in Rust.
    """

    def __init__(
        self,
        identity: str | AgentIdentity,
        *,
        key: str | None = None,
        db: str | None = None,
        policy: str | None = None,
    ) -> None:
        if isinstance(identity, str):
            self._identity = AgentIdentity(name=identity)
        else:
            self._identity = identity

        if key:
            self._signer = Signer.from_file(key)
        else:
            self._signer = Signer.generate()

        if db:
            self._storage: Storage | None = Storage.open(db)
        else:
            self._storage = None

        self._merkle = MerkleTree()
        if self._storage:
            leaves = self._storage.load_merkle_leaves()
            if leaves:
                self._merkle = MerkleTree.from_leaves(leaves)

        self._policy_config: PolicyConfig | None = None
        if policy:
            self._policy_config = PolicyConfig.load(policy)

        self._last_hash: str | None = None
        if self._storage:
            self._last_hash = self._storage.latest_receipt_hash()

    def record(
        self,
        tool: str,
        input: object,
        output: object = None,
        error: dict | None = None,
        session_id: str | None = None,
    ) -> Receipt:
        """Record a tool call and return the signed receipt."""
        # Evaluate policy
        delta_authorized = None
        delta_violations = None
        policy_snapshot = None

        if self._policy_config:
            agent_name = self._identity.name
            violations = self._policy_config.evaluate(tool, input, output, agent_name=agent_name)
            delta_authorized = len(violations) == 0
            delta_violations = violations
            policy_snapshot = self._policy_config.to_snapshot(agent_name=agent_name)

        # Build receipt via Rust
        error_code = error.get("code") if error else None
        error_message = error.get("message") if error else None
        error_data = error.get("data") if error else None

        receipt_dict = build_receipt(
            signer=self._signer,
            merkle=self._merkle,
            agent_name=self._identity.name,
            tool=tool,
            input=input,
            output=output,
            error_code=error_code,
            error_message=error_message,
            error_data=error_data,
            policy_snapshot=policy_snapshot,
            delta_authorized=delta_authorized,
            delta_violations=delta_violations,
            previous_receipt=self._last_hash,
            agent_version=self._identity.version,
            agent_source=self._identity.source,
        )

        receipt = Receipt(receipt_dict)

        # Persist
        if self._storage:
            self._storage.insert_receipt(receipt_dict, session_id)
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
    "AgentIdentity",
    "IdentitySource",
    "Manifest",
    "MerkleTree",
    "PolicyConfig",
    "Receipt",
    "Signer",
    "Storage",
    "build_receipt",
    "canonical_bytes",
    "content_hash",
    "load_public_key",
    "sha256",
    "sha256_hex",
    "verify_with_public_key",
]

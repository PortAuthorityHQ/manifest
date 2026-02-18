"""Receipt, ReceiptBuilder, Action, Delta, Proof matching manifest-core."""

from __future__ import annotations

import json
import os
import struct
import time
from datetime import datetime, timezone
from typing import Any

from .hashing import sha256, sha256_hex
from .identity import AgentIdentity
from .merkle import MerkleTree
from .signer import Signer


class ActionError:
    """Error details from a failed tool call."""

    def __init__(self, code: int, message: str, data: Any | None = None) -> None:
        self.code = code
        self.message = message
        self.data = data

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"code": self.code, "message": self.message}
        if self.data is not None:
            d["data"] = self.data
        return d


class Action:
    """A captured tool call action."""

    def __init__(
        self,
        tool: str,
        input: Any,
        output: Any | None = None,
        error: ActionError | None = None,
    ) -> None:
        self.tool = tool
        self.input = input
        self.output = output
        self.error = error

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"tool": self.tool, "input": self.input}
        if self.output is not None:
            d["output"] = self.output
        if self.error is not None:
            d["error"] = self.error.to_dict()
        return d


class Countersignature:
    """Third-party countersignature over a receipt."""

    def __init__(
        self, signer: str, algorithm: str, signature: str, timestamp: str
    ) -> None:
        self.signer = signer
        self.algorithm = algorithm
        self.signature = signature
        self.timestamp = timestamp

    def to_dict(self) -> dict[str, Any]:
        return {
            "signer": self.signer,
            "algorithm": self.algorithm,
            "signature": self.signature,
            "timestamp": self.timestamp,
        }


class Proof:
    """Cryptographic proof binding all receipt fields together."""

    def __init__(
        self,
        signature: str = "",
        merkle_root: str = "",
        previous_receipt: str | None = None,
        countersignatures: list[Countersignature] | None = None,
    ) -> None:
        self.signature = signature
        self.merkle_root = merkle_root
        self.previous_receipt = previous_receipt
        self.countersignatures = countersignatures

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "signature": self.signature,
            "merkleRoot": self.merkle_root,
        }
        if self.previous_receipt is not None:
            d["previousReceipt"] = self.previous_receipt
        if self.countersignatures is not None:
            d["countersignatures"] = [c.to_dict() for c in self.countersignatures]
        return d


class PolicySnapshot:
    """Snapshot of active policy at receipt time."""

    def __init__(
        self,
        snapshot: str,
        max_transaction_value: int | None = None,
        allowed_tools: list[str] | None = None,
    ) -> None:
        self.snapshot = snapshot
        self.max_transaction_value = max_transaction_value
        self.allowed_tools = allowed_tools

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {}
        if self.max_transaction_value is not None:
            d["maxTransactionValue"] = self.max_transaction_value
        if self.allowed_tools is not None:
            d["allowedTools"] = self.allowed_tools
        d["snapshot"] = self.snapshot
        return d


class Delta:
    """Authorization delta: was the action authorized, and what violations occurred?"""

    def __init__(self, authorized: bool, violations: list[str] | None = None) -> None:
        self.authorized = authorized
        self.violations = violations or []

    def to_dict(self) -> dict[str, Any]:
        return {"authorized": self.authorized, "violations": self.violations}


class Receipt:
    """A cryptographic receipt for a single tool call."""

    CONTEXT = "https://portauthority.dev/receipt/v1"

    def __init__(
        self,
        *,
        id: str,
        timestamp: datetime,
        agent: AgentIdentity,
        action: Action,
        proof: Proof,
        policy: PolicySnapshot | None = None,
        delta: Delta | None = None,
    ) -> None:
        self.context = self.CONTEXT
        self.id = id
        self.timestamp = timestamp
        self.agent = agent
        self.policy = policy
        self.action = action
        self.delta = delta
        self.proof = proof

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict matching Rust's serde JSON output."""
        d: dict[str, Any] = {
            "@context": self.context,
            "id": self.id,
            "timestamp": _format_timestamp(self.timestamp),
            "agent": self.agent.to_dict(),
        }
        if self.policy is not None:
            d["policy"] = self.policy.to_dict()
        d["action"] = self.action.to_dict()
        if self.delta is not None:
            d["delta"] = self.delta.to_dict()
        d["proof"] = self.proof.to_dict()
        return d

    def canonical_bytes(self) -> bytes:
        """Compute canonical bytes for signing.

        Includes all fields except proof.signature and proof.merkle_root.
        Uses sorted keys at every nesting level for deterministic output.
        """
        signable: dict[str, Any] = {
            "@context": self.context,
            "id": self.id,
            "timestamp": _format_timestamp(self.timestamp),
            "agent": self.agent.to_dict(),
            "policy": self.policy.to_dict() if self.policy else None,
            "action": self.action.to_dict(),
            "delta": self.delta.to_dict() if self.delta else None,
            "previousReceipt": self.proof.previous_receipt,
        }
        return json.dumps(signable, sort_keys=True, separators=(",", ":")).encode()

    def content_hash(self) -> str:
        """Compute SHA-256 content hash (post-signing, pre-Merkle).

        Covers identity + policy + action + delta + signature + previousReceipt.
        Excludes merkle_root because it depends on this hash.
        """
        hashable: dict[str, Any] = {
            "@context": self.context,
            "id": self.id,
            "timestamp": _format_timestamp(self.timestamp),
            "agent": self.agent.to_dict(),
            "policy": self.policy.to_dict() if self.policy else None,
            "action": self.action.to_dict(),
            "delta": self.delta.to_dict() if self.delta else None,
            "signature": self.proof.signature,
            "previousReceipt": self.proof.previous_receipt,
        }
        data = json.dumps(hashable, sort_keys=True, separators=(",", ":")).encode()
        return sha256_hex(data)

    def to_json(self, pretty: bool = False) -> str:
        """Serialize the full receipt to JSON."""
        if pretty:
            return json.dumps(self.to_dict(), indent=2, sort_keys=True)
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))

    @staticmethod
    def from_json(data: str) -> Receipt:
        """Deserialize a receipt from JSON."""
        obj = json.loads(data)
        return Receipt.from_dict(obj)

    @staticmethod
    def from_dict(obj: dict[str, Any]) -> Receipt:
        """Deserialize a receipt from a dict."""
        agent_d = obj["agent"]
        from .identity import IdentitySource

        agent = AgentIdentity(
            name=agent_d["name"],
            version=agent_d.get("version"),
            deployer=agent_d.get("deployer"),
            environment=agent_d.get("environment"),
            source=IdentitySource(agent_d["source"]),
            verified=agent_d.get("verified", False),
        )

        action_d = obj["action"]
        error = None
        if action_d.get("error"):
            e = action_d["error"]
            error = ActionError(code=e["code"], message=e["message"], data=e.get("data"))
        action = Action(
            tool=action_d["tool"],
            input=action_d["input"],
            output=action_d.get("output"),
            error=error,
        )

        proof_d = obj["proof"]
        countersignatures = None
        if proof_d.get("countersignatures"):
            countersignatures = [
                Countersignature(
                    signer=c["signer"],
                    algorithm=c["algorithm"],
                    signature=c["signature"],
                    timestamp=c["timestamp"],
                )
                for c in proof_d["countersignatures"]
            ]
        proof = Proof(
            signature=proof_d["signature"],
            merkle_root=proof_d["merkleRoot"],
            previous_receipt=proof_d.get("previousReceipt"),
            countersignatures=countersignatures,
        )

        policy = None
        if obj.get("policy"):
            p = obj["policy"]
            policy = PolicySnapshot(
                snapshot=p["snapshot"],
                max_transaction_value=p.get("maxTransactionValue"),
                allowed_tools=p.get("allowedTools"),
            )

        delta = None
        if obj.get("delta"):
            d = obj["delta"]
            delta = Delta(authorized=d["authorized"], violations=d.get("violations", []))

        timestamp = datetime.fromisoformat(obj["timestamp"].replace("Z", "+00:00"))

        return Receipt(
            id=obj["id"],
            timestamp=timestamp,
            agent=agent,
            action=action,
            proof=proof,
            policy=policy,
            delta=delta,
        )


class ReceiptBuilder:
    """Builder for constructing and signing receipts."""

    def __init__(self) -> None:
        self._agent: AgentIdentity | None = None
        self._policy: PolicySnapshot | None = None
        self._action: Action | None = None
        self._delta: Delta | None = None
        self._previous_receipt: str | None = None

    def agent(self, identity: AgentIdentity) -> ReceiptBuilder:
        self._agent = identity
        return self

    def policy(self, snapshot: PolicySnapshot | None) -> ReceiptBuilder:
        self._policy = snapshot
        return self

    def action(self, action: Action) -> ReceiptBuilder:
        self._action = action
        return self

    def delta(self, delta: Delta | None) -> ReceiptBuilder:
        self._delta = delta
        return self

    def previous_receipt(self, hash: str | None) -> ReceiptBuilder:
        self._previous_receipt = hash
        return self

    def build(self, signer: Signer, merkle: MerkleTree) -> Receipt:
        """Build, sign, and chain the receipt into the Merkle tree.

        Flow:
        1. Assemble all fields with placeholder proof
        2. Compute canonical bytes and sign
        3. Compute content hash (includes signature)
        4. Append to Merkle tree and set the root
        """
        if self._agent is None:
            raise ValueError("receipt requires agent identity")
        if self._action is None:
            raise ValueError("receipt requires action")

        # Step 1: Assemble with placeholder proof
        receipt = Receipt(
            id=f"urn:uuid:{_uuid7()}",
            timestamp=datetime.now(timezone.utc),
            agent=self._agent,
            action=self._action,
            proof=Proof(
                signature="",
                merkle_root="",
                previous_receipt=self._previous_receipt,
            ),
            policy=self._policy,
            delta=self._delta,
        )

        # Step 2: Sign the canonical bytes
        canonical = receipt.canonical_bytes()
        receipt.proof.signature = signer.sign(canonical)

        # Step 3: Compute content hash (covers signature)
        content_hash = receipt.content_hash()

        # Step 4: Append to Merkle tree
        hash_hex = content_hash.removeprefix("sha256:")
        hash_bytes = bytes.fromhex(hash_hex)
        merkle.append(hash_bytes)
        receipt.proof.merkle_root = merkle.root()

        return receipt


def _uuid7() -> str:
    """Generate a UUID v7 (timestamp-ordered, random) matching Rust's Uuid::now_v7()."""
    # 48-bit Unix timestamp in milliseconds
    ms = int(time.time() * 1000)
    # 4-bit version (0b0111 = 7)
    # 12-bit random
    rand_a = int.from_bytes(os.urandom(2), "big") & 0x0FFF
    time_and_version = (ms << 16) | (0x7000) | rand_a
    # 2-bit variant (0b10) + 62-bit random
    rand_b = int.from_bytes(os.urandom(8), "big") & 0x3FFFFFFFFFFFFFFF
    rand_b |= 0x8000000000000000  # set variant bits

    hi = time_and_version
    lo = rand_b

    b = struct.pack(">QQ", hi, lo)
    h = b.hex()
    return f"{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


def _format_timestamp(dt: datetime) -> str:
    """Format datetime to RFC 3339 matching Rust's chrono serialization."""
    # Rust's chrono serializes as: 2026-02-18T12:00:00.000000000Z (nanoseconds)
    # Python's isoformat gives: 2026-02-18T12:00:00.000000+00:00
    # We need to match Rust's format for cross-verification
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc)
    # Use isoformat but replace +00:00 with Z
    s = dt.isoformat()
    if s.endswith("+00:00"):
        s = s[:-6] + "Z"
    return s

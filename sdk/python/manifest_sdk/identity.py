"""Agent identity matching manifest-core's AgentIdentity."""

from __future__ import annotations

import os
import platform
import sys
from enum import Enum
from pathlib import Path
from typing import Any

import yaml


class IdentitySource(Enum):
    """How the agent identity was determined."""

    MCP_HANDSHAKE = "mcp_handshake"
    CONFIG = "config"
    ENVIRONMENT = "environment"


class AgentIdentity:
    """Agent identity included in every receipt."""

    def __init__(
        self,
        name: str,
        *,
        version: str | None = None,
        deployer: str | None = None,
        environment: str | None = None,
        source: IdentitySource = IdentitySource.ENVIRONMENT,
        verified: bool = False,
    ) -> None:
        self.name = name
        self.version = version
        self.deployer = deployer
        self.environment = environment
        self.source = source
        self.verified = verified

    @staticmethod
    def from_mcp_client_info(name: str, version: str | None = None) -> AgentIdentity:
        """Build identity from MCP initialize handshake clientInfo."""
        return AgentIdentity(
            name=name,
            version=version,
            source=IdentitySource.MCP_HANDSHAKE,
        )

    @staticmethod
    def from_config_file(path: str) -> AgentIdentity:
        """Build identity from a YAML config file."""
        data = yaml.safe_load(Path(path).read_text())
        agent = data["agent"]
        return AgentIdentity(
            name=agent["name"],
            deployer=agent.get("deployer"),
            environment=agent.get("environment"),
            source=IdentitySource.CONFIG,
        )

    @staticmethod
    def from_environment() -> AgentIdentity:
        """Build identity from the runtime environment."""
        name = Path(sys.executable).name if sys.executable else "unknown"
        deployer = platform.node() or None
        environment = os.environ.get("MANIFEST_ENV")
        return AgentIdentity(
            name=name,
            deployer=deployer,
            environment=environment,
            source=IdentitySource.ENVIRONMENT,
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict, omitting None fields (matching Rust's skip_serializing_if)."""
        d: dict[str, Any] = {"name": self.name}
        if self.version is not None:
            d["version"] = self.version
        if self.deployer is not None:
            d["deployer"] = self.deployer
        if self.environment is not None:
            d["environment"] = self.environment
        d["source"] = self.source.value
        d["verified"] = self.verified
        return d

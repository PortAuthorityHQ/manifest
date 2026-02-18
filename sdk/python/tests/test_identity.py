"""Tests for agent identity."""

from manifest_sdk import AgentIdentity, IdentitySource


def test_from_mcp_client_info():
    identity = AgentIdentity.from_mcp_client_info("claude-desktop", "1.2.0")
    assert identity.name == "claude-desktop"
    assert identity.version == "1.2.0"
    assert identity.source == IdentitySource.MCP_HANDSHAKE
    assert identity.verified is False


def test_from_environment():
    identity = AgentIdentity.from_environment()
    assert identity.name
    assert identity.source == IdentitySource.ENVIRONMENT
    assert identity.verified is False


def test_from_config_file(tmp_path):
    config = tmp_path / "identity.yml"
    config.write_text(
        """
agent:
  name: "procurement-bot"
  deployer: "acme-corp"
  environment: "production"
"""
    )

    identity = AgentIdentity.from_config_file(str(config))
    assert identity.name == "procurement-bot"
    assert identity.deployer == "acme-corp"
    assert identity.environment == "production"
    assert identity.source == IdentitySource.CONFIG


def test_to_dict_omits_none():
    identity = AgentIdentity.from_mcp_client_info("test-agent")
    d = identity.to_dict()
    assert d["source"] == "mcp_handshake"
    assert d["verified"] is False
    assert "version" not in d
    assert "deployer" not in d
    assert "environment" not in d


def test_to_dict_includes_present_fields():
    identity = AgentIdentity(
        name="bot",
        version="2.0",
        deployer="corp",
        environment="staging",
        source=IdentitySource.CONFIG,
        verified=False,
    )
    d = identity.to_dict()
    assert d["name"] == "bot"
    assert d["version"] == "2.0"
    assert d["deployer"] == "corp"
    assert d["environment"] == "staging"

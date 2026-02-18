"""Tests for policy evaluation."""

from manifest_sdk import PolicyConfig


def test_load_from_yaml(tmp_path):
    policy_file = tmp_path / "policy.yml"
    policy_file.write_text(
        """
policies:
  - name: spending-limit
    max_transaction_value: 50000
  - name: tool-allowlist
    allowed_tools:
      - db_query
      - send_email
  - name: pii-flag
    flag_if_contains:
      - SSN
      - credit_card
"""
    )
    config = PolicyConfig.load(str(policy_file))
    assert len(config.policies) == 3


def test_to_snapshot():
    config = PolicyConfig(
        [
            {"name": "spending-limit", "max_transaction_value": 10000},
            {"name": "tool-allowlist", "allowed_tools": ["read_file"]},
        ]
    )
    snapshot = config.to_snapshot()
    assert snapshot.max_transaction_value == 10000
    assert snapshot.allowed_tools == ["read_file"]
    assert snapshot.snapshot.startswith("sha256:")


def test_tool_allowlist():
    config = PolicyConfig(
        [{"name": "tool-allowlist", "allowed_tools": ["db_query", "send_email"]}]
    )
    assert config.is_tool_allowed("db_query") is True
    assert config.is_tool_allowed("drop_table") is False


def test_no_allowlist_returns_none():
    config = PolicyConfig(
        [{"name": "spending-limit", "max_transaction_value": 5000}]
    )
    assert config.is_tool_allowed("anything") is None


def test_spending_limit_violation():
    config = PolicyConfig(
        [{"name": "spending-limit", "max_transaction_value": 10000}]
    )
    violations = config.evaluate("transfer", {"amount": 50000, "currency": "USD"})
    assert len(violations) == 1
    assert "spending_limit_exceeded" in violations[0]
    assert "50000" in violations[0]


def test_spending_limit_passes():
    config = PolicyConfig(
        [{"name": "spending-limit", "max_transaction_value": 10000}]
    )
    violations = config.evaluate("transfer", {"amount": 500})
    assert len(violations) == 0


def test_spending_limit_with_field_path():
    config = PolicyConfig(
        [
            {
                "name": "spending-limit",
                "max_transaction_value": 50000,
                "field_path": "$.amount",
            }
        ]
    )
    # Only the "amount" field is checked, not "page"
    violations = config.evaluate("transfer", {"amount": 100000, "page": 99999})
    assert len(violations) == 1
    assert "100000" in violations[0]


def test_spending_limit_field_path_passes():
    config = PolicyConfig(
        [
            {
                "name": "spending-limit",
                "max_transaction_value": 50000,
                "field_path": "$.amount",
            }
        ]
    )
    violations = config.evaluate("transfer", {"amount": 100, "page": 99999})
    assert len(violations) == 0


def test_pii_flag_input():
    config = PolicyConfig(
        [{"name": "pii-flag", "flag_if_contains": ["SSN", "credit_card"]}]
    )
    violations = config.evaluate("db_query", {"query": "SELECT ssn FROM users"})
    assert len(violations) == 1
    assert "pii_detected_in_input" in violations[0]


def test_pii_flag_output():
    config = PolicyConfig(
        [{"name": "pii-flag", "flag_if_contains": ["credit_card"]}]
    )
    violations = config.evaluate(
        "db_query",
        {"query": "SELECT * FROM payments"},
        {"rows": [{"credit_card": "4111-1111-1111"}]},
    )
    assert len(violations) == 1
    assert "pii_detected_in_output" in violations[0]


def test_pii_regex_ssn():
    config = PolicyConfig(
        [{"name": "pii-regex", "builtin": ["ssn"], "custom": {}}]
    )
    violations = config.evaluate("query", {"data": "SSN is 123-45-6789"})
    assert len(violations) == 1
    assert "pii_regex_match_in_input" in violations[0]


def test_pii_regex_no_false_positive():
    config = PolicyConfig(
        [{"name": "pii-regex", "builtin": ["ssn"], "custom": {}}]
    )
    violations = config.evaluate("task", {"action": "assign task to user"})
    assert len(violations) == 0


def test_pii_regex_credit_card():
    config = PolicyConfig(
        [{"name": "pii-regex", "builtin": ["credit_card"], "custom": {}}]
    )
    violations = config.evaluate("payment", {"card": "4111111111111111"})
    assert len(violations) == 1
    assert "credit_card" in violations[0]


def test_pii_regex_custom():
    config = PolicyConfig(
        [
            {
                "name": "pii-regex",
                "builtin": [],
                "custom": {"passport": r"\b[A-Z]\d{8}\b"},
            }
        ]
    )
    violations = config.evaluate("verify", {"doc": "Passport: A12345678"})
    assert len(violations) == 1
    assert "passport" in violations[0]


def test_multiple_rules():
    config = PolicyConfig(
        [
            {"name": "tool-allowlist", "allowed_tools": ["db_query"]},
            {"name": "spending-limit", "max_transaction_value": 1000},
            {"name": "pii-flag", "flag_if_contains": ["SSN"]},
        ]
    )
    violations = config.evaluate("transfer", {"amount": 5000, "field": "ssn"})
    assert len(violations) == 3


def test_snapshot_hash_is_deterministic():
    config = PolicyConfig(
        [{"name": "spending-limit", "max_transaction_value": 100}]
    )
    assert config.snapshot_hash() == config.snapshot_hash()

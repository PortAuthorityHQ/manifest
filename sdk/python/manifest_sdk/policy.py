"""Policy evaluation matching manifest-core's PolicyConfig."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import yaml

from .hashing import sha256_hex
from .receipt import PolicySnapshot


class PolicyConfig:
    """Top-level policy configuration loaded from YAML."""

    def __init__(self, policies: list[dict[str, Any]]) -> None:
        self.policies = policies
        self._compiled_patterns: list[tuple[str, re.Pattern]] | None = None

    @staticmethod
    def load(path: str) -> PolicyConfig:
        """Load policy configuration from a YAML file."""
        data = yaml.safe_load(Path(path).read_text())
        return PolicyConfig(data["policies"])

    def snapshot_hash(self) -> str:
        """Compute a deterministic SHA-256 hash of this policy configuration."""
        canonical = json.dumps(
            {"policies": self.policies}, sort_keys=True, separators=(",", ":")
        )
        return sha256_hex(canonical.encode())

    def to_snapshot(self) -> PolicySnapshot:
        """Convert to a PolicySnapshot for embedding in receipts."""
        max_value = None
        allowed = None

        for rule in self.policies:
            name = rule.get("name")
            if name == "spending-limit":
                max_value = rule.get("max_transaction_value")
            elif name == "tool-allowlist":
                allowed = rule.get("allowed_tools", [])

        return PolicySnapshot(
            snapshot=self.snapshot_hash(),
            max_transaction_value=max_value,
            allowed_tools=allowed,
        )

    def is_tool_allowed(self, tool_name: str) -> bool | None:
        """Check if a tool is allowed. Returns None if no allowlist configured."""
        for rule in self.policies:
            if rule.get("name") == "tool-allowlist":
                return tool_name in rule.get("allowed_tools", [])
        return None

    def _get_compiled_patterns(self) -> list[tuple[str, re.Pattern]]:
        """Get or compile cached regex patterns."""
        if self._compiled_patterns is not None:
            return self._compiled_patterns

        patterns: list[tuple[str, re.Pattern]] = []
        for rule in self.policies:
            if rule.get("name") != "pii-regex":
                continue
            for name in rule.get("builtin", []):
                regex = _builtin_pii_regex(name)
                if regex:
                    patterns.append((name, regex))
            for label, pattern in rule.get("custom", {}).items():
                try:
                    patterns.append((label, re.compile(pattern)))
                except re.error:
                    pass

        self._compiled_patterns = patterns
        return patterns

    def evaluate(
        self,
        tool_name: str,
        input: Any,
        output: Any | None = None,
    ) -> list[str]:
        """Evaluate all policy rules against a tool call.

        Returns a list of violation strings. Empty list means fully authorized.
        """
        violations: list[str] = []

        for rule in self.policies:
            name = rule.get("name")

            if name == "tool-allowlist":
                allowed_tools = rule.get("allowed_tools", [])
                if tool_name not in allowed_tools:
                    tools_str = ", ".join(allowed_tools)
                    violations.append(
                        f"tool_not_in_allowlist: '{tool_name}' not in [{tools_str}]"
                    )

            elif name == "spending-limit":
                max_val = rule.get("max_transaction_value", 0)
                field_path = rule.get("field_path")
                if field_path:
                    value = _resolve_field_path(input, field_path)
                    if value is not None and value > max_val:
                        violations.append(
                            f"spending_limit_exceeded: value {value} exceeds max {max_val}"
                        )
                else:
                    for value in _extract_numeric_values(input):
                        if value > max_val:
                            violations.append(
                                f"spending_limit_exceeded: value {value} exceeds max {max_val}"
                            )

            elif name == "pii-flag":
                flag_patterns = rule.get("flag_if_contains", [])
                input_str = json.dumps(input).lower()
                for pattern in flag_patterns:
                    if pattern.lower() in input_str:
                        violations.append(f"pii_detected_in_input: '{pattern}'")
                if output is not None:
                    output_str = json.dumps(output).lower()
                    for pattern in flag_patterns:
                        if pattern.lower() in output_str:
                            violations.append(f"pii_detected_in_output: '{pattern}'")

            elif name == "pii-regex":
                patterns = self._get_compiled_patterns()
                input_str = json.dumps(input)
                for label, regex in patterns:
                    if regex.search(input_str):
                        violations.append(f"pii_regex_match_in_input: '{label}'")
                if output is not None:
                    output_str = json.dumps(output)
                    for label, regex in patterns:
                        if regex.search(output_str):
                            violations.append(f"pii_regex_match_in_output: '{label}'")

        return violations


def _builtin_pii_regex(name: str) -> re.Pattern | None:
    """Get a built-in regex pattern for a named PII type."""
    patterns = {
        "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
        "credit_card": r"\b(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|3[47]\d{13}|6(?:011|5\d{2})\d{12})\b",
        "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        "phone": r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
    }
    pattern = patterns.get(name)
    if pattern:
        return re.compile(pattern)
    return None


def _resolve_field_path(value: Any, path: str) -> float | None:
    """Resolve a field path to a numeric value."""
    if path.startswith("/"):
        parts = [p for p in path.split("/") if p]
    else:
        stripped = path.removeprefix("$.")
        parts = stripped.split(".")

    current = value
    for part in parts:
        if isinstance(current, dict):
            if part not in current:
                return None
            current = current[part]
        elif isinstance(current, list):
            try:
                idx = int(part)
                current = current[idx]
            except (ValueError, IndexError):
                return None
        else:
            return None

    if isinstance(current, (int, float)):
        return float(current)
    return None


def _extract_numeric_values(value: Any) -> list[float]:
    """Recursively extract all numeric values from a JSON-like structure."""
    values: list[float] = []
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        values.append(float(value))
    elif isinstance(value, dict):
        for v in value.values():
            values.extend(_extract_numeric_values(v))
    elif isinstance(value, list):
        for v in value:
            values.extend(_extract_numeric_values(v))
    return values

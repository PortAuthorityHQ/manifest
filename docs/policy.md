# Policy Configuration

Policies are optional. Without them, `manifest` generates signed receipts for every tool call. With policies, receipts also include an authorization verdict (`delta.authorized`) and any violations.

## Quick Walkthrough

**Step 1: Run your server through manifest without a policy first.**

```bash
manifest proxy --server "your-mcp-server-command"
```

**Step 2: Use your agent normally, then check what tools it called.**

```bash
manifest log --tail 10
```

```
TIMESTAMP                TOOL                 AGENT                STATUS       HASH
----------------------------------------------------------------------------------------------------
2026-02-19 01:32:22      place_order          buyer-bot            -            sha256:08c880cde570...
2026-02-19 01:32:22      search               buyer-bot            -            sha256:8dbb2aba0f83...
2026-02-19 01:32:21      summarize            chat-bot             -            sha256:02bda8da1b26...
```

The TOOL column shows the exact tool names your MCP server exposes. The AGENT column shows the agent name (from the MCP handshake or your `--identity` config). Use these exact names in your policy.

**Step 3: Write a policy using those names.**

```yaml
# policy.yaml
policies:
  - name: tool-allowlist
    agents: [chat-bot]
    allowed_tools: [search, summarize]

  - name: tool-allowlist
    agents: [buyer-bot]
    allowed_tools: [search, place_order]

  - name: spending-limit
    agents: [buyer-bot]
    max_transaction_value: 5000
    field_path: "$.amount"
```

**Step 4: Restart the proxy with the policy.**

```bash
manifest proxy --server "your-mcp-server-command" --policy policy.yaml
```

Now every tool call is checked against your rules. Run `manifest log --tail 10` again and you'll see the STATUS column light up — green `ok` for authorized calls, red `VIOLATION` for anything outside the policy.

## Rule Types

### Tool Allowlist

Only allow specific tools. Any tool not in the list triggers a violation.

```yaml
policies:
  - name: tool-allowlist
    allowed_tools: [db_query, send_email, read_file]
```

### Spending Limit

Flag tool calls where numeric values exceed a threshold.

```yaml
policies:
  - name: spending-limit
    max_transaction_value: 50000
    field_path: "$.amount"    # Only check this field
```

Without `field_path`, all numeric values in the JSON input are checked recursively. This means `{"page": 50000}` would trigger a violation — use `field_path` to target the right field.

`field_path` supports dot notation (`$.order.total`) and JSON pointer (`/order/total`).

### PII Detection (Regex)

Pattern-based PII detection in both input and output. Built-in patterns for common types, plus custom regex support.

```yaml
policies:
  - name: pii-regex
    builtin:
      - ssn           # US Social Security Numbers (XXX-XX-XXXX)
      - credit_card   # Major credit card numbers
      - email         # Email addresses
      - phone         # US phone numbers
    custom:
      passport: '\b[A-Z]\d{8}\b'
```

### PII Detection (String Match)

Simpler substring matching. Faster but prone to false positives (e.g., "assign" matches "ssn").

```yaml
policies:
  - name: pii-flag
    flag_if_contains: [SSN, credit_card, date_of_birth]
```

Use `pii-regex` when precision matters.

### Rate Limit

Limit how many times a tool can be called per session. Prevents runaway agents from hammering a tool in a loop.

```yaml
policies:
  - name: rate-limit
    tool: db_insert
    max_calls: 10
```

Each agent tracks its own counter — if `agent-a` hits the limit, `agent-b` is unaffected. Counters reset when a new proxy session starts.

You can scope rate limits to specific agents:

```yaml
policies:
  - name: rate-limit
    agents: [buyer-bot]
    tool: purchase
    max_calls: 5
```

## Per-Agent Scoping

Different agents can have different policies. Add an `agents` field to scope a rule to specific agent names. Rules without `agents` apply to everyone.

```yaml
policies:
  # Global — applies to all agents
  - name: pii-regex
    builtin: [ssn, credit_card]

  # Chat agents can only read
  - name: tool-allowlist
    agents: [chat-bot]
    allowed_tools: [db_query]

  # Buyer agents can read + write, with spending cap
  - name: tool-allowlist
    agents: [buyer-bot]
    allowed_tools: [db_query, db_insert, purchase]

  - name: spending-limit
    agents: [buyer-bot]
    max_transaction_value: 10000
    field_path: "$.amount"
```

The agent name comes from (in priority order):
1. Identity config file (`--identity`)
2. MCP `initialize` handshake (`clientInfo.name`)
3. Environment fallback (process name)

## Combining Rules

Multiple rules are evaluated independently. A tool call can trigger multiple violations:

```yaml
policies:
  - name: tool-allowlist
    allowed_tools: [db_query]
  - name: spending-limit
    max_transaction_value: 1000
  - name: pii-flag
    flag_if_contains: [SSN]
```

A call to `transfer` with `{"amount": 5000, "field": "ssn"}` would produce 3 violations:
- `tool_not_in_allowlist`
- `spending_limit_exceeded`
- `pii_detected_in_input`

## Policy Snapshots

Each receipt embeds a snapshot of the active policy (allowed tools, spending limits) and a SHA-256 hash of the full config. This proves what rules were in effect at the exact moment of the tool call.

PII and rate-limit rules are not included in the snapshot — they are evaluated at runtime only.

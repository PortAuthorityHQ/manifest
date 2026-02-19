# SIEM Export

Stream receipts to your security infrastructure in real-time, or batch export existing receipts.

## Real-Time Streaming

Add `--sink` to either proxy mode to POST each receipt as it's generated:

```bash
# Stream to any HTTP endpoint
manifest proxy --server "your-mcp-server" \
    --sink http://collector.example.com/receipts

# Stream to Splunk HEC
manifest proxy --server "your-mcp-server" \
    --sink https://splunk.example.com:8088/services/collector \
    --sink-token "your-hec-token" \
    --sink-format splunk-hec

# Works with proxy-http too
manifest proxy-http --upstream http://localhost:9090/mcp --port 8080 \
    --sink https://sentinel.example.com/api/logs \
    --sink-token "your-api-key"
```

## Batch Export

Export existing receipts from the database:

```bash
# Export all receipts to Splunk
manifest export --format json \
    --sink https://splunk.example.com:8088/services/collector \
    --sink-token "your-hec-token" \
    --sink-format splunk-hec

# Export a specific session
manifest export --session <session-id> \
    --sink http://collector.example.com/receipts
```

## Formats

| Format | `--sink-format` | Payload |
|--------|----------------|---------|
| Raw JSON (default) | `json` | Receipt JSON |
| Splunk HEC | `splunk-hec` | `{"event": <receipt>, "sourcetype": "manifest:receipt"}` |

## Webhook Alerts

For real-time policy violation alerts (separate from SIEM export):

```bash
manifest proxy --server "your-server" --policy policy.yaml \
    --webhook https://hooks.slack.com/services/...
```

Webhook payload:
```json
{
  "event": "policy_violation",
  "timestamp": "2026-02-19T01:32:22Z",
  "tool": "db_insert",
  "agent": "procurement-bot",
  "violations": ["tool_not_in_allowlist: 'db_insert' not in [db_query]"]
}
```

Sink export is best-effort — failures are logged but never block receipt generation.

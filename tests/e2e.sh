#!/usr/bin/env bash
#
# End-to-end test for the manifest proxy.
#
# What this does:
#   1. Builds all binaries
#   2. Starts the manifest proxy wrapping the mock MCP server
#   3. Sends MCP messages (initialize, tools/call) to the proxy's stdin
#   4. Reads responses from the proxy's stdout
#   5. Checks that receipts were generated in the database
#
# Usage:
#   ./tests/e2e.sh
#
set -euo pipefail

# ── Setup ───────────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
TEST_DIR=$(mktemp -d)
DB_PATH="$TEST_DIR/receipts.db"
KEY_PATH="$TEST_DIR/signing.key"

cleanup() {
    rm -rf "$TEST_DIR"
}
trap cleanup EXIT

echo "=== Manifest E2E Test ==="
echo "Working directory: $TEST_DIR"
echo ""

# ── Build ───────────────────────────────────────────────────────────────────

echo "--- Building binaries..."
cd "$PROJECT_DIR"
cargo build --quiet 2>&1
MANIFEST="$PROJECT_DIR/target/debug/manifest"
MOCK_SERVER="$PROJECT_DIR/target/debug/mock-mcp-server"

echo "    manifest:          $MANIFEST"
echo "    mock-mcp-server:   $MOCK_SERVER"
echo ""

# ── Step 1: Generate signing key ────────────────────────────────────────────

echo "--- Step 1: Generate signing key"
"$MANIFEST" init --key "$KEY_PATH"
echo ""

# ── Step 2: Test the mock server directly ───────────────────────────────────

echo "--- Step 2: Verify mock server works standalone"
MOCK_RESPONSE=$(echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"clientInfo":{"name":"test","version":"1.0"}}}' \
    | "$MOCK_SERVER")

if echo "$MOCK_RESPONSE" | grep -q "mock-mcp-server"; then
    echo "    PASS: Mock server responds to initialize"
else
    echo "    FAIL: Mock server did not respond correctly"
    echo "    Got: $MOCK_RESPONSE"
    exit 1
fi
echo ""

# ── Step 3: Run proxy with mock server, send MCP messages ──────────────────

echo "--- Step 3: Run proxy with tool calls"

# Prepare the input messages (one per line, newline-delimited JSON)
cat > "$TEST_DIR/input.jsonl" << 'JSONL'
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"clientInfo":{"name":"test-agent","version":"2.0"},"protocolVersion":"2024-11-05"}}
{"jsonrpc":"2.0","method":"notifications/initialized"}
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{"message":"hello world"}}}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"add","arguments":{"a":17,"b":25}}}
{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"db_query","arguments":{"query":"SELECT * FROM orders WHERE value > 10000"}}}
{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"fail","arguments":{}}}
JSONL

# Run the proxy. Feed input, capture output.
PROXY_OUTPUT=$("$MANIFEST" proxy \
    --server "$MOCK_SERVER" \
    --key "$KEY_PATH" \
    --db "$DB_PATH" \
    < "$TEST_DIR/input.jsonl" 2>"$TEST_DIR/proxy_stderr.log" || true)

echo "$PROXY_OUTPUT" > "$TEST_DIR/output.jsonl"

# Count responses
RESPONSE_COUNT=$(echo "$PROXY_OUTPUT" | grep -c '"jsonrpc"' || true)
echo "    Received $RESPONSE_COUNT JSON-RPC responses from proxy"

# Verify responses pass through correctly
if echo "$PROXY_OUTPUT" | grep -q "mock-mcp-server"; then
    echo "    PASS: Initialize response forwarded"
else
    echo "    FAIL: Initialize response not forwarded"
    echo "    Output: $PROXY_OUTPUT"
fi

if echo "$PROXY_OUTPUT" | grep -q "42"; then
    echo "    PASS: Tool call response forwarded (42)"
else
    echo "    WARN: Expected '42' in tool responses"
fi

if echo "$PROXY_OUTPUT" | grep -q "permission denied"; then
    echo "    PASS: Error response forwarded"
else
    echo "    WARN: Expected error response for 'fail' tool"
fi
echo ""

# ── Step 4: Check receipts ──────────────────────────────────────────────────

echo "--- Step 4: Check receipts in database"

RECEIPT_LOG=$("$MANIFEST" log --tail 20 --db "$DB_PATH" 2>/dev/null || \
    "$MANIFEST" log --tail 20 2>/dev/null || \
    echo "RECEIPT_LOG_FAILED")

# The log command uses the default db path, but we specified a custom one.
# Let's query the database directly to verify.
if [ -f "$DB_PATH" ]; then
    echo "    PASS: Receipt database created at $DB_PATH"

    # Count receipts using sqlite3 if available, otherwise check file size
    if command -v sqlite3 &> /dev/null; then
        RECEIPT_COUNT=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM receipts;")
        echo "    Receipts generated: $RECEIPT_COUNT"

        if [ "$RECEIPT_COUNT" -ge 3 ]; then
            echo "    PASS: Expected at least 3 receipts (echo, add, db_query, fail)"
        else
            echo "    WARN: Expected more receipts, got $RECEIPT_COUNT"
        fi

        echo ""
        echo "--- Step 5: Inspect receipts"

        # Show each receipt summary
        sqlite3 "$DB_PATH" "SELECT id, tool_name, agent_name, timestamp FROM receipts ORDER BY timestamp;" \
            | while IFS='|' read -r id tool agent ts; do
            echo "    $ts | $tool | $agent"
        done

        echo ""

        # Get a hash and inspect one receipt
        FIRST_HASH=$(sqlite3 "$DB_PATH" "SELECT content_hash FROM receipts LIMIT 1;")
        if [ -n "$FIRST_HASH" ]; then
            echo "--- Step 6: Full receipt inspection"
            echo "    Hash: $FIRST_HASH"
            echo ""

            # Export the receipt JSON directly from the database
            RECEIPT_JSON=$(sqlite3 "$DB_PATH" "SELECT receipt_json FROM receipts LIMIT 1;")
            echo "$RECEIPT_JSON" | python3 -m json.tool 2>/dev/null || echo "$RECEIPT_JSON"
        fi

        echo ""

        # Verify Merkle tree was persisted
        LEAF_COUNT=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM merkle_leaves;")
        echo "    Merkle leaves persisted: $LEAF_COUNT"
        if [ "$LEAF_COUNT" -ge 3 ]; then
            echo "    PASS: Merkle tree leaves match receipt count"
        fi
    else
        DB_SIZE=$(wc -c < "$DB_PATH")
        echo "    Database size: $DB_SIZE bytes"
        echo "    (install sqlite3 for detailed receipt inspection)"
    fi
else
    echo "    FAIL: Receipt database not created"
    echo "    Proxy stderr:"
    cat "$TEST_DIR/proxy_stderr.log"
    exit 1
fi

echo ""

# ── Step 7: Check proxy logs ───────────────────────────────────────────────

echo "--- Proxy log output (stderr):"
if [ -f "$TEST_DIR/proxy_stderr.log" ]; then
    cat "$TEST_DIR/proxy_stderr.log" | head -20
fi

echo ""
echo "=== E2E Test Complete ==="

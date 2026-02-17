#!/usr/bin/env bash
#
# End-to-end test for the HTTP proxy transport.
#
# What this does:
#   1. Builds all binaries
#   2. Starts the mock MCP server in HTTP mode
#   3. Starts the manifest HTTP proxy pointing at the mock server
#   4. Sends JSON-RPC requests via curl
#   5. Checks that receipts were generated
#   6. Tests bearer token authentication
#
# Usage:
#   ./tests/e2e_http.sh
#
set -euo pipefail

# ── Setup ───────────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
TEST_DIR=$(mktemp -d)
DB_PATH="$TEST_DIR/receipts.db"
KEY_PATH="$TEST_DIR/signing.key"
MOCK_PORT=19090
PROXY_PORT=18080

cleanup() {
    # Kill background processes
    kill "$MOCK_PID" 2>/dev/null || true
    kill "$PROXY_PID" 2>/dev/null || true
    rm -rf "$TEST_DIR"
}
trap cleanup EXIT

echo "=== Manifest HTTP E2E Test ==="
echo "Working directory: $TEST_DIR"
echo ""

# ── Build ───────────────────────────────────────────────────────────────────

echo "--- Building binaries..."
cd "$PROJECT_DIR"
cargo build --quiet 2>&1
MANIFEST="$PROJECT_DIR/target/debug/manifest"
MOCK_SERVER="$PROJECT_DIR/target/debug/mock-mcp-server"
echo ""

# ── Step 1: Generate signing key ────────────────────────────────────────────

echo "--- Step 1: Generate signing key"
"$MANIFEST" init --key "$KEY_PATH"
echo ""

# ── Step 2: Start mock MCP server in HTTP mode ─────────────────────────────

echo "--- Step 2: Start mock MCP server (HTTP on port $MOCK_PORT)"
"$MOCK_SERVER" --http "$MOCK_PORT" &
MOCK_PID=$!
sleep 0.5

# Verify mock server is running
if curl -s -o /dev/null -w "%{http_code}" \
    -X POST "http://127.0.0.1:$MOCK_PORT/mcp" \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"clientInfo":{"name":"test","version":"1.0"}}}' \
    | grep -q "200"; then
    echo "    PASS: Mock HTTP server is running"
else
    echo "    FAIL: Mock HTTP server not responding"
    exit 1
fi
echo ""

# ── Step 3: Start manifest HTTP proxy ───────────────────────────────────────

echo "--- Step 3: Start manifest HTTP proxy (port $PROXY_PORT)"
"$MANIFEST" proxy-http \
    --upstream "http://127.0.0.1:$MOCK_PORT/mcp" \
    --port "$PROXY_PORT" \
    --key "$KEY_PATH" \
    --db "$DB_PATH" \
    2>"$TEST_DIR/proxy_stderr.log" &
PROXY_PID=$!
sleep 0.5

# Verify proxy is running
if curl -s -o /dev/null -w "%{http_code}" \
    -X POST "http://127.0.0.1:$PROXY_PORT/mcp" \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"clientInfo":{"name":"http-agent","version":"1.0"}}}' \
    | grep -q "200"; then
    echo "    PASS: HTTP proxy is running"
else
    echo "    FAIL: HTTP proxy not responding"
    cat "$TEST_DIR/proxy_stderr.log"
    exit 1
fi
echo ""

# ── Step 4: Send tool calls via HTTP ────────────────────────────────────────

echo "--- Step 4: Send tool calls via HTTP"

# Initialize
INIT_RESP=$(curl -s -X POST "http://127.0.0.1:$PROXY_PORT/mcp" \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"clientInfo":{"name":"http-test-agent","version":"2.0"},"protocolVersion":"2024-11-05"}}')

if echo "$INIT_RESP" | grep -q "mock-mcp-server"; then
    echo "    PASS: Initialize response forwarded"
else
    echo "    FAIL: Initialize response not forwarded"
    echo "    Got: $INIT_RESP"
fi

# Send notification (should get 202 from upstream, proxy forwards)
curl -s -o /dev/null -X POST "http://127.0.0.1:$PROXY_PORT/mcp" \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"notifications/initialized"}'

# Tool call: echo
ECHO_RESP=$(curl -s -X POST "http://127.0.0.1:$PROXY_PORT/mcp" \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{"message":"hello http"}}}')

if echo "$ECHO_RESP" | grep -q "hello http"; then
    echo "    PASS: Echo tool call forwarded"
else
    echo "    FAIL: Echo tool call not forwarded"
    echo "    Got: $ECHO_RESP"
fi

# Tool call: add
ADD_RESP=$(curl -s -X POST "http://127.0.0.1:$PROXY_PORT/mcp" \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"add","arguments":{"a":10,"b":32}}}')

if echo "$ADD_RESP" | grep -q "42"; then
    echo "    PASS: Add tool call forwarded (42)"
else
    echo "    FAIL: Add tool call not forwarded"
    echo "    Got: $ADD_RESP"
fi

# Tool call: fail
FAIL_RESP=$(curl -s -X POST "http://127.0.0.1:$PROXY_PORT/mcp" \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"fail","arguments":{}}}')

if echo "$FAIL_RESP" | grep -q "permission denied"; then
    echo "    PASS: Error response forwarded"
else
    echo "    FAIL: Error response not forwarded"
    echo "    Got: $FAIL_RESP"
fi
echo ""

# ── Step 5: Wait for receipts to flush, then check ──────────────────────────

echo "--- Step 5: Check receipts"
sleep 1  # Give receipt worker time to process

if command -v sqlite3 &> /dev/null && [ -f "$DB_PATH" ]; then
    RECEIPT_COUNT=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM receipts;")
    echo "    Receipts generated: $RECEIPT_COUNT"

    if [ "$RECEIPT_COUNT" -ge 3 ]; then
        echo "    PASS: Expected at least 3 receipts (echo, add, fail)"
    else
        echo "    WARN: Expected more receipts, got $RECEIPT_COUNT"
    fi

    # Show receipts
    sqlite3 "$DB_PATH" "SELECT timestamp, tool_name, agent_name FROM receipts ORDER BY timestamp;" \
        | while IFS='|' read -r ts tool agent; do
        echo "    $ts | $tool | $agent"
    done

    # Verify a receipt
    FIRST_HASH=$(sqlite3 "$DB_PATH" "SELECT content_hash FROM receipts LIMIT 1;")
    PUB_KEY="$KEY_PATH.pub"
    if [ -f "$PUB_KEY" ] && [ -n "$FIRST_HASH" ]; then
        echo ""
        echo "--- Step 6: Cryptographic verification"
        VERIFY_OUTPUT=$("$MANIFEST" verify "$FIRST_HASH" --public-key "$PUB_KEY" --db "$DB_PATH" 2>&1)
        echo "$VERIFY_OUTPUT"

        if echo "$VERIFY_OUTPUT" | grep -q "verified successfully"; then
            echo "    PASS: Receipt cryptographic verification"
        else
            echo "    FAIL: Receipt verification failed"
        fi
    fi
else
    echo "    WARN: sqlite3 not available or database not created"
fi

# ── Step 7: Kill proxy and test auth ────────────────────────────────────────

echo ""
echo "--- Step 7: Test bearer token authentication"
kill "$PROXY_PID" 2>/dev/null || true
sleep 0.5

AUTH_DB="$TEST_DIR/auth_receipts.db"
TOKEN="test-secret-token-12345"

"$MANIFEST" proxy-http \
    --upstream "http://127.0.0.1:$MOCK_PORT/mcp" \
    --port "$PROXY_PORT" \
    --key "$KEY_PATH" \
    --db "$AUTH_DB" \
    --token "$TOKEN" \
    2>"$TEST_DIR/auth_stderr.log" &
PROXY_PID=$!
sleep 0.5

# Request without token should fail
NO_AUTH_STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "http://127.0.0.1:$PROXY_PORT/mcp" \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}')

if [ "$NO_AUTH_STATUS" = "401" ]; then
    echo "    PASS: Unauthenticated request rejected (401)"
else
    echo "    FAIL: Expected 401, got $NO_AUTH_STATUS"
fi

# Request with wrong token should fail
BAD_AUTH_STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "http://127.0.0.1:$PROXY_PORT/mcp" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer wrong-token" \
    -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}')

if [ "$BAD_AUTH_STATUS" = "401" ]; then
    echo "    PASS: Wrong token rejected (401)"
else
    echo "    FAIL: Expected 401, got $BAD_AUTH_STATUS"
fi

# Request with correct token should succeed
AUTH_RESP=$(curl -s -X POST "http://127.0.0.1:$PROXY_PORT/mcp" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"clientInfo":{"name":"auth-agent","version":"1.0"}}}')

if echo "$AUTH_RESP" | grep -q "mock-mcp-server"; then
    echo "    PASS: Authenticated request forwarded"
else
    echo "    FAIL: Authenticated request not forwarded"
    echo "    Got: $AUTH_RESP"
fi

echo ""
echo "=== HTTP E2E Test Complete ==="

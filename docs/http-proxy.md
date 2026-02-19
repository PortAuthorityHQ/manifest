# HTTP Proxy

For remote MCP servers using the Streamable HTTP transport, use `proxy-http` instead of `proxy`.

## Usage

```bash
# Basic — proxy a remote MCP server
manifest proxy-http --upstream http://localhost:9090/mcp --port 8080

# With policy and identity
manifest proxy-http --upstream http://mcp.example.com/mcp --port 8080 \
    --policy policy.yaml --identity identity.yaml

# With bearer token authentication
manifest proxy-http --upstream http://localhost:9090/mcp --port 8080 \
    --token my-secret-token

# With rate limiting (requests per second)
manifest proxy-http --upstream http://localhost:9090/mcp --port 8080 \
    --rate-limit 100
```

Point your agent at `http://localhost:8080/mcp` instead of the upstream server.

## Options

| Flag | Description |
|------|-------------|
| `--upstream URL` | Upstream MCP server URL (required) |
| `--port 8080` | Port to listen on (default: 8080) |
| `--policy PATH` | Policy config file |
| `--identity PATH` | Identity config file |
| `--key PATH` | Signing key path |
| `--db PATH` | SQLite database path |
| `--token TOKEN` | Bearer token for auth (rejects unauthenticated requests) |
| `--rate-limit N` | Max requests per second (excess gets 429) |
| `--webhook URL` | POST violation alerts to this URL |
| `--sink URL` | Stream receipts to SIEM endpoint |
| `--sink-token TOKEN` | Bearer token for sink auth |
| `--sink-format FORMAT` | `json` (default) or `splunk-hec` |

## Features

- Handles POST, GET (SSE), and DELETE methods transparently
- Each concurrent client gets isolated session state via `Mcp-Session-Id` header
- `/health` endpoint returns `{"status":"ok"}` for load balancer probes
- When `--token` is set, all requests must include `Authorization: Bearer <token>`

## TLS

The proxy serves plaintext on `127.0.0.1`. For network deployments, put a reverse proxy in front:

**Caddy** (automatic HTTPS):
```
mcp.example.com {
    reverse_proxy localhost:8080
}
```

**nginx**:
```nginx
server {
    listen 443 ssl;
    server_name mcp.example.com;
    ssl_certificate     /etc/ssl/certs/mcp.pem;
    ssl_certificate_key /etc/ssl/private/mcp.key;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_buffering off;  # Required for SSE
    }
}
```

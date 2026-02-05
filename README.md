# openapi-to-mcp

[![PyPI](https://img.shields.io/pypi/v/openapi-to-mcp)](https://pypi.org/project/openapi-to-mcp/)
[![Python](https://img.shields.io/pypi/pyversions/openapi-to-mcp)](https://pypi.org/project/openapi-to-mcp/)
[![CI](https://github.com/afstkla/openapi-to-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/afstkla/openapi-to-mcp/actions)
[![codecov](https://codecov.io/gh/afstkla/openapi-to-mcp/graph/badge.svg)](https://codecov.io/gh/afstkla/openapi-to-mcp)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

Convert any OpenAPI/Swagger spec into an MCP server, instantly exposing your REST API as tools for Claude.

```bash
uvx openapi-to-mcp serve ./spec.json --base-url https://api.example.com -a bearer --bearer-token $TOKEN
```

## Installation

**No installation needed** — just use `uvx`:

```bash
uvx openapi-to-mcp --help
```

Or install globally:

```bash
uv tool install openapi-to-mcp
```

## Quick Start

```bash
# See what tools will be generated
uvx openapi-to-mcp list-endpoints ./openapi.json

# Run MCP server
uvx openapi-to-mcp serve ./openapi.json --base-url https://api.example.com
```

## Authentication

Supports all OpenAPI/Swagger security schemes:

```bash
# HTTP Basic
uvx openapi-to-mcp serve spec.json -b https://api.example.com \
  -a basic -u user -p pass

# Bearer Token
uvx openapi-to-mcp serve spec.json -b https://api.example.com \
  -a bearer --bearer-token $TOKEN

# API Key (header, query, or cookie)
uvx openapi-to-mcp serve spec.json -b https://api.example.com \
  -a api-key-header --api-key $KEY --api-key-name X-API-Key

# OAuth2 Password (cookie-based login)
uvx openapi-to-mcp serve spec.json -b https://api.example.com \
  -a oauth2-password -u user -p pass --login-url /auth/login

# OAuth2 Password (token-based)
uvx openapi-to-mcp serve spec.json -b https://api.example.com \
  -a oauth2-password -u user -p pass --token-url /oauth/token

# OAuth2 Client Credentials
uvx openapi-to-mcp serve spec.json -b https://api.example.com \
  -a oauth2-client --client-id $ID --client-secret $SECRET --token-url /oauth/token
```

## Adding to Claude Code

Add to `~/.claude.json` or `.mcp.json`:

```json
{
  "mcpServers": {
    "my-api": {
      "command": "uvx",
      "args": [
        "openapi-to-mcp",
        "serve",
        "/path/to/spec.json",
        "--base-url", "https://api.example.com",
        "--auth-type", "bearer",
        "--bearer-token", "your-token"
      ]
    }
  }
}
```

Or generate a config:

```bash
uvx openapi-to-mcp generate-config ./spec.json \
  --base-url https://api.example.com \
  --server-name my-api \
  -a bearer --bearer-token $TOKEN
```

## Filtering Endpoints

Large APIs can expose hundreds of tools. Use tag filters:

```bash
# Only include specific tags
uvx openapi-to-mcp serve spec.json -b https://api.example.com \
  --include-tag Users --include-tag Orders

# Exclude tags
uvx openapi-to-mcp serve spec.json -b https://api.example.com \
  --exclude-tag Admin --exclude-tag Internal
```

## Commands

| Command | Description |
|---------|-------------|
| `serve` | Run MCP server for an OpenAPI spec |
| `list-endpoints` | Preview endpoints and generated tool names |
| `inspect` | Show full tool definitions as JSON |
| `generate-config` | Generate Claude Code MCP config |

## Tool Naming

Endpoints are converted to clean tool names:

| Method | Path | Tool Name |
|--------|------|-----------|
| GET | /users | `list_users` |
| POST | /users | `create_user` |
| GET | /users/{id} | `get_user` |
| PATCH | /users/{id} | `update_user` |
| DELETE | /users/{id} | `delete_user` |

## How It Works

1. **Parse** — Reads OpenAPI 3.x spec (JSON or YAML, file or URL)
2. **Generate** — Converts each endpoint to an MCP tool with proper input schema
3. **Authenticate** — Handles login flows, stores tokens/cookies
4. **Serve** — Runs stdio MCP server, executes HTTP calls on tool invocation

## License

MIT

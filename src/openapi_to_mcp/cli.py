"""CLI for openapi-to-mcp."""

import asyncio
import json
from pathlib import Path

import click

from .auth import AuthConfig, AuthType
from .generator import generate_tool_definitions
from .parser import extract_endpoints, load_spec

AUTH_TYPE_CHOICES = click.Choice(
    [
        "none",
        "basic",
        "bearer",
        "api-key-header",
        "api-key-query",
        "api-key-cookie",
        "oauth2-password",
        "oauth2-client",
    ],
    case_sensitive=False,
)


@click.group()
def main():
    """Convert OpenAPI/Swagger specs to MCP servers."""
    pass


@main.command()
@click.argument("spec_source")
@click.option("--base-url", "-b", required=True, help="Base URL for the API")
@click.option(
    "--auth-type",
    "-a",
    type=AUTH_TYPE_CHOICES,
    default="none",
    help="Authentication type",
)
@click.option("--username", "-u", help="Username (for basic, oauth2-password)")
@click.option("--password", "-p", help="Password (for basic, oauth2-password)")
@click.option("--bearer-token", help="Bearer token (for bearer auth)")
@click.option("--api-key", help="API key value (for api-key-* auth)")
@click.option("--api-key-name", default="X-API-Key", help="API key header/param/cookie name")
@click.option("--client-id", help="Client ID (for oauth2-client)")
@click.option("--client-secret", help="Client secret (for oauth2-client)")
@click.option("--token-url", help="OAuth2 token endpoint (for oauth2-* with token response)")
@click.option("--login-url", help="Login endpoint that sets cookie (for oauth2-password)")
@click.option("--scope", default="", help="OAuth2 scope")
@click.option("--include-tag", "-t", multiple=True, help="Only include endpoints with these tags")
@click.option("--exclude-tag", "-x", multiple=True, help="Exclude endpoints with these tags")
def serve(
    spec_source: str,
    base_url: str,
    auth_type: str,
    username: str | None,
    password: str | None,
    bearer_token: str | None,
    api_key: str | None,
    api_key_name: str,
    client_id: str | None,
    client_secret: str | None,
    token_url: str | None,
    login_url: str | None,
    scope: str,
    include_tag: tuple[str, ...],
    exclude_tag: tuple[str, ...],
):
    """Run an MCP server for the given OpenAPI spec.

    SPEC_SOURCE can be a file path or URL to the OpenAPI spec.

    \b
    Authentication types (--auth-type):
      none              No authentication
      basic             HTTP Basic (--username, --password)
      bearer            HTTP Bearer token (--bearer-token)
      api-key-header    API key in header (--api-key, --api-key-name)
      api-key-query     API key in query param (--api-key, --api-key-name)
      api-key-cookie    API key in cookie (--api-key, --api-key-name)
      oauth2-password   OAuth2 password flow (--username, --password, --login-url or --token-url)
      oauth2-client     OAuth2 client credentials (--client-id, --client-secret, --token-url)

    \b
    Examples:
      # HTTP Basic auth
      -a basic -u user -p pass

      # Bearer token
      -a bearer --bearer-token TOKEN

      # API key in header
      -a api-key-header --api-key KEY --api-key-name X-API-Key

      # OAuth2 password (cookie login)
      -a oauth2-password -u user -p pass --login-url /auth/login

      # OAuth2 password (token response)
      -a oauth2-password -u user -p pass --token-url /oauth/token

      # OAuth2 client credentials
      -a oauth2-client --client-id ID --client-secret SECRET --token-url /oauth/token
    """
    from .server import run_server

    # Map CLI auth type to enum
    auth_type_map = {
        "none": AuthType.NONE,
        "basic": AuthType.HTTP_BASIC,
        "bearer": AuthType.HTTP_BEARER,
        "api-key-header": AuthType.API_KEY_HEADER,
        "api-key-query": AuthType.API_KEY_QUERY,
        "api-key-cookie": AuthType.API_KEY_COOKIE,
        "oauth2-password": AuthType.OAUTH2_PASSWORD,
        "oauth2-client": AuthType.OAUTH2_CLIENT_CREDENTIALS,
    }

    auth = AuthConfig(
        auth_type=auth_type_map[auth_type],
        username=username,
        password=password,
        bearer_token=bearer_token,
        api_key=api_key,
        api_key_name=api_key_name,
        client_id=client_id,
        client_secret=client_secret,
        token_url=token_url,
        login_url=login_url,
        scope=scope,
    )

    asyncio.run(
        run_server(
            spec_source,
            base_url,
            auth=auth,
            include_tags=set(include_tag) if include_tag else None,
            exclude_tags=set(exclude_tag) if exclude_tag else None,
        )
    )


@main.command()
@click.argument("spec_source")
@click.option("--output", "-o", help="Output file (default: stdout)")
def inspect(spec_source: str, output: str | None):
    """Inspect an OpenAPI spec and show the generated tools."""
    spec = load_spec(spec_source)
    endpoints = extract_endpoints(spec)
    tools = generate_tool_definitions(endpoints)

    display_tools = [{k: v for k, v in t.items() if not k.startswith("_")} for t in tools]

    result = {"tool_count": len(display_tools), "tools": display_tools}

    if output:
        Path(output).write_text(json.dumps(result, indent=2))
        click.echo(f"Wrote {len(display_tools)} tools to {output}")
    else:
        click.echo(json.dumps(result, indent=2))


@main.command()
@click.argument("spec_source")
@click.option("--base-url", "-b", required=True, help="Base URL for the API")
@click.option("--output", "-o", default="mcp_config.json", help="Output config file")
@click.option("--server-name", "-n", default="swagger-api", help="Name for the MCP server")
@click.option("--auth-type", "-a", type=AUTH_TYPE_CHOICES, default="none", help="Auth type")
@click.option("--username", "-u", help="Username")
@click.option("--password", "-p", help="Password")
@click.option("--bearer-token", help="Bearer token")
@click.option("--api-key", help="API key value")
@click.option("--api-key-name", default="X-API-Key", help="API key name")
@click.option("--client-id", help="OAuth2 client ID")
@click.option("--client-secret", help="OAuth2 client secret")
@click.option("--token-url", help="OAuth2 token endpoint")
@click.option("--login-url", help="Login endpoint (cookie-based)")
@click.option("--scope", default="", help="OAuth2 scope")
@click.option("--include-tag", "-t", multiple=True, help="Only include endpoints with these tags")
@click.option("--exclude-tag", "-x", multiple=True, help="Exclude endpoints with these tags")
def generate_config(
    spec_source: str,
    base_url: str,
    output: str,
    server_name: str,
    auth_type: str,
    username: str | None,
    password: str | None,
    bearer_token: str | None,
    api_key: str | None,
    api_key_name: str,
    client_id: str | None,
    client_secret: str | None,
    token_url: str | None,
    login_url: str | None,
    scope: str,
    include_tag: tuple[str, ...],
    exclude_tag: tuple[str, ...],
):
    """Generate Claude Code MCP config for the given spec."""
    args = ["serve", spec_source, "--base-url", base_url]

    if auth_type != "none":
        args.extend(["--auth-type", auth_type])
    if username:
        args.extend(["--username", username])
    if password:
        args.extend(["--password", password])
    if bearer_token:
        args.extend(["--bearer-token", bearer_token])
    if api_key:
        args.extend(["--api-key", api_key])
    if api_key_name != "X-API-Key":
        args.extend(["--api-key-name", api_key_name])
    if client_id:
        args.extend(["--client-id", client_id])
    if client_secret:
        args.extend(["--client-secret", client_secret])
    if token_url:
        args.extend(["--token-url", token_url])
    if login_url:
        args.extend(["--login-url", login_url])
    if scope:
        args.extend(["--scope", scope])
    for tag in include_tag:
        args.extend(["--include-tag", tag])
    for tag in exclude_tag:
        args.extend(["--exclude-tag", tag])

    project_dir = Path(__file__).parent.parent.parent.resolve()

    config = {
        "mcpServers": {
            server_name: {
                "command": "uv",
                "args": ["--directory", str(project_dir), "run", "openapi-to-mcp", *args],
            }
        }
    }

    Path(output).write_text(json.dumps(config, indent=2))
    click.echo(f"Generated MCP config: {output}")
    click.echo("\nAdd to your Claude settings (~/.claude.json or project .mcp.json):")
    click.echo(json.dumps(config, indent=2))


@main.command()
@click.argument("spec_source")
def list_endpoints(spec_source: str):
    """List all endpoints in the OpenAPI spec."""
    spec = load_spec(spec_source)
    endpoints = extract_endpoints(spec)

    click.echo(f"Found {len(endpoints)} endpoints:\n")

    by_tag: dict[str, list] = {}
    for ep in endpoints:
        tag = ep["tags"][0] if ep["tags"] else "default"
        by_tag.setdefault(tag, []).append(ep)

    for tag, eps in sorted(by_tag.items()):
        click.echo(f"[{tag}]")
        for ep in eps:
            click.echo(f"  {ep['method']:6} {ep['path']}")
            click.echo(f"         -> {ep['tool_name']}")
        click.echo()


if __name__ == "__main__":
    main()

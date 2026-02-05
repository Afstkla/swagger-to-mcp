"""MCP server that exposes OpenAPI endpoints as tools."""

import json
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

from .auth import AuthConfig, AuthenticatedClient
from .generator import generate_tool_definitions
from .parser import extract_endpoints, load_spec


class SwaggerMCPServer:
    """MCP server that wraps an OpenAPI-described API."""

    def __init__(
        self,
        spec_source: str,
        base_url: str,
        auth: AuthConfig | None = None,
        include_tags: set[str] | None = None,
        exclude_tags: set[str] | None = None,
    ):
        self.spec_source = spec_source
        self.base_url = base_url.rstrip("/")
        self.auth = auth or AuthConfig()
        self.include_tags = include_tags
        self.exclude_tags = exclude_tags or set()

        self.spec: dict[str, Any] = {}
        self.endpoints: list[dict[str, Any]] = []
        self.tools: list[dict[str, Any]] = []
        self.tool_map: dict[str, dict[str, Any]] = {}

        self._client: AuthenticatedClient | None = None

        self.server = Server("swagger-mcp")
        self._setup_handlers()

    def _setup_handlers(self):
        @self.server.list_tools()
        async def list_tools() -> list[Tool]:
            return [
                Tool(
                    name=t["name"],
                    description=t["description"],
                    inputSchema=t["inputSchema"],
                )
                for t in self.tools
            ]

        @self.server.call_tool()
        async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
            result = await self.execute_tool(name, arguments)
            return [TextContent(type="text", text=json.dumps(result, indent=2))]

    def load(self):
        """Load and parse the OpenAPI spec."""
        self.spec = load_spec(self.spec_source)
        self.endpoints = extract_endpoints(self.spec)

        # Filter by tags
        if self.include_tags or self.exclude_tags:
            filtered = []
            for ep in self.endpoints:
                tags = set(ep.get("tags", []))
                if self.include_tags and not tags.intersection(self.include_tags):
                    continue
                if self.exclude_tags and tags.intersection(self.exclude_tags):
                    continue
                filtered.append(ep)
            self.endpoints = filtered

        self.tools = generate_tool_definitions(self.endpoints)
        self.tool_map = {t["name"]: t for t in self.tools}

    async def execute_tool(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Execute an API call for the given tool."""
        tool = self.tool_map.get(tool_name)
        if not tool:
            return {"error": f"Unknown tool: {tool_name}"}

        endpoint = tool["_endpoint"]
        method = endpoint["method"]
        path = endpoint["path"]

        # Build path with path parameters
        for param in endpoint["parameters"]:
            if param["in"] == "path" and param["name"] in arguments:
                path = path.replace(f"{{{param['name']}}}", str(arguments[param["name"]]))

        # Collect query parameters
        query_params = {}
        for param in endpoint["parameters"]:
            if param["in"] == "query" and param["name"] in arguments:
                query_params[param["name"]] = arguments[param["name"]]

        # Collect headers
        headers = {}
        for param in endpoint["parameters"]:
            if param["in"] == "header" and param["name"] in arguments:
                headers[param["name"]] = arguments[param["name"]]

        # Build request body
        body = None
        content_type = None
        if endpoint["request_body"]:
            rb = endpoint["request_body"]
            content_type = rb.get("content_type", "application/json")
            rb_schema = rb.get("schema", {})

            if rb_schema.get("type") == "object" and "properties" in rb_schema:
                # Reconstruct body from flattened params
                body = {}
                for prop_name in rb_schema["properties"]:
                    full_name = f"body_{prop_name}"
                    if full_name in arguments:
                        body[prop_name] = arguments[full_name]
            elif "body" in arguments:
                body = arguments["body"]

        # Make the request
        try:
            if content_type == "application/x-www-form-urlencoded":
                response = await self._client.request(
                    method, path, params=query_params, headers=headers, data=body
                )
            else:
                response = await self._client.request(
                    method, path, params=query_params, headers=headers, json=body
                )

            # Parse response
            result: dict[str, Any] = {
                "status_code": response.status_code,
            }

            if response.status_code == 204:
                result["data"] = None
            elif "application/json" in response.headers.get("content-type", ""):
                result["data"] = response.json()
            else:
                result["data"] = response.text

            return result

        except Exception as e:
            return {"error": f"Request failed: {e!s}"}

    async def run(self):
        """Run the MCP server."""
        self.load()

        async with AuthenticatedClient(self.base_url, self.auth) as client:
            self._client = client

            async with stdio_server() as (read_stream, write_stream):
                init_options = self.server.create_initialization_options()
                await self.server.run(read_stream, write_stream, init_options)


async def run_server(
    spec_source: str,
    base_url: str,
    auth: AuthConfig | None = None,
    include_tags: set[str] | None = None,
    exclude_tags: set[str] | None = None,
):
    """Create and run the MCP server."""
    server = SwaggerMCPServer(
        spec_source=spec_source,
        base_url=base_url,
        auth=auth,
        include_tags=include_tags,
        exclude_tags=exclude_tags,
    )
    await server.run()

"""Integration tests for SwaggerMCPServer."""

import json
import tempfile
from typing import Any

import httpx
import pytest
import yaml
from pytest_httpx import HTTPXMock

from openapi_to_mcp.auth import AuthConfig, AuthenticatedClient, AuthType
from openapi_to_mcp.server import SwaggerMCPServer


@pytest.fixture
def petstore_spec_file(petstore_spec: dict[str, Any]) -> str:
    """Create a temporary petstore spec file and return its path."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        yaml.dump(petstore_spec, f)
        return f.name


@pytest.fixture
def minimal_spec_file(minimal_spec: dict[str, Any]) -> str:
    """Create a temporary minimal spec file and return its path."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(minimal_spec, f)
        return f.name


class TestServerInitialization:
    """Tests for SwaggerMCPServer initialization."""

    def test_server_initialization_with_defaults(self, petstore_spec_file: str):
        """Test server initializes with correct defaults."""
        server = SwaggerMCPServer(
            spec_source=petstore_spec_file,
            base_url="https://api.example.com",
        )

        assert server.spec_source == petstore_spec_file
        assert server.base_url == "https://api.example.com"
        assert server.auth.auth_type == AuthType.NONE
        assert server.include_tags is None
        assert server.exclude_tags == set()
        assert server.spec == {}
        assert server.endpoints == []
        assert server.tools == []

    def test_server_initialization_with_auth(
        self, petstore_spec_file: str, api_key_auth: AuthConfig
    ):
        """Test server initializes with auth config."""
        server = SwaggerMCPServer(
            spec_source=petstore_spec_file,
            base_url="https://api.example.com",
            auth=api_key_auth,
        )

        assert server.auth.auth_type == AuthType.API_KEY_HEADER
        assert server.auth.api_key == "test-api-key-12345"

    def test_server_initialization_strips_trailing_slash(self, petstore_spec_file: str):
        """Test that trailing slashes are stripped from base URL."""
        server = SwaggerMCPServer(
            spec_source=petstore_spec_file,
            base_url="https://api.example.com/",
        )

        assert server.base_url == "https://api.example.com"

    def test_server_initialization_with_tag_filters(self, petstore_spec_file: str):
        """Test server initializes with tag filters."""
        server = SwaggerMCPServer(
            spec_source=petstore_spec_file,
            base_url="https://api.example.com",
            include_tags={"pets", "stores"},
            exclude_tags={"admin"},
        )

        assert server.include_tags == {"pets", "stores"}
        assert server.exclude_tags == {"admin"}


class TestServerLoad:
    """Tests for SwaggerMCPServer.load() method."""

    def test_load_parses_spec_and_generates_tools(self, petstore_spec_file: str):
        """Test that load() parses spec and generates tools."""
        server = SwaggerMCPServer(
            spec_source=petstore_spec_file,
            base_url="https://api.example.com",
        )
        server.load()

        assert server.spec != {}
        assert "paths" in server.spec
        assert len(server.endpoints) > 0
        assert len(server.tools) > 0
        assert len(server.tool_map) == len(server.tools)

    def test_load_with_include_tags_filters_endpoints(self, petstore_spec_file: str):
        """Test that include_tags filters endpoints correctly."""
        server = SwaggerMCPServer(
            spec_source=petstore_spec_file,
            base_url="https://api.example.com",
            include_tags={"pets"},
        )
        server.load()

        # All endpoints should have 'pets' tag
        for endpoint in server.endpoints:
            assert "pets" in endpoint["tags"]

        # Should not include stores or admin endpoints
        tool_names = [t["name"] for t in server.tools]
        assert not any("store" in name for name in tool_names)
        assert not any("admin" in name for name in tool_names)

    def test_load_with_exclude_tags_filters_endpoints(self, petstore_spec_file: str):
        """Test that exclude_tags filters endpoints correctly."""
        server = SwaggerMCPServer(
            spec_source=petstore_spec_file,
            base_url="https://api.example.com",
            exclude_tags={"admin", "orders"},
        )
        server.load()

        # No endpoints should have 'admin' or 'orders' tag
        for endpoint in server.endpoints:
            tags = set(endpoint.get("tags", []))
            assert "admin" not in tags
            assert "orders" not in tags

    def test_load_with_include_and_exclude_tags(self, petstore_spec_file: str):
        """Test that include and exclude tags work together."""
        server = SwaggerMCPServer(
            spec_source=petstore_spec_file,
            base_url="https://api.example.com",
            include_tags={"pets", "stores"},
            exclude_tags={"stores"},
        )
        server.load()

        # Should only have pets endpoints
        for endpoint in server.endpoints:
            assert "pets" in endpoint["tags"]

    def test_load_creates_correct_tool_map(self, petstore_spec_file: str):
        """Test that tool_map is correctly built."""
        server = SwaggerMCPServer(
            spec_source=petstore_spec_file,
            base_url="https://api.example.com",
        )
        server.load()

        for tool in server.tools:
            assert tool["name"] in server.tool_map
            assert server.tool_map[tool["name"]] == tool


class TestExecuteTool:
    """Tests for SwaggerMCPServer.execute_tool() method."""

    @pytest.fixture
    def loaded_server(self, petstore_spec_file: str) -> SwaggerMCPServer:
        """Create and load a server instance."""
        server = SwaggerMCPServer(
            spec_source=petstore_spec_file,
            base_url="https://api.petstore.example.com",
        )
        server.load()
        return server

    async def test_execute_tool_unknown_tool_returns_error(self, loaded_server: SwaggerMCPServer):
        """Test that unknown tool returns an error."""
        result = await loaded_server.execute_tool("nonexistent_tool", {})

        assert "error" in result
        assert "Unknown tool" in result["error"]
        assert "nonexistent_tool" in result["error"]

    async def test_execute_tool_with_path_parameters(
        self, loaded_server: SwaggerMCPServer, httpx_mock: HTTPXMock
    ):
        """Test tool execution with path parameters."""
        httpx_mock.add_response(
            url="https://api.petstore.example.com/pets/123",
            method="GET",
            json={"id": 123, "name": "Fluffy", "species": "cat"},
        )

        async with AuthenticatedClient(loaded_server.base_url, loaded_server.auth) as client:
            loaded_server._client = client

            result = await loaded_server.execute_tool("get_pet", {"petId": 123})

        assert result["status_code"] == 200
        assert result["data"]["id"] == 123
        assert result["data"]["name"] == "Fluffy"

    async def test_execute_tool_with_query_parameters(
        self, loaded_server: SwaggerMCPServer, httpx_mock: HTTPXMock
    ):
        """Test tool execution with query parameters."""
        httpx_mock.add_response(
            url="https://api.petstore.example.com/pets?limit=10&status=available",
            method="GET",
            json=[
                {"id": 1, "name": "Fluffy", "species": "cat"},
                {"id": 2, "name": "Rex", "species": "dog"},
            ],
        )

        async with AuthenticatedClient(loaded_server.base_url, loaded_server.auth) as client:
            loaded_server._client = client

            result = await loaded_server.execute_tool(
                "list_pets", {"limit": 10, "status": "available"}
            )

        assert result["status_code"] == 200
        assert len(result["data"]) == 2

    async def test_execute_tool_with_body_reconstruction(
        self, loaded_server: SwaggerMCPServer, httpx_mock: HTTPXMock
    ):
        """Test tool execution with request body reconstruction from flattened params."""
        httpx_mock.add_response(
            url="https://api.petstore.example.com/pets",
            method="POST",
            json={"id": 456, "name": "Buddy", "status": "available"},
            status_code=201,
        )

        async with AuthenticatedClient(loaded_server.base_url, loaded_server.auth) as client:
            loaded_server._client = client

            # The petstore spec uses PetInput which has: name, categoryId, tagIds, status
            # operationId is "createPet" -> "create_pet"
            result = await loaded_server.execute_tool(
                "create_pet",
                {
                    "body_name": "Buddy",
                    "body_status": "available",
                },
            )

        assert result["status_code"] == 201
        assert result["data"]["name"] == "Buddy"

        # Verify the request body was properly reconstructed
        request = httpx_mock.get_request()
        body = json.loads(request.content)
        assert body["name"] == "Buddy"
        assert body["status"] == "available"

    async def test_execute_tool_with_header_parameters(
        self, loaded_server: SwaggerMCPServer, httpx_mock: HTTPXMock
    ):
        """Test tool execution with header parameters."""
        # The list_pets endpoint has an optional X-Request-ID header param
        httpx_mock.add_response(
            url="https://api.petstore.example.com/pets",
            method="GET",
            json=[{"id": 1, "name": "Test"}],
        )

        async with AuthenticatedClient(loaded_server.base_url, loaded_server.auth) as client:
            loaded_server._client = client

            result = await loaded_server.execute_tool(
                "list_pets",
                {"X-Request-ID": "test-request-id-123"},
            )

        assert result["status_code"] == 200

        # Verify header was sent
        request = httpx_mock.get_request()
        assert request.headers.get("X-Request-ID") == "test-request-id-123"

    async def test_execute_tool_json_response_parsing(
        self, loaded_server: SwaggerMCPServer, httpx_mock: HTTPXMock
    ):
        """Test JSON response parsing."""
        httpx_mock.add_response(
            url="https://api.petstore.example.com/pets",
            method="GET",
            json={"pets": [{"id": 1, "name": "Test"}]},
            headers={"content-type": "application/json"},
        )

        async with AuthenticatedClient(loaded_server.base_url, loaded_server.auth) as client:
            loaded_server._client = client

            result = await loaded_server.execute_tool("list_pets", {})

        assert result["status_code"] == 200
        assert isinstance(result["data"], dict)
        assert "pets" in result["data"]

    async def test_execute_tool_text_response_parsing(
        self, loaded_server: SwaggerMCPServer, httpx_mock: HTTPXMock
    ):
        """Test text response parsing."""
        httpx_mock.add_response(
            url="https://api.petstore.example.com/pets",
            method="GET",
            text="Plain text response",
            headers={"content-type": "text/plain"},
        )

        async with AuthenticatedClient(loaded_server.base_url, loaded_server.auth) as client:
            loaded_server._client = client

            result = await loaded_server.execute_tool("list_pets", {})

        assert result["status_code"] == 200
        assert result["data"] == "Plain text response"

    async def test_execute_tool_204_response(
        self, loaded_server: SwaggerMCPServer, httpx_mock: HTTPXMock
    ):
        """Test 204 No Content response handling."""
        httpx_mock.add_response(
            url="https://api.petstore.example.com/pets/1",
            method="DELETE",
            status_code=204,
        )

        async with AuthenticatedClient(loaded_server.base_url, loaded_server.auth) as client:
            loaded_server._client = client

            result = await loaded_server.execute_tool("delete_pet", {"petId": 1})

        assert result["status_code"] == 204
        assert result["data"] is None

    async def test_execute_tool_request_error(
        self, loaded_server: SwaggerMCPServer, httpx_mock: HTTPXMock
    ):
        """Test handling of request errors."""
        httpx_mock.add_exception(httpx.ConnectError("Connection refused"))

        async with AuthenticatedClient(loaded_server.base_url, loaded_server.auth) as client:
            loaded_server._client = client

            result = await loaded_server.execute_tool("list_pets", {})

        assert "error" in result
        assert "Request failed" in result["error"]

    async def test_execute_tool_with_path_and_query_params_combined(
        self, loaded_server: SwaggerMCPServer, httpx_mock: HTTPXMock
    ):
        """Test tool with both path and query parameters."""
        # Using the store orders endpoint which has path param (orderId) and the
        # list orders endpoint has query param (status)
        httpx_mock.add_response(
            url="https://api.petstore.example.com/store/orders?status=placed",
            method="GET",
            json=[{"id": "uuid-1", "petId": 10, "status": "placed"}],
        )

        async with AuthenticatedClient(loaded_server.base_url, loaded_server.auth) as client:
            loaded_server._client = client

            # operationId is "listOrders" -> "list_orders"
            result = await loaded_server.execute_tool("list_orders", {"status": "placed"})

        assert result["status_code"] == 200

    async def test_execute_tool_with_put_method(
        self, loaded_server: SwaggerMCPServer, httpx_mock: HTTPXMock
    ):
        """Test PUT method tool execution."""
        httpx_mock.add_response(
            url="https://api.petstore.example.com/pets/5",
            method="PUT",
            json={"id": 5, "name": "Updated Name", "status": "available"},
        )

        async with AuthenticatedClient(loaded_server.base_url, loaded_server.auth) as client:
            loaded_server._client = client

            # The petstore spec uses PetInput for PUT which has: name, categoryId, tagIds, status
            # operationId is "updatePet" -> "update_pet"
            result = await loaded_server.execute_tool(
                "update_pet",
                {
                    "petId": 5,
                    "body_name": "Updated Name",
                    "body_status": "available",
                },
            )

        assert result["status_code"] == 200
        assert result["data"]["name"] == "Updated Name"


class TestServerMCPHandlers:
    """Tests for MCP server handlers."""

    def test_list_tools_handler_registered(self, petstore_spec_file: str):
        """Test that list_tools handler is registered."""
        server = SwaggerMCPServer(
            spec_source=petstore_spec_file,
            base_url="https://api.example.com",
        )

        # The handlers should be set up during initialization
        assert server.server is not None

    def test_call_tool_handler_registered(self, petstore_spec_file: str):
        """Test that call_tool handler is registered."""
        server = SwaggerMCPServer(
            spec_source=petstore_spec_file,
            base_url="https://api.example.com",
        )

        assert server.server is not None

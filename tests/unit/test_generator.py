"""Unit tests for the generator module."""

import pytest

from openapi_to_mcp.generator import (
    build_tool_input_schema,
    generate_tool_definitions,
    openapi_type_to_json_schema,
)


class TestOpenapiTypeToJsonSchema:
    """Tests for openapi_type_to_json_schema function."""

    @pytest.mark.parametrize(
        "openapi_schema,expected_type",
        [
            ({"type": "string"}, "string"),
            ({"type": "integer"}, "integer"),
            ({"type": "number"}, "number"),
            ({"type": "boolean"}, "boolean"),
        ],
        ids=["string", "integer", "number", "boolean"],
    )
    def test_primitive_types(self, openapi_schema, expected_type):
        """Test conversion of primitive OpenAPI types to JSON Schema."""
        result = openapi_type_to_json_schema(openapi_schema)
        assert result["type"] == expected_type

    def test_array_type_with_items(self):
        """Test conversion of array type with items specification."""
        openapi_schema = {
            "type": "array",
            "items": {"type": "string"},
        }
        result = openapi_type_to_json_schema(openapi_schema)
        assert result == {
            "type": "array",
            "items": {"type": "string"},
        }

    def test_array_type_with_complex_items(self):
        """Test conversion of array type with object items."""
        openapi_schema = {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "id": {"type": "integer"},
                    "name": {"type": "string"},
                },
            },
        }
        result = openapi_type_to_json_schema(openapi_schema)
        assert result["type"] == "array"
        assert result["items"]["type"] == "object"
        assert "id" in result["items"]["properties"]
        assert result["items"]["properties"]["id"]["type"] == "integer"

    def test_object_type_with_properties(self):
        """Test conversion of object type with properties."""
        openapi_schema = {
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "age": {"type": "integer"},
            },
            "required": ["name"],
        }
        result = openapi_type_to_json_schema(openapi_schema)
        assert result["type"] == "object"
        assert "name" in result["properties"]
        assert result["properties"]["name"]["type"] == "string"
        assert result["properties"]["age"]["type"] == "integer"
        assert result["required"] == ["name"]

    def test_enum_values(self):
        """Test that enum values are preserved in conversion."""
        openapi_schema = {
            "type": "string",
            "enum": ["active", "inactive", "pending"],
        }
        result = openapi_type_to_json_schema(openapi_schema)
        assert result["type"] == "string"
        assert result["enum"] == ["active", "inactive", "pending"]

    def test_default_values(self):
        """Test that default values are preserved in conversion."""
        openapi_schema = {
            "type": "integer",
            "default": 10,
        }
        result = openapi_type_to_json_schema(openapi_schema)
        assert result["type"] == "integer"
        assert result["default"] == 10

    def test_format_datetime(self):
        """Test that date-time format adds description suffix."""
        openapi_schema = {
            "type": "string",
            "format": "date-time",
        }
        result = openapi_type_to_json_schema(openapi_schema)
        assert result["type"] == "string"
        assert "(ISO 8601 datetime)" in result["description"]

    def test_format_datetime_with_existing_description(self):
        """Test that date-time format appends to existing description."""
        openapi_schema = {
            "type": "string",
            "format": "date-time",
            "description": "Creation date",
        }
        result = openapi_type_to_json_schema(openapi_schema)
        assert result["description"] == "Creation date (ISO 8601 datetime)"

    def test_format_uuid(self):
        """Test that uuid format adds description suffix."""
        openapi_schema = {
            "type": "string",
            "format": "uuid",
        }
        result = openapi_type_to_json_schema(openapi_schema)
        assert result["type"] == "string"
        assert "(UUID)" in result["description"]

    def test_format_uuid_with_existing_description(self):
        """Test that uuid format appends to existing description."""
        openapi_schema = {
            "type": "string",
            "format": "uuid",
            "description": "User identifier",
        }
        result = openapi_type_to_json_schema(openapi_schema)
        assert result["description"] == "User identifier (UUID)"

    def test_empty_schema_returns_object_type(self):
        """Test that empty schema returns object type."""
        result = openapi_type_to_json_schema({})
        assert result == {"type": "object"}

    def test_none_schema_returns_object_type(self):
        """Test that None-ish schema returns object type."""
        result = openapi_type_to_json_schema(None)
        assert result == {"type": "object"}

    def test_nested_objects(self):
        """Test conversion of deeply nested object structures."""
        openapi_schema = {
            "type": "object",
            "properties": {
                "user": {
                    "type": "object",
                    "properties": {
                        "profile": {
                            "type": "object",
                            "properties": {
                                "avatar_url": {"type": "string"},
                            },
                        },
                    },
                },
            },
        }
        result = openapi_type_to_json_schema(openapi_schema)
        assert result["type"] == "object"
        assert result["properties"]["user"]["type"] == "object"
        assert result["properties"]["user"]["properties"]["profile"]["type"] == "object"
        assert (
            result["properties"]["user"]["properties"]["profile"]["properties"]["avatar_url"][
                "type"
            ]
            == "string"
        )

    def test_description_preservation(self):
        """Test that descriptions are preserved across all schema types."""
        # Primitive type
        primitive_result = openapi_type_to_json_schema(
            {"type": "string", "description": "A name field"}
        )
        assert primitive_result["description"] == "A name field"

        # Object type
        object_result = openapi_type_to_json_schema(
            {"type": "object", "properties": {}, "description": "User object"}
        )
        assert object_result["description"] == "User object"

        # Array type
        array_result = openapi_type_to_json_schema(
            {"type": "array", "items": {"type": "string"}, "description": "List of names"}
        )
        assert array_result["description"] == "List of names"


class TestBuildToolInputSchema:
    """Tests for build_tool_input_schema function."""

    def test_path_parameters_marked_required(self):
        """Test that path parameters are marked as required."""
        endpoint = {
            "parameters": [
                {
                    "name": "user_id",
                    "in": "path",
                    "required": True,
                    "schema": {"type": "string"},
                    "description": "The user ID",
                }
            ],
            "request_body": None,
        }
        result = build_tool_input_schema(endpoint)
        assert "user_id" in result["properties"]
        assert "user_id" in result["required"]
        assert "[path]" in result["properties"]["user_id"]["description"]

    def test_query_parameters(self):
        """Test that query parameters are handled correctly without location prefix."""
        endpoint = {
            "parameters": [
                {
                    "name": "limit",
                    "in": "query",
                    "required": False,
                    "schema": {"type": "integer"},
                    "description": "Maximum number of results",
                }
            ],
            "request_body": None,
        }
        result = build_tool_input_schema(endpoint)
        assert "limit" in result["properties"]
        assert result["properties"]["limit"]["type"] == "integer"
        # Query params should not have [query] prefix
        assert result["properties"]["limit"]["description"] == "Maximum number of results"
        assert "required" not in result or "limit" not in result.get("required", [])

    def test_header_parameters_with_prefix(self):
        """Test that header parameters include [header] prefix in description."""
        endpoint = {
            "parameters": [
                {
                    "name": "X-Request-ID",
                    "in": "header",
                    "required": False,
                    "schema": {"type": "string"},
                    "description": "Request tracking ID",
                }
            ],
            "request_body": None,
        }
        result = build_tool_input_schema(endpoint)
        assert "X-Request-ID" in result["properties"]
        assert "[header]" in result["properties"]["X-Request-ID"]["description"]
        assert "Request tracking ID" in result["properties"]["X-Request-ID"]["description"]

    def test_request_body_flattening_with_body_prefix(self):
        """Test that request body properties are flattened with body_ prefix."""
        endpoint = {
            "parameters": [],
            "request_body": {
                "required": True,
                "schema": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "email": {"type": "string"},
                    },
                    "required": ["name"],
                },
            },
        }
        result = build_tool_input_schema(endpoint)
        assert "body_name" in result["properties"]
        assert "body_email" in result["properties"]
        assert result["properties"]["body_name"]["type"] == "string"
        assert result["properties"]["body_email"]["type"] == "string"

    def test_required_body_properties(self):
        """Test that required body properties are marked as required with body_ prefix."""
        endpoint = {
            "parameters": [],
            "request_body": {
                "required": True,
                "schema": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "email": {"type": "string"},
                    },
                    "required": ["name"],
                },
            },
        }
        result = build_tool_input_schema(endpoint)
        assert "body_name" in result["required"]
        assert "body_email" not in result["required"]

    def test_non_object_request_body(self):
        """Test that non-object request body is added as single 'body' parameter."""
        endpoint = {
            "parameters": [],
            "request_body": {
                "required": True,
                "schema": {"type": "string"},
            },
        }
        result = build_tool_input_schema(endpoint)
        assert "body" in result["properties"]
        assert result["properties"]["body"]["type"] == "string"
        assert "body" in result["required"]

    def test_combined_parameters_and_body(self):
        """Test endpoint with both parameters and request body."""
        endpoint = {
            "parameters": [
                {
                    "name": "user_id",
                    "in": "path",
                    "required": True,
                    "schema": {"type": "string"},
                    "description": "User ID",
                },
                {
                    "name": "dry_run",
                    "in": "query",
                    "required": False,
                    "schema": {"type": "boolean"},
                    "description": "Simulate the operation",
                },
            ],
            "request_body": {
                "required": True,
                "schema": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                    },
                    "required": ["name"],
                },
            },
        }
        result = build_tool_input_schema(endpoint)
        # Path parameter
        assert "user_id" in result["properties"]
        assert "user_id" in result["required"]
        # Query parameter
        assert "dry_run" in result["properties"]
        # Body parameter
        assert "body_name" in result["properties"]
        assert "body_name" in result["required"]


class TestGenerateToolDefinitions:
    """Tests for generate_tool_definitions function."""

    def test_complete_tool_generation(self):
        """Test that tools are generated with name, description, and inputSchema."""
        endpoints = [
            {
                "tool_name": "get_user",
                "description": "Retrieve a user by ID",
                "method": "GET",
                "path": "/users/{id}",
                "parameters": [
                    {
                        "name": "id",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "string"},
                        "description": "User ID",
                    }
                ],
                "request_body": None,
            }
        ]
        tools = generate_tool_definitions(endpoints)
        assert len(tools) == 1
        tool = tools[0]
        assert tool["name"] == "get_user"
        assert tool["description"] == "Retrieve a user by ID"
        assert "inputSchema" in tool
        assert tool["inputSchema"]["type"] == "object"
        assert "id" in tool["inputSchema"]["properties"]

    def test_endpoint_metadata_preserved(self):
        """Test that _endpoint metadata is preserved in tool definition."""
        endpoints = [
            {
                "tool_name": "create_user",
                "description": "Create a new user",
                "method": "POST",
                "path": "/users",
                "parameters": [],
                "request_body": {
                    "required": True,
                    "schema": {
                        "type": "object",
                        "properties": {"name": {"type": "string"}},
                    },
                },
            }
        ]
        tools = generate_tool_definitions(endpoints)
        tool = tools[0]
        assert "_endpoint" in tool
        assert tool["_endpoint"]["method"] == "POST"
        assert tool["_endpoint"]["path"] == "/users"
        assert tool["_endpoint"]["parameters"] == []
        assert tool["_endpoint"]["request_body"] is not None

    def test_multiple_endpoints_processed(self):
        """Test that multiple endpoints are correctly processed into tools."""
        endpoints = [
            {
                "tool_name": "list_users",
                "description": "List all users",
                "method": "GET",
                "path": "/users",
                "parameters": [],
                "request_body": None,
            },
            {
                "tool_name": "get_user",
                "description": "Get a specific user",
                "method": "GET",
                "path": "/users/{id}",
                "parameters": [
                    {
                        "name": "id",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "string"},
                    }
                ],
                "request_body": None,
            },
            {
                "tool_name": "delete_user",
                "description": "Delete a user",
                "method": "DELETE",
                "path": "/users/{id}",
                "parameters": [
                    {
                        "name": "id",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "string"},
                    }
                ],
                "request_body": None,
            },
        ]
        tools = generate_tool_definitions(endpoints)
        assert len(tools) == 3
        tool_names = [t["name"] for t in tools]
        assert "list_users" in tool_names
        assert "get_user" in tool_names
        assert "delete_user" in tool_names

    def test_fallback_description_when_missing(self):
        """Test that missing description falls back to method + path."""
        endpoints = [
            {
                "tool_name": "unknown_endpoint",
                "description": None,
                "method": "PATCH",
                "path": "/resources/{id}",
                "parameters": [],
                "request_body": None,
            }
        ]
        tools = generate_tool_definitions(endpoints)
        tool = tools[0]
        assert tool["description"] == "PATCH /resources/{id}"

    def test_empty_description_uses_fallback(self):
        """Test that empty string description also uses fallback."""
        endpoints = [
            {
                "tool_name": "another_endpoint",
                "description": "",
                "method": "PUT",
                "path": "/items/{id}",
                "parameters": [],
                "request_body": None,
            }
        ]
        tools = generate_tool_definitions(endpoints)
        tool = tools[0]
        assert tool["description"] == "PUT /items/{id}"

    def test_empty_endpoints_list(self):
        """Test that empty endpoints list returns empty tools list."""
        tools = generate_tool_definitions([])
        assert tools == []

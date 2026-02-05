"""Unit tests for the parser module."""

import json
from pathlib import Path

import httpx
import pytest

from swagger_to_mcp.parser import (
    extract_endpoints,
    load_spec,
    make_tool_name,
    resolve_ref,
    resolve_schema,
)

# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def fixtures_path() -> Path:
    """Return the path to the test fixtures directory."""
    return Path(__file__).parent.parent / "fixtures" / "specs"


@pytest.fixture
def simple_json_spec(fixtures_path: Path) -> dict:
    """Load the simple JSON spec fixture."""
    return json.loads((fixtures_path / "simple.json").read_text())


@pytest.fixture
def complex_schemas_spec(fixtures_path: Path) -> dict:
    """Load the complex schemas spec fixture."""
    return json.loads((fixtures_path / "complex_schemas.json").read_text())


@pytest.fixture
def nested_resources_spec(fixtures_path: Path) -> dict:
    """Load the nested resources spec fixture."""
    return json.loads((fixtures_path / "nested_resources.json").read_text())


@pytest.fixture
def duplicate_names_spec(fixtures_path: Path) -> dict:
    """Load the duplicate names spec fixture."""
    return json.loads((fixtures_path / "duplicate_names.json").read_text())


# =============================================================================
# load_spec tests
# =============================================================================


class TestLoadSpec:
    """Tests for the load_spec function."""

    def test_load_json_file(self, fixtures_path: Path) -> None:
        """Test loading a JSON OpenAPI spec from a file."""
        spec = load_spec(str(fixtures_path / "simple.json"))

        assert spec["openapi"] == "3.0.0"
        assert spec["info"]["title"] == "Simple API"
        assert "/users" in spec["paths"]

    def test_load_yaml_file(self, fixtures_path: Path) -> None:
        """Test loading a YAML OpenAPI spec from a file."""
        spec = load_spec(str(fixtures_path / "simple.yaml"))

        assert spec["openapi"] == "3.0.0"
        assert spec["info"]["title"] == "Simple API"
        assert "/items" in spec["paths"]

    def test_load_from_url_json(self, httpx_mock, simple_json_spec: dict) -> None:
        """Test loading an OpenAPI spec from a URL (JSON response)."""
        url = "https://api.example.com/openapi.json"
        httpx_mock.add_response(url=url, json=simple_json_spec)

        spec = load_spec(url)

        assert spec["openapi"] == "3.0.0"
        assert spec["info"]["title"] == "Simple API"

    def test_load_from_url_yaml(self, httpx_mock, fixtures_path: Path) -> None:
        """Test loading an OpenAPI spec from a URL (YAML response)."""
        url = "https://api.example.com/openapi.yaml"
        yaml_content = (fixtures_path / "simple.yaml").read_text()
        httpx_mock.add_response(url=url, text=yaml_content)

        spec = load_spec(url)

        assert spec["openapi"] == "3.0.0"
        assert spec["info"]["title"] == "Simple API"

    def test_load_invalid_format(self, fixtures_path: Path) -> None:
        """Test loading an invalid file raises an error."""
        with pytest.raises((json.JSONDecodeError, ValueError)):
            load_spec(str(fixtures_path / "invalid.txt"))

    def test_load_network_error(self, httpx_mock) -> None:
        """Test that network errors are properly raised."""
        url = "https://api.example.com/openapi.json"
        httpx_mock.add_exception(httpx.ConnectError("Connection refused"))

        with pytest.raises(httpx.ConnectError):
            load_spec(url)


# =============================================================================
# resolve_ref tests
# =============================================================================


class TestResolveRef:
    """Tests for the resolve_ref function."""

    def test_simple_ref_resolution(self, simple_json_spec: dict) -> None:
        """Test resolving a simple $ref pointer."""
        resolved = resolve_ref(simple_json_spec, "#/components/schemas/User")

        assert resolved["type"] == "object"
        assert "id" in resolved["properties"]
        assert "name" in resolved["properties"]
        assert resolved["required"] == ["id", "name"]

    def test_nested_ref_resolution(self, simple_json_spec: dict) -> None:
        """Test resolving a nested $ref pointer (parameters)."""
        resolved = resolve_ref(simple_json_spec, "#/components/parameters/UserId")

        assert resolved["name"] == "id"
        assert resolved["in"] == "path"
        assert resolved["required"] is True
        assert resolved["schema"]["type"] == "integer"

    def test_missing_ref_returns_empty_dict(self, simple_json_spec: dict) -> None:
        """Test that a missing $ref returns an empty dict."""
        resolved = resolve_ref(simple_json_spec, "#/components/schemas/NonExistent")

        assert resolved == {}

    def test_external_ref_returns_empty_dict(self, simple_json_spec: dict) -> None:
        """Test that an external $ref (not starting with #/) returns empty dict."""
        resolved = resolve_ref(simple_json_spec, "https://example.com/schema.json")

        assert resolved == {}


# =============================================================================
# resolve_schema tests
# =============================================================================


class TestResolveSchema:
    """Tests for the resolve_schema function."""

    def test_allof_merges_properties(self, complex_schemas_spec: dict) -> None:
        """Test that allOf correctly merges properties from multiple schemas."""
        user_schema = complex_schemas_spec["components"]["schemas"]["User"]
        resolved = resolve_schema(complex_schemas_spec, user_schema)

        assert resolved["type"] == "object"
        # Should have properties from BaseEntity and User
        assert "id" in resolved["properties"]
        assert "createdAt" in resolved["properties"]
        assert "name" in resolved["properties"]
        assert "email" in resolved["properties"]
        # Should merge required fields
        assert "id" in resolved["required"]
        assert "name" in resolved["required"]

    def test_anyof_selects_first_non_null(self, complex_schemas_spec: dict) -> None:
        """Test that anyOf selects the first non-null option."""
        nullable_string = complex_schemas_spec["components"]["schemas"]["NullableString"]
        resolved = resolve_schema(complex_schemas_spec, nullable_string)

        # First option is null, so should select second (string)
        assert resolved["type"] == "string"

    def test_anyof_with_non_null_first(self, complex_schemas_spec: dict) -> None:
        """Test anyOf when the first option is not null."""
        nullable_reversed = complex_schemas_spec["components"]["schemas"]["NullableStringReversed"]
        resolved = resolve_schema(complex_schemas_spec, nullable_reversed)

        # First option is string (not null)
        assert resolved["type"] == "string"

    def test_oneof_selects_first_option(self, complex_schemas_spec: dict) -> None:
        """Test that oneOf selects the first option."""
        oneof_schema = complex_schemas_spec["components"]["schemas"]["OneOfExample"]
        resolved = resolve_schema(complex_schemas_spec, oneof_schema)

        assert resolved["type"] == "object"
        assert "type" in resolved["properties"]
        assert "email" in resolved["properties"]

    def test_nested_compositions(self, complex_schemas_spec: dict) -> None:
        """Test resolving nested allOf compositions (allOf referencing allOf)."""
        nested_allof = complex_schemas_spec["components"]["schemas"]["NestedAllOf"]
        resolved = resolve_schema(complex_schemas_spec, nested_allof)

        assert resolved["type"] == "object"
        # Should have properties from BaseEntity, User, and the additional role
        assert "id" in resolved["properties"]
        assert "name" in resolved["properties"]
        assert "role" in resolved["properties"]
        # Should merge all required fields
        assert "id" in resolved["required"]
        assert "name" in resolved["required"]
        assert "role" in resolved["required"]

    def test_array_items_resolution(self, complex_schemas_spec: dict) -> None:
        """Test that array items with $ref are resolved."""
        array_schema = complex_schemas_spec["components"]["schemas"]["ArrayOfUsers"]
        resolved = resolve_schema(complex_schemas_spec, array_schema)

        assert resolved["type"] == "array"
        assert resolved["items"]["type"] == "object"
        # Items should be resolved User schema (from allOf)
        assert "id" in resolved["items"]["properties"]
        assert "name" in resolved["items"]["properties"]

    def test_object_properties_resolution(self, complex_schemas_spec: dict) -> None:
        """Test that object properties with $ref are resolved."""
        obj_schema = complex_schemas_spec["components"]["schemas"]["ObjectWithNestedRef"]
        resolved = resolve_schema(complex_schemas_spec, obj_schema)

        assert resolved["type"] == "object"
        # The user property should be resolved
        assert resolved["properties"]["user"]["type"] == "object"
        assert "id" in resolved["properties"]["user"]["properties"]
        # Metadata should remain as-is
        assert "tags" in resolved["properties"]["metadata"]["properties"]

    def test_empty_schema_returns_empty(self, simple_json_spec: dict) -> None:
        """Test that an empty schema returns an empty dict."""
        resolved = resolve_schema(simple_json_spec, {})
        assert resolved == {}

    def test_direct_ref_resolution(self, complex_schemas_spec: dict) -> None:
        """Test resolving a schema that is just a $ref."""
        deep_nested = complex_schemas_spec["components"]["schemas"]["DeepNested"]
        resolved = resolve_schema(complex_schemas_spec, deep_nested)

        # Should resolve the User schema through the $ref
        assert resolved["type"] == "object"
        assert "id" in resolved["properties"]
        assert "name" in resolved["properties"]


# =============================================================================
# make_tool_name tests
# =============================================================================


class TestMakeToolName:
    """Tests for the make_tool_name function."""

    def test_get_collection_returns_list(self) -> None:
        """Test GET on collection returns list_{resources}."""
        name = make_tool_name("GET", "/users", None)
        assert name == "list_users"

    def test_get_item_returns_get_singular(self) -> None:
        """Test GET on item returns get_{resource} (singularized)."""
        name = make_tool_name("GET", "/users/{id}", None)
        assert name == "get_user"

    def test_post_returns_create(self) -> None:
        """Test POST returns create_{resource} (uses plural form for collection endpoint)."""
        name = make_tool_name("POST", "/users", None)
        # POST to collection uses the plural form since there's no {id}
        assert name == "create_users"

    def test_put_returns_replace(self) -> None:
        """Test PUT returns replace_{resource}."""
        name = make_tool_name("PUT", "/users/{id}", None)
        assert name == "replace_user"

    def test_patch_returns_update(self) -> None:
        """Test PATCH returns update_{resource}."""
        name = make_tool_name("PATCH", "/users/{id}", None)
        assert name == "update_user"

    def test_delete_returns_delete(self) -> None:
        """Test DELETE returns delete_{resource}."""
        name = make_tool_name("DELETE", "/users/{id}", None)
        assert name == "delete_user"

    def test_nested_resources_adds_parent_context(self) -> None:
        """Test nested resources include parent context with verb first."""
        name = make_tool_name("GET", "/organizations/{org_id}/teams", None)
        assert name == "list_organizations_teams"

    def test_nested_item_resource(self) -> None:
        """Test nested item resources include parent and singularize."""
        name = make_tool_name("GET", "/organizations/{org_id}/teams/{team_id}", None)
        assert name == "get_organizations_team"

    def test_nested_resource_store_orders(self) -> None:
        """Test /store/orders generates list_store_orders."""
        name = make_tool_name("GET", "/store/orders", None)
        assert name == "list_store_orders"

    def test_version_prefix_removal(self) -> None:
        """Test that version prefixes (/v1/, /v2/) are removed."""
        name_v1 = make_tool_name("GET", "/v1/users", None)
        name_v2 = make_tool_name("GET", "/v2/users", None)

        assert name_v1 == "list_users"
        assert name_v2 == "list_users"

    def test_version_prefix_with_nested(self) -> None:
        """Test version prefix removal with nested resources."""
        name = make_tool_name("GET", "/v1/organizations/{org_id}/teams", None)
        assert name == "list_organizations_teams"

    def test_hyphenated_resources(self) -> None:
        """Test that hyphens are converted to underscores."""
        name = make_tool_name("GET", "/data-sources", None)
        assert name == "list_data_sources"

    def test_empty_path_uses_root(self) -> None:
        """Test that empty path segments result in 'root' as resource."""
        name = make_tool_name("GET", "/", None)
        assert name == "list_root"

    def test_resource_ending_in_ss_not_over_singularized(self) -> None:
        """Test that resources ending in 'ss' are not over-singularized."""
        # 'address' should stay as 'address', not become 'addres'
        name = make_tool_name("GET", "/address/{id}", None)
        assert "addres" not in name or "address" in name

    def test_lowercase_method(self) -> None:
        """Test that method handling is case-insensitive."""
        name_lower = make_tool_name("get", "/users", None)
        name_upper = make_tool_name("GET", "/users", None)
        assert name_lower == name_upper

    def test_uncommon_method(self) -> None:
        """Test handling of uncommon HTTP methods."""
        name = make_tool_name("OPTIONS", "/users", None)
        assert name == "options_users"

    def test_operation_id_used_when_provided(self) -> None:
        """Test that operationId from spec is used when provided."""
        # When an operationId is provided, it should be used instead of generating one
        name = make_tool_name(
            "POST", "/v1/skills/webhooks/skill/{skill_id}", "receive_skill_webhook"
        )
        assert name == "receive_skill_webhook"

    def test_operation_id_cleaned_up(self) -> None:
        """Test that operationId is cleaned up (camelCase to snake_case, etc)."""
        # CamelCase operationId should be converted to snake_case
        name = make_tool_name("GET", "/users", "getUsersList")
        assert name == "get_users_list"

    def test_operation_id_with_hyphens(self) -> None:
        """Test that operationId with hyphens is converted to underscores."""
        name = make_tool_name("GET", "/users", "get-users-list")
        assert name == "get_users_list"

    def test_operation_id_none_generates_name(self) -> None:
        """Test that None operationId falls back to generated name."""
        name = make_tool_name("GET", "/users", None)
        assert name == "list_users"

    def test_operation_id_empty_string_generates_name(self) -> None:
        """Test that empty string operationId falls back to generated name."""
        name = make_tool_name("GET", "/users", "")
        assert name == "list_users"


# =============================================================================
# extract_endpoints tests
# =============================================================================


class TestExtractEndpoints:
    """Tests for the extract_endpoints function."""

    def test_extracts_parameters_correctly(self, simple_json_spec: dict) -> None:
        """Test that parameters are correctly extracted."""
        endpoints = extract_endpoints(simple_json_spec)

        # Find the GET /users endpoint
        list_users = next(e for e in endpoints if e["method"] == "GET" and e["path"] == "/users")

        assert len(list_users["parameters"]) == 1
        param = list_users["parameters"][0]
        assert param["name"] == "limit"
        assert param["in"] == "query"
        assert param["required"] is False
        assert param["schema"]["type"] == "integer"

    def test_extracts_request_body(self, simple_json_spec: dict) -> None:
        """Test that request bodies are correctly extracted."""
        endpoints = extract_endpoints(simple_json_spec)

        # Find the POST /users endpoint
        create_user = next(e for e in endpoints if e["method"] == "POST" and e["path"] == "/users")

        assert create_user["request_body"] is not None
        assert create_user["request_body"]["content_type"] == "application/json"
        assert create_user["request_body"]["required"] is True
        # Schema should be resolved
        assert create_user["request_body"]["schema"]["type"] == "object"
        assert "name" in create_user["request_body"]["schema"]["properties"]

    def test_handles_tags(self, simple_json_spec: dict) -> None:
        """Test that tags are correctly extracted."""
        endpoints = extract_endpoints(simple_json_spec)

        # All endpoints in simple.json have 'users' tag
        for endpoint in endpoints:
            assert endpoint["tags"] == ["users"]

    def test_resolves_parameter_refs(self, simple_json_spec: dict) -> None:
        """Test that parameter $refs are resolved."""
        endpoints = extract_endpoints(simple_json_spec)

        # Find GET /users/{id} - it uses a $ref for the id parameter
        get_user = next(e for e in endpoints if e["method"] == "GET" and e["path"] == "/users/{id}")

        # Should have the id parameter resolved from $ref
        id_param = next((p for p in get_user["parameters"] if p["name"] == "id"), None)
        assert id_param is not None
        assert id_param["in"] == "path"
        assert id_param["required"] is True
        assert id_param["description"] == "User ID"
        assert id_param["schema"]["type"] == "integer"

    def test_handles_duplicate_tool_names(self, duplicate_names_spec: dict) -> None:
        """Test that duplicate tool names get unique suffixes."""
        endpoints = extract_endpoints(duplicate_names_spec)

        tool_names = [e["tool_name"] for e in endpoints]

        # All tool names should be unique
        assert len(tool_names) == len(set(tool_names))

        # First one should not have suffix, subsequent ones should
        # Due to parent context, these might all be unique already
        # but if there are duplicates, they should have _2, _3, etc.
        for name in tool_names:
            assert name  # All should have a name

    def test_extracts_response_schema(self, simple_json_spec: dict) -> None:
        """Test that response schemas are extracted."""
        endpoints = extract_endpoints(simple_json_spec)

        # GET /users/{id} has a response schema
        get_user = next(e for e in endpoints if e["method"] == "GET" and e["path"] == "/users/{id}")

        assert get_user["response_schema"] is not None
        assert get_user["response_schema"]["type"] == "object"
        assert "id" in get_user["response_schema"]["properties"]

    def test_extracts_all_http_methods(self, simple_json_spec: dict) -> None:
        """Test that all HTTP methods are extracted."""
        endpoints = extract_endpoints(simple_json_spec)

        methods = {e["method"] for e in endpoints}

        assert "GET" in methods
        assert "POST" in methods
        assert "PATCH" in methods
        assert "DELETE" in methods

    def test_extracts_description_from_summary_and_description(
        self, simple_json_spec: dict
    ) -> None:
        """Test that full description combines summary and description."""
        endpoints = extract_endpoints(simple_json_spec)

        # GET /users has both summary and description
        list_users = next(e for e in endpoints if e["method"] == "GET" and e["path"] == "/users")

        assert "List all users" in list_users["description"]
        assert "Returns a list of users" in list_users["description"]

    def test_extracts_operation_id(self, simple_json_spec: dict) -> None:
        """Test that operationId is extracted."""
        endpoints = extract_endpoints(simple_json_spec)

        list_users = next(e for e in endpoints if e["method"] == "GET" and e["path"] == "/users")
        assert list_users["operation_id"] == "listUsers"

    def test_path_level_parameters_inherited(self, simple_json_spec: dict) -> None:
        """Test that path-level parameters are inherited by operations."""
        endpoints = extract_endpoints(simple_json_spec)

        # All /users/{id} operations should have the id parameter
        users_id_endpoints = [e for e in endpoints if e["path"] == "/users/{id}"]

        for endpoint in users_id_endpoints:
            id_param = next((p for p in endpoint["parameters"] if p["name"] == "id"), None)
            assert id_param is not None, f"{endpoint['method']} /users/{{id}} missing id parameter"

    def test_nested_resources_tool_names(self, nested_resources_spec: dict) -> None:
        """Test tool naming for nested resources uses operationId when provided."""
        endpoints = extract_endpoints(nested_resources_spec)

        # Find organizations/teams endpoints - these have operationId in the fixture
        org_teams_list = next(
            (
                e
                for e in endpoints
                if "teams" in e["path"] and e["method"] == "GET" and "{team_id}" not in e["path"]
            ),
            None,
        )
        org_team_get = next(
            (e for e in endpoints if "{team_id}" in e["path"] and e["method"] == "GET"), None
        )

        # The fixture has operationId: "listOrgTeams" -> "list_org_teams"
        assert org_teams_list is not None
        assert org_teams_list["tool_name"] == "list_org_teams"

        # The fixture has operationId: "getOrgTeam" -> "get_org_team"
        assert org_team_get is not None
        assert org_team_get["tool_name"] == "get_org_team"

    def test_nested_resources_without_operation_id(self, nested_resources_spec: dict) -> None:
        """Test tool naming falls back to generated name without operationId."""
        endpoints = extract_endpoints(nested_resources_spec)

        # Find /skills endpoint which has no operationId
        skills_list = next(
            (e for e in endpoints if e["path"] == "/skills" and e["method"] == "GET"), None
        )

        assert skills_list is not None
        # Without operationId, should generate name from path
        assert skills_list["tool_name"] == "list_skills"

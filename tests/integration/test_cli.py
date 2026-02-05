"""Integration tests for CLI commands."""

import json
import tempfile
from typing import Any
from unittest.mock import patch

import pytest
import yaml
from click.testing import CliRunner

from openapi_to_mcp.auth import AuthType
from openapi_to_mcp.cli import main


@pytest.fixture
def cli_runner() -> CliRunner:
    """Create a Click CLI test runner."""
    return CliRunner()


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


class TestServeCommand:
    """Tests for the 'serve' CLI command."""

    def test_serve_command_calls_run_server(self, cli_runner: CliRunner, petstore_spec_file: str):
        """Test that serve command invokes run_server with correct args."""
        with patch("openapi_to_mcp.cli.asyncio.run") as mock_run:
            result = cli_runner.invoke(
                main,
                [
                    "serve",
                    petstore_spec_file,
                    "--base-url",
                    "https://api.example.com",
                ],
            )

        assert result.exit_code == 0
        mock_run.assert_called_once()

    def test_serve_command_with_basic_auth(self, cli_runner: CliRunner, petstore_spec_file: str):
        """Test serve command with basic authentication options."""
        with patch("openapi_to_mcp.cli.asyncio.run") as mock_run:
            result = cli_runner.invoke(
                main,
                [
                    "serve",
                    petstore_spec_file,
                    "--base-url",
                    "https://api.example.com",
                    "--auth-type",
                    "basic",
                    "--username",
                    "testuser",
                    "--password",
                    "testpass",
                ],
            )

        assert result.exit_code == 0
        mock_run.assert_called_once()

    def test_serve_command_with_bearer_auth(self, cli_runner: CliRunner, petstore_spec_file: str):
        """Test serve command with bearer token authentication."""
        with patch("openapi_to_mcp.cli.asyncio.run") as mock_run:
            result = cli_runner.invoke(
                main,
                [
                    "serve",
                    petstore_spec_file,
                    "--base-url",
                    "https://api.example.com",
                    "--auth-type",
                    "bearer",
                    "--bearer-token",
                    "my-secret-token",
                ],
            )

        assert result.exit_code == 0
        mock_run.assert_called_once()

    def test_serve_command_with_api_key_header_auth(
        self, cli_runner: CliRunner, petstore_spec_file: str
    ):
        """Test serve command with API key header authentication."""
        with patch("openapi_to_mcp.cli.asyncio.run") as mock_run:
            result = cli_runner.invoke(
                main,
                [
                    "serve",
                    petstore_spec_file,
                    "--base-url",
                    "https://api.example.com",
                    "--auth-type",
                    "api-key-header",
                    "--api-key",
                    "my-api-key",
                    "--api-key-name",
                    "X-Custom-Key",
                ],
            )

        assert result.exit_code == 0
        mock_run.assert_called_once()

    def test_serve_command_with_oauth2_password(
        self, cli_runner: CliRunner, petstore_spec_file: str
    ):
        """Test serve command with OAuth2 password flow."""
        with patch("openapi_to_mcp.cli.asyncio.run") as mock_run:
            result = cli_runner.invoke(
                main,
                [
                    "serve",
                    petstore_spec_file,
                    "--base-url",
                    "https://api.example.com",
                    "--auth-type",
                    "oauth2-password",
                    "--username",
                    "oauth-user",
                    "--password",
                    "oauth-pass",
                    "--token-url",
                    "/oauth/token",
                    "--scope",
                    "read write",
                ],
            )

        assert result.exit_code == 0
        mock_run.assert_called_once()

    def test_serve_command_with_oauth2_client_credentials(
        self, cli_runner: CliRunner, petstore_spec_file: str
    ):
        """Test serve command with OAuth2 client credentials flow."""
        with patch("openapi_to_mcp.cli.asyncio.run") as mock_run:
            result = cli_runner.invoke(
                main,
                [
                    "serve",
                    petstore_spec_file,
                    "--base-url",
                    "https://api.example.com",
                    "--auth-type",
                    "oauth2-client",
                    "--client-id",
                    "my-client-id",
                    "--client-secret",
                    "my-client-secret",
                    "--token-url",
                    "/oauth/token",
                ],
            )

        assert result.exit_code == 0
        mock_run.assert_called_once()

    def test_serve_command_with_tag_filters(self, cli_runner: CliRunner, petstore_spec_file: str):
        """Test serve command with include and exclude tag filters."""
        with patch("openapi_to_mcp.cli.asyncio.run") as mock_run:
            result = cli_runner.invoke(
                main,
                [
                    "serve",
                    petstore_spec_file,
                    "--base-url",
                    "https://api.example.com",
                    "--include-tag",
                    "pets",
                    "--include-tag",
                    "stores",
                    "--exclude-tag",
                    "admin",
                ],
            )

        assert result.exit_code == 0
        mock_run.assert_called_once()

    def test_serve_command_requires_base_url(self, cli_runner: CliRunner, petstore_spec_file: str):
        """Test that serve command requires --base-url option."""
        result = cli_runner.invoke(
            main,
            ["serve", petstore_spec_file],
        )

        assert result.exit_code != 0
        assert "Missing option" in result.output or "required" in result.output.lower()

    def test_serve_command_requires_spec_source(self, cli_runner: CliRunner):
        """Test that serve command requires spec source argument."""
        result = cli_runner.invoke(
            main,
            ["serve", "--base-url", "https://api.example.com"],
        )

        assert result.exit_code != 0


class TestInspectCommand:
    """Tests for the 'inspect' CLI command."""

    def test_inspect_command_outputs_tools(self, cli_runner: CliRunner, minimal_spec_file: str):
        """Test that inspect command outputs tool definitions."""
        result = cli_runner.invoke(
            main,
            ["inspect", minimal_spec_file],
        )

        assert result.exit_code == 0

        output = json.loads(result.output)
        assert "tool_count" in output
        assert "tools" in output
        assert output["tool_count"] >= 1

    def test_inspect_command_with_output_file(self, cli_runner: CliRunner, minimal_spec_file: str):
        """Test that inspect command writes to output file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            output_path = f.name

        result = cli_runner.invoke(
            main,
            ["inspect", minimal_spec_file, "--output", output_path],
        )

        assert result.exit_code == 0
        assert "Wrote" in result.output
        assert output_path in result.output

        # Verify the file was written correctly
        with open(output_path) as f:
            output_data = json.load(f)

        assert "tool_count" in output_data
        assert "tools" in output_data

    def test_inspect_command_excludes_internal_fields(
        self, cli_runner: CliRunner, minimal_spec_file: str
    ):
        """Test that inspect command excludes internal fields starting with _."""
        result = cli_runner.invoke(
            main,
            ["inspect", minimal_spec_file],
        )

        assert result.exit_code == 0

        output = json.loads(result.output)
        for tool in output["tools"]:
            # Check no keys start with underscore
            for key in tool.keys():
                assert not key.startswith("_")

    def test_inspect_command_with_petstore_spec(
        self, cli_runner: CliRunner, petstore_spec_file: str
    ):
        """Test inspect command with a larger petstore spec."""
        result = cli_runner.invoke(
            main,
            ["inspect", petstore_spec_file],
        )

        assert result.exit_code == 0

        output = json.loads(result.output)
        # Petstore spec should have multiple tools
        assert output["tool_count"] > 5


class TestListEndpointsCommand:
    """Tests for the 'list-endpoints' CLI command."""

    def test_list_endpoints_shows_all_endpoints(
        self, cli_runner: CliRunner, minimal_spec_file: str
    ):
        """Test that list-endpoints shows all endpoints."""
        result = cli_runner.invoke(
            main,
            ["list-endpoints", minimal_spec_file],
        )

        assert result.exit_code == 0
        assert "Found" in result.output
        assert "endpoints" in result.output

    def test_list_endpoints_groups_by_tag(self, cli_runner: CliRunner, petstore_spec_file: str):
        """Test that list-endpoints groups endpoints by tag."""
        result = cli_runner.invoke(
            main,
            ["list-endpoints", petstore_spec_file],
        )

        assert result.exit_code == 0
        # Should show tag sections
        assert "[pets]" in result.output or "[default]" in result.output

    def test_list_endpoints_shows_method_and_path(
        self, cli_runner: CliRunner, minimal_spec_file: str
    ):
        """Test that list-endpoints shows HTTP method and path."""
        result = cli_runner.invoke(
            main,
            ["list-endpoints", minimal_spec_file],
        )

        assert result.exit_code == 0
        assert "GET" in result.output or "POST" in result.output
        assert "/items" in result.output

    def test_list_endpoints_shows_tool_names(self, cli_runner: CliRunner, minimal_spec_file: str):
        """Test that list-endpoints shows generated tool names."""
        result = cli_runner.invoke(
            main,
            ["list-endpoints", minimal_spec_file],
        )

        assert result.exit_code == 0
        assert "->" in result.output  # Tool name indicator


class TestGenerateConfigCommand:
    """Tests for the 'generate-config' CLI command."""

    def test_generate_config_creates_mcp_config(
        self, cli_runner: CliRunner, minimal_spec_file: str
    ):
        """Test that generate-config creates valid MCP config."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            output_path = f.name

        result = cli_runner.invoke(
            main,
            [
                "generate-config",
                minimal_spec_file,
                "--base-url",
                "https://api.example.com",
                "--output",
                output_path,
            ],
        )

        assert result.exit_code == 0
        assert "Generated MCP config" in result.output

        with open(output_path) as f:
            config = json.load(f)

        assert "mcpServers" in config
        assert "swagger-api" in config["mcpServers"]  # default name
        assert "command" in config["mcpServers"]["swagger-api"]
        assert "args" in config["mcpServers"]["swagger-api"]

    def test_generate_config_with_custom_server_name(
        self, cli_runner: CliRunner, minimal_spec_file: str
    ):
        """Test generate-config with custom server name."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            output_path = f.name

        result = cli_runner.invoke(
            main,
            [
                "generate-config",
                minimal_spec_file,
                "--base-url",
                "https://api.example.com",
                "--output",
                output_path,
                "--server-name",
                "my-custom-api",
            ],
        )

        assert result.exit_code == 0

        with open(output_path) as f:
            config = json.load(f)

        assert "my-custom-api" in config["mcpServers"]

    def test_generate_config_includes_auth_options(
        self, cli_runner: CliRunner, minimal_spec_file: str
    ):
        """Test that generate-config includes auth options in args."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            output_path = f.name

        result = cli_runner.invoke(
            main,
            [
                "generate-config",
                minimal_spec_file,
                "--base-url",
                "https://api.example.com",
                "--output",
                output_path,
                "--auth-type",
                "bearer",
                "--bearer-token",
                "secret-token",
            ],
        )

        assert result.exit_code == 0

        with open(output_path) as f:
            config = json.load(f)

        args = config["mcpServers"]["swagger-api"]["args"]
        assert "--auth-type" in args
        assert "bearer" in args
        assert "--bearer-token" in args
        assert "secret-token" in args

    def test_generate_config_includes_tag_filters(
        self, cli_runner: CliRunner, minimal_spec_file: str
    ):
        """Test that generate-config includes tag filters in args."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            output_path = f.name

        result = cli_runner.invoke(
            main,
            [
                "generate-config",
                minimal_spec_file,
                "--base-url",
                "https://api.example.com",
                "--output",
                output_path,
                "--include-tag",
                "pets",
                "--exclude-tag",
                "admin",
            ],
        )

        assert result.exit_code == 0

        with open(output_path) as f:
            config = json.load(f)

        args = config["mcpServers"]["swagger-api"]["args"]
        assert "--include-tag" in args
        assert "pets" in args
        assert "--exclude-tag" in args
        assert "admin" in args

    def test_generate_config_uses_uv_command(self, cli_runner: CliRunner, minimal_spec_file: str):
        """Test that generate-config uses uv as the command."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            output_path = f.name

        result = cli_runner.invoke(
            main,
            [
                "generate-config",
                minimal_spec_file,
                "--base-url",
                "https://api.example.com",
                "--output",
                output_path,
            ],
        )

        assert result.exit_code == 0

        with open(output_path) as f:
            config = json.load(f)

        assert config["mcpServers"]["swagger-api"]["command"] == "uv"


class TestAuthTypeMapping:
    """Tests for CLI auth type string to AuthType enum mapping."""

    @pytest.mark.parametrize(
        "cli_auth_type,expected_enum",
        [
            ("none", AuthType.NONE),
            ("basic", AuthType.HTTP_BASIC),
            ("bearer", AuthType.HTTP_BEARER),
            ("api-key-header", AuthType.API_KEY_HEADER),
            ("api-key-query", AuthType.API_KEY_QUERY),
            ("api-key-cookie", AuthType.API_KEY_COOKIE),
            ("oauth2-password", AuthType.OAUTH2_PASSWORD),
            ("oauth2-client", AuthType.OAUTH2_CLIENT_CREDENTIALS),
        ],
    )
    def test_auth_type_mapping(
        self,
        cli_runner: CliRunner,
        petstore_spec_file: str,
        cli_auth_type: str,
        expected_enum: AuthType,
    ):
        """Test that CLI auth type strings map to correct AuthType enums."""
        with patch("openapi_to_mcp.cli.asyncio.run"):
            result = cli_runner.invoke(
                main,
                [
                    "serve",
                    petstore_spec_file,
                    "--base-url",
                    "https://api.example.com",
                    "--auth-type",
                    cli_auth_type,
                ],
            )

        assert result.exit_code == 0

    def test_invalid_auth_type_rejected(self, cli_runner: CliRunner, petstore_spec_file: str):
        """Test that invalid auth type is rejected."""
        result = cli_runner.invoke(
            main,
            [
                "serve",
                petstore_spec_file,
                "--base-url",
                "https://api.example.com",
                "--auth-type",
                "invalid-auth-type",
            ],
        )

        assert result.exit_code != 0
        assert "Invalid value" in result.output or "invalid" in result.output.lower()

    def test_auth_type_case_insensitive(self, cli_runner: CliRunner, petstore_spec_file: str):
        """Test that auth type is case insensitive."""
        with patch("openapi_to_mcp.cli.asyncio.run"):
            result = cli_runner.invoke(
                main,
                [
                    "serve",
                    petstore_spec_file,
                    "--base-url",
                    "https://api.example.com",
                    "--auth-type",
                    "BEARER",
                ],
            )

        assert result.exit_code == 0


class TestCLIHelp:
    """Tests for CLI help text."""

    def test_main_help(self, cli_runner: CliRunner):
        """Test main CLI help text."""
        result = cli_runner.invoke(main, ["--help"])

        assert result.exit_code == 0
        assert "OpenAPI" in result.output or "Swagger" in result.output

    def test_serve_help(self, cli_runner: CliRunner):
        """Test serve command help text."""
        result = cli_runner.invoke(main, ["serve", "--help"])

        assert result.exit_code == 0
        assert "--base-url" in result.output
        assert "--auth-type" in result.output

    def test_inspect_help(self, cli_runner: CliRunner):
        """Test inspect command help text."""
        result = cli_runner.invoke(main, ["inspect", "--help"])

        assert result.exit_code == 0
        assert "SPEC_SOURCE" in result.output

    def test_generate_config_help(self, cli_runner: CliRunner):
        """Test generate-config command help text."""
        result = cli_runner.invoke(main, ["generate-config", "--help"])

        assert result.exit_code == 0
        assert "--server-name" in result.output

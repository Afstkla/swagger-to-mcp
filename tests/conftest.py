"""Shared pytest fixtures for openapi-to-mcp tests."""

from pathlib import Path
from typing import Any

import pytest
import yaml

from openapi_to_mcp.auth import AuthConfig, AuthType

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "specs"


@pytest.fixture
def minimal_spec() -> dict[str, Any]:
    """Return a minimal valid OpenAPI 3.0 spec dict."""
    return {
        "openapi": "3.0.0",
        "info": {
            "title": "Minimal API",
            "version": "1.0.0",
            "description": "A minimal OpenAPI spec for testing",
        },
        "paths": {
            "/items": {
                "get": {
                    "operationId": "getItems",
                    "summary": "Get all items",
                    "responses": {
                        "200": {
                            "description": "Successful response",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "array",
                                        "items": {"type": "string"},
                                    }
                                }
                            },
                        }
                    },
                },
                "post": {
                    "operationId": "createItem",
                    "summary": "Create an item",
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {"name": {"type": "string"}},
                                    "required": ["name"],
                                }
                            }
                        },
                    },
                    "responses": {
                        "201": {
                            "description": "Item created",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "id": {"type": "integer"},
                                            "name": {"type": "string"},
                                        },
                                    }
                                }
                            },
                        }
                    },
                },
            }
        },
    }


@pytest.fixture
def petstore_spec() -> dict[str, Any]:
    """Load the petstore OpenAPI spec from fixtures."""
    spec_path = FIXTURES_DIR / "petstore.yaml"
    with open(spec_path) as f:
        return yaml.safe_load(f)


@pytest.fixture
def complex_refs_spec() -> dict[str, Any]:
    """Load the complex refs OpenAPI spec from fixtures."""
    spec_path = FIXTURES_DIR / "complex_refs.yaml"
    with open(spec_path) as f:
        return yaml.safe_load(f)


@pytest.fixture
def auth_config():
    """Factory fixture for creating AuthConfig objects with various configurations."""

    def _create_auth_config(
        auth_type: AuthType = AuthType.NONE,
        username: str | None = None,
        password: str | None = None,
        bearer_token: str | None = None,
        api_key: str | None = None,
        api_key_name: str = "X-API-Key",
        token_url: str | None = None,
        login_url: str | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
        scope: str = "",
    ) -> AuthConfig:
        """Create an AuthConfig with the specified parameters."""
        return AuthConfig(
            auth_type=auth_type,
            username=username,
            password=password,
            bearer_token=bearer_token,
            api_key=api_key,
            api_key_name=api_key_name,
            token_url=token_url,
            login_url=login_url,
            client_id=client_id,
            client_secret=client_secret,
            scope=scope,
        )

    return _create_auth_config


@pytest.fixture
def api_key_auth(auth_config) -> AuthConfig:
    """Pre-configured API key header auth."""
    return auth_config(
        auth_type=AuthType.API_KEY_HEADER,
        api_key="test-api-key-12345",
        api_key_name="X-API-Key",
    )


@pytest.fixture
def bearer_auth(auth_config) -> AuthConfig:
    """Pre-configured bearer token auth."""
    return auth_config(
        auth_type=AuthType.HTTP_BEARER,
        bearer_token="test-bearer-token-xyz",
    )


@pytest.fixture
def basic_auth(auth_config) -> AuthConfig:
    """Pre-configured HTTP basic auth."""
    return auth_config(
        auth_type=AuthType.HTTP_BASIC,
        username="testuser",
        password="testpass",
    )


@pytest.fixture
def oauth2_password_auth(auth_config) -> AuthConfig:
    """Pre-configured OAuth2 password flow auth."""
    return auth_config(
        auth_type=AuthType.OAUTH2_PASSWORD,
        username="oauth-user",
        password="oauth-pass",
        token_url="/oauth/token",
        scope="read write",
    )


@pytest.fixture
def oauth2_client_credentials_auth(auth_config) -> AuthConfig:
    """Pre-configured OAuth2 client credentials flow auth."""
    return auth_config(
        auth_type=AuthType.OAUTH2_CLIENT_CREDENTIALS,
        client_id="client-id-123",
        client_secret="client-secret-456",
        token_url="/oauth/token",
        scope="api.read api.write",
    )

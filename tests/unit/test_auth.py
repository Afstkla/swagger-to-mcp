"""Unit tests for the auth module."""

import base64

import httpx
import pytest
from pytest_httpx import HTTPXMock

from openapi_to_mcp.auth import (
    AuthConfig,
    AuthenticatedClient,
    AuthenticationError,
    AuthType,
)

# =============================================================================
# AuthType Enum Tests
# =============================================================================


class TestAuthType:
    """Tests for the AuthType enum."""

    def test_auth_type_values(self):
        """Test that AuthType has all expected values."""
        assert AuthType.NONE.value == "none"
        assert AuthType.HTTP_BASIC.value == "http_basic"
        assert AuthType.HTTP_BEARER.value == "http_bearer"
        assert AuthType.API_KEY_HEADER.value == "api_key_header"
        assert AuthType.API_KEY_QUERY.value == "api_key_query"
        assert AuthType.API_KEY_COOKIE.value == "api_key_cookie"
        assert AuthType.OAUTH2_PASSWORD.value == "oauth2_password"
        assert AuthType.OAUTH2_CLIENT_CREDENTIALS.value == "oauth2_client_credentials"

    def test_auth_type_count(self):
        """Test that AuthType has exactly 8 members."""
        assert len(AuthType) == 8


# =============================================================================
# AuthConfig Tests
# =============================================================================


class TestAuthConfig:
    """Tests for the AuthConfig dataclass."""

    def test_default_values(self):
        """Test AuthConfig default values."""
        config = AuthConfig()

        assert config.auth_type == AuthType.NONE
        assert config.username is None
        assert config.password is None
        assert config.bearer_token is None
        assert config.api_key is None
        assert config.api_key_name == "X-API-Key"
        assert config.token_url is None
        assert config.login_url is None
        assert config.client_id is None
        assert config.client_secret is None
        assert config.scope == ""

    def test_all_fields_initialization(self):
        """Test AuthConfig with all fields set."""
        config = AuthConfig(
            auth_type=AuthType.OAUTH2_CLIENT_CREDENTIALS,
            username="user",
            password="pass",
            bearer_token="token123",
            api_key="apikey123",
            api_key_name="X-Custom-Key",
            token_url="https://auth.example.com/token",
            login_url="https://auth.example.com/login",
            client_id="client123",
            client_secret="secret456",
            scope="read write",
        )

        assert config.auth_type == AuthType.OAUTH2_CLIENT_CREDENTIALS
        assert config.username == "user"
        assert config.password == "pass"
        assert config.bearer_token == "token123"
        assert config.api_key == "apikey123"
        assert config.api_key_name == "X-Custom-Key"
        assert config.token_url == "https://auth.example.com/token"
        assert config.login_url == "https://auth.example.com/login"
        assert config.client_id == "client123"
        assert config.client_secret == "secret456"
        assert config.scope == "read write"

    def test_private_fields_default_values(self):
        """Test that private fields have correct default values."""
        config = AuthConfig()

        assert config._access_token is None
        assert config._token_type == "Bearer"

    def test_private_fields_not_in_repr(self):
        """Test that private fields are excluded from repr."""
        config = AuthConfig()
        config._access_token = "secret_token"

        repr_str = repr(config)
        assert "secret_token" not in repr_str
        assert "_access_token" not in repr_str
        assert "_token_type" not in repr_str

    def test_auth_config_with_http_basic(self):
        """Test AuthConfig for HTTP Basic authentication."""
        config = AuthConfig(
            auth_type=AuthType.HTTP_BASIC,
            username="admin",
            password="secret",
        )

        assert config.auth_type == AuthType.HTTP_BASIC
        assert config.username == "admin"
        assert config.password == "secret"


# =============================================================================
# AuthenticatedClient Tests
# =============================================================================


class TestAuthenticatedClientInit:
    """Tests for AuthenticatedClient initialization."""

    def test_init_with_defaults(self):
        """Test AuthenticatedClient initialization with defaults."""
        client = AuthenticatedClient("https://api.example.com")

        assert client.base_url == "https://api.example.com"
        assert client.auth.auth_type == AuthType.NONE
        assert client.timeout == 60
        assert client._client is None

    def test_init_strips_trailing_slash(self):
        """Test that trailing slash is stripped from base_url."""
        client = AuthenticatedClient("https://api.example.com/")

        assert client.base_url == "https://api.example.com"

    def test_init_with_auth_config(self):
        """Test AuthenticatedClient initialization with auth config."""
        auth = AuthConfig(auth_type=AuthType.HTTP_BEARER, bearer_token="token123")
        client = AuthenticatedClient("https://api.example.com", auth=auth, timeout=30)

        assert client.auth.auth_type == AuthType.HTTP_BEARER
        assert client.auth.bearer_token == "token123"
        assert client.timeout == 30


class TestAuthenticatedClientContextManager:
    """Tests for AuthenticatedClient async context manager."""

    async def test_context_manager_enters_correctly(self, httpx_mock: HTTPXMock):
        """Test that context manager creates client on enter."""
        async with AuthenticatedClient("https://api.example.com") as client:
            assert client._client is not None
            assert isinstance(client._client, httpx.AsyncClient)

    async def test_context_manager_exits_correctly(self, httpx_mock: HTTPXMock):
        """Test that context manager closes client on exit."""
        client = AuthenticatedClient("https://api.example.com")

        async with client:
            assert client._client is not None

        assert client._client is None

    async def test_context_manager_returns_self(self, httpx_mock: HTTPXMock):
        """Test that context manager returns the client instance."""
        client = AuthenticatedClient("https://api.example.com")

        async with client as ctx:
            assert ctx is client


class TestAuthenticatedClientHttpBasic:
    """Tests for HTTP Basic authentication."""

    async def test_http_basic_auth_headers(self, httpx_mock: HTTPXMock):
        """Test that HTTP Basic auth sets correct Authorization header."""
        auth = AuthConfig(
            auth_type=AuthType.HTTP_BASIC,
            username="user",
            password="pass",
        )

        httpx_mock.add_response(url="https://api.example.com/test", json={"ok": True})

        async with AuthenticatedClient("https://api.example.com", auth=auth) as client:
            await client.get("/test")

        request = httpx_mock.get_request()
        expected_credentials = base64.b64encode(b"user:pass").decode()
        assert request.headers["Authorization"] == f"Basic {expected_credentials}"


class TestAuthenticatedClientHttpBearer:
    """Tests for HTTP Bearer authentication."""

    async def test_http_bearer_auth_headers(self, httpx_mock: HTTPXMock):
        """Test that HTTP Bearer auth sets correct Authorization header."""
        auth = AuthConfig(
            auth_type=AuthType.HTTP_BEARER,
            bearer_token="my-token-123",
        )

        httpx_mock.add_response(url="https://api.example.com/test", json={"ok": True})

        async with AuthenticatedClient("https://api.example.com", auth=auth) as client:
            await client.get("/test")

        request = httpx_mock.get_request()
        assert request.headers["Authorization"] == "Bearer my-token-123"


class TestAuthenticatedClientApiKey:
    """Tests for API Key authentication."""

    async def test_api_key_in_header(self, httpx_mock: HTTPXMock):
        """Test that API key is sent in header."""
        auth = AuthConfig(
            auth_type=AuthType.API_KEY_HEADER,
            api_key="my-api-key",
            api_key_name="X-API-Key",
        )

        httpx_mock.add_response(url="https://api.example.com/test", json={"ok": True})

        async with AuthenticatedClient("https://api.example.com", auth=auth) as client:
            await client.get("/test")

        request = httpx_mock.get_request()
        assert request.headers["X-API-Key"] == "my-api-key"

    async def test_api_key_in_header_custom_name(self, httpx_mock: HTTPXMock):
        """Test that API key uses custom header name."""
        auth = AuthConfig(
            auth_type=AuthType.API_KEY_HEADER,
            api_key="my-api-key",
            api_key_name="X-Custom-Auth",
        )

        httpx_mock.add_response(url="https://api.example.com/test", json={"ok": True})

        async with AuthenticatedClient("https://api.example.com", auth=auth) as client:
            await client.get("/test")

        request = httpx_mock.get_request()
        assert request.headers["X-Custom-Auth"] == "my-api-key"

    async def test_api_key_in_query_param(self, httpx_mock: HTTPXMock):
        """Test that API key is sent in query parameter."""
        auth = AuthConfig(
            auth_type=AuthType.API_KEY_QUERY,
            api_key="my-api-key",
            api_key_name="api_key",
        )

        httpx_mock.add_response(json={"ok": True})

        async with AuthenticatedClient("https://api.example.com", auth=auth) as client:
            await client.get("/test")

        request = httpx_mock.get_request()
        assert "api_key=my-api-key" in str(request.url)

    async def test_api_key_in_cookie(self, httpx_mock: HTTPXMock):
        """Test that API key is set as a cookie."""
        auth = AuthConfig(
            auth_type=AuthType.API_KEY_COOKIE,
            api_key="my-api-key",
            api_key_name="session_token",
        )

        httpx_mock.add_response(json={"ok": True})

        async with AuthenticatedClient("https://api.example.com", auth=auth) as client:
            # Cookie should be set during authentication
            assert client._client.cookies.get("session_token") == "my-api-key"

            await client.get("/test")

        request = httpx_mock.get_request()
        # Check that cookie is sent with request
        assert "session_token=my-api-key" in request.headers.get("cookie", "")


class TestAuthenticatedClientOAuth2Password:
    """Tests for OAuth2 Password flow authentication."""

    async def test_oauth2_password_with_token_url(self, httpx_mock: HTTPXMock):
        """Test OAuth2 password flow with token_url returns access token."""
        auth = AuthConfig(
            auth_type=AuthType.OAUTH2_PASSWORD,
            username="user",
            password="pass",
            token_url="https://auth.example.com/oauth/token",
            scope="read write",
        )

        # Mock the token endpoint
        httpx_mock.add_response(
            url="https://auth.example.com/oauth/token",
            json={"access_token": "oauth-token-123", "token_type": "Bearer"},
        )

        # Mock the API endpoint
        httpx_mock.add_response(
            url="https://api.example.com/test",
            json={"ok": True},
        )

        async with AuthenticatedClient("https://api.example.com", auth=auth) as client:
            assert client.auth._access_token == "oauth-token-123"
            assert client.auth._token_type == "Bearer"

            await client.get("/test")

        # Check token request was made correctly
        requests = httpx_mock.get_requests()
        token_request = requests[0]
        assert token_request.url == "https://auth.example.com/oauth/token"
        assert b"grant_type=password" in token_request.content
        assert b"username=user" in token_request.content
        assert b"password=pass" in token_request.content

        # Check API request has Authorization header
        api_request = requests[1]
        assert api_request.headers["Authorization"] == "Bearer oauth-token-123"

    async def test_oauth2_password_with_relative_token_url(self, httpx_mock: HTTPXMock):
        """Test OAuth2 password flow with relative token_url."""
        auth = AuthConfig(
            auth_type=AuthType.OAUTH2_PASSWORD,
            username="user",
            password="pass",
            token_url="/oauth/token",
        )

        httpx_mock.add_response(
            url="https://api.example.com/oauth/token",
            json={"access_token": "token-456", "token_type": "Bearer"},
        )

        async with AuthenticatedClient("https://api.example.com", auth=auth) as client:
            assert client.auth._access_token == "token-456"

    async def test_oauth2_password_with_login_url(self, httpx_mock: HTTPXMock):
        """Test OAuth2 password flow with login_url (cookie-based)."""
        auth = AuthConfig(
            auth_type=AuthType.OAUTH2_PASSWORD,
            username="user",
            password="pass",
            login_url="https://api.example.com/login",
        )

        # Mock the login endpoint - it sets cookies
        httpx_mock.add_response(
            url="https://api.example.com/login",
            status_code=200,
        )

        async with AuthenticatedClient("https://api.example.com", auth=auth):
            # Login should have been called
            pass

        request = httpx_mock.get_request()
        assert request.url == "https://api.example.com/login"
        assert b"username=user" in request.content
        assert b"password=pass" in request.content
        assert request.headers["Content-Type"] == "application/x-www-form-urlencoded"

    async def test_oauth2_password_with_relative_login_url(self, httpx_mock: HTTPXMock):
        """Test OAuth2 password flow with relative login_url."""
        auth = AuthConfig(
            auth_type=AuthType.OAUTH2_PASSWORD,
            username="user",
            password="pass",
            login_url="/auth/login",
        )

        httpx_mock.add_response(
            url="https://api.example.com/auth/login",
            status_code=204,
        )

        async with AuthenticatedClient("https://api.example.com", auth=auth):
            pass

        request = httpx_mock.get_request()
        assert str(request.url) == "https://api.example.com/auth/login"

    async def test_oauth2_password_missing_url_raises_error(self, httpx_mock: HTTPXMock):
        """Test that OAuth2 password flow without token_url or login_url raises error."""
        auth = AuthConfig(
            auth_type=AuthType.OAUTH2_PASSWORD,
            username="user",
            password="pass",
        )

        with pytest.raises(AuthenticationError) as exc_info:
            async with AuthenticatedClient("https://api.example.com", auth=auth):
                pass

        assert "requires --token-url or --login-url" in str(exc_info.value)

    async def test_oauth2_password_token_failure(self, httpx_mock: HTTPXMock):
        """Test that failed token request raises AuthenticationError."""
        auth = AuthConfig(
            auth_type=AuthType.OAUTH2_PASSWORD,
            username="user",
            password="wrong_pass",
            token_url="https://auth.example.com/oauth/token",
        )

        httpx_mock.add_response(
            url="https://auth.example.com/oauth/token",
            status_code=401,
            json={"error": "invalid_grant", "error_description": "Invalid credentials"},
        )

        with pytest.raises(AuthenticationError) as exc_info:
            async with AuthenticatedClient("https://api.example.com", auth=auth):
                pass

        assert "Token request failed (401)" in str(exc_info.value)
        assert "Invalid credentials" in str(exc_info.value)

    async def test_oauth2_password_login_failure(self, httpx_mock: HTTPXMock):
        """Test that failed login request raises AuthenticationError."""
        auth = AuthConfig(
            auth_type=AuthType.OAUTH2_PASSWORD,
            username="user",
            password="wrong_pass",
            login_url="https://api.example.com/login",
        )

        httpx_mock.add_response(
            url="https://api.example.com/login",
            status_code=403,
            json={"detail": "Forbidden"},
        )

        with pytest.raises(AuthenticationError) as exc_info:
            async with AuthenticatedClient("https://api.example.com", auth=auth):
                pass

        assert "Login failed (403)" in str(exc_info.value)
        assert "Forbidden" in str(exc_info.value)


class TestAuthenticatedClientOAuth2ClientCredentials:
    """Tests for OAuth2 Client Credentials flow authentication."""

    async def test_oauth2_client_credentials_flow(self, httpx_mock: HTTPXMock):
        """Test OAuth2 client credentials flow gets access token."""
        auth = AuthConfig(
            auth_type=AuthType.OAUTH2_CLIENT_CREDENTIALS,
            client_id="client123",
            client_secret="secret456",
            token_url="https://auth.example.com/oauth/token",
            scope="api:read api:write",
        )

        httpx_mock.add_response(
            url="https://auth.example.com/oauth/token",
            json={"access_token": "client-token-789", "token_type": "Bearer"},
        )

        httpx_mock.add_response(
            url="https://api.example.com/test",
            json={"ok": True},
        )

        async with AuthenticatedClient("https://api.example.com", auth=auth) as client:
            assert client.auth._access_token == "client-token-789"
            assert client.auth._token_type == "Bearer"

            await client.get("/test")

        requests = httpx_mock.get_requests()
        token_request = requests[0]
        assert b"grant_type=client_credentials" in token_request.content
        assert b"client_id=client123" in token_request.content
        assert b"client_secret=secret456" in token_request.content

        api_request = requests[1]
        assert api_request.headers["Authorization"] == "Bearer client-token-789"

    async def test_oauth2_client_credentials_missing_token_url(self, httpx_mock: HTTPXMock):
        """Test that client credentials flow without token_url raises error."""
        auth = AuthConfig(
            auth_type=AuthType.OAUTH2_CLIENT_CREDENTIALS,
            client_id="client123",
            client_secret="secret456",
        )

        with pytest.raises(AuthenticationError) as exc_info:
            async with AuthenticatedClient("https://api.example.com", auth=auth):
                pass

        assert "requires --token-url" in str(exc_info.value)

    async def test_oauth2_client_credentials_failure(self, httpx_mock: HTTPXMock):
        """Test that failed client credentials request raises AuthenticationError."""
        auth = AuthConfig(
            auth_type=AuthType.OAUTH2_CLIENT_CREDENTIALS,
            client_id="invalid_client",
            client_secret="wrong_secret",
            token_url="https://auth.example.com/oauth/token",
        )

        httpx_mock.add_response(
            url="https://auth.example.com/oauth/token",
            status_code=401,
            json={"error": "invalid_client"},
        )

        with pytest.raises(AuthenticationError) as exc_info:
            async with AuthenticatedClient("https://api.example.com", auth=auth):
                pass

        assert "Client credentials failed (401)" in str(exc_info.value)

    async def test_oauth2_custom_token_type(self, httpx_mock: HTTPXMock):
        """Test that custom token_type from response is used."""
        auth = AuthConfig(
            auth_type=AuthType.OAUTH2_CLIENT_CREDENTIALS,
            client_id="client123",
            client_secret="secret456",
            token_url="https://auth.example.com/oauth/token",
        )

        httpx_mock.add_response(
            url="https://auth.example.com/oauth/token",
            json={"access_token": "mac-token", "token_type": "MAC"},
        )

        httpx_mock.add_response(
            url="https://api.example.com/test",
            json={"ok": True},
        )

        async with AuthenticatedClient("https://api.example.com", auth=auth) as client:
            assert client.auth._token_type == "MAC"
            await client.get("/test")

        api_request = httpx_mock.get_requests()[1]
        assert api_request.headers["Authorization"] == "MAC mac-token"


class TestAuthenticatedClientRequest:
    """Tests for the request method."""

    async def test_request_merges_headers(self, httpx_mock: HTTPXMock):
        """Test that request merges auth headers with provided headers."""
        auth = AuthConfig(
            auth_type=AuthType.HTTP_BEARER,
            bearer_token="token123",
        )

        httpx_mock.add_response(json={"ok": True})

        async with AuthenticatedClient("https://api.example.com", auth=auth) as client:
            await client.request(
                "GET",
                "/test",
                headers={"X-Custom-Header": "custom-value"},
            )

        request = httpx_mock.get_request()
        assert request.headers["Authorization"] == "Bearer token123"
        assert request.headers["X-Custom-Header"] == "custom-value"

    async def test_request_merges_params(self, httpx_mock: HTTPXMock):
        """Test that request merges auth params with provided params."""
        auth = AuthConfig(
            auth_type=AuthType.API_KEY_QUERY,
            api_key="my-api-key",
            api_key_name="api_key",
        )

        httpx_mock.add_response(json={"ok": True})

        async with AuthenticatedClient("https://api.example.com", auth=auth) as client:
            await client.request(
                "GET",
                "/test",
                params={"filter": "active"},
            )

        request = httpx_mock.get_request()
        url_str = str(request.url)
        assert "api_key=my-api-key" in url_str
        assert "filter=active" in url_str

    async def test_request_with_json_body(self, httpx_mock: HTTPXMock):
        """Test that request passes JSON body."""
        import json

        httpx_mock.add_response(json={"created": True})

        async with AuthenticatedClient("https://api.example.com") as client:
            await client.post("/items", json={"name": "test"})

        request = httpx_mock.get_request()
        assert json.loads(request.content) == {"name": "test"}

    async def test_request_with_form_data(self, httpx_mock: HTTPXMock):
        """Test that request passes form data."""
        httpx_mock.add_response(json={"ok": True})

        async with AuthenticatedClient("https://api.example.com") as client:
            await client.post("/submit", data={"field": "value"})

        request = httpx_mock.get_request()
        assert b"field=value" in request.content


class TestAuthenticatedClientHttpMethods:
    """Tests for HTTP method convenience methods."""

    async def test_get_method(self, httpx_mock: HTTPXMock):
        """Test GET convenience method."""
        httpx_mock.add_response(json={"items": []})

        async with AuthenticatedClient("https://api.example.com") as client:
            await client.get("/items")

        request = httpx_mock.get_request()
        assert request.method == "GET"
        assert str(request.url) == "https://api.example.com/items"

    async def test_post_method(self, httpx_mock: HTTPXMock):
        """Test POST convenience method."""
        httpx_mock.add_response(json={"id": 1}, status_code=201)

        async with AuthenticatedClient("https://api.example.com") as client:
            await client.post("/items", json={"name": "test"})

        request = httpx_mock.get_request()
        assert request.method == "POST"

    async def test_put_method(self, httpx_mock: HTTPXMock):
        """Test PUT convenience method."""
        httpx_mock.add_response(json={"updated": True})

        async with AuthenticatedClient("https://api.example.com") as client:
            await client.put("/items/1", json={"name": "updated"})

        request = httpx_mock.get_request()
        assert request.method == "PUT"

    async def test_patch_method(self, httpx_mock: HTTPXMock):
        """Test PATCH convenience method."""
        httpx_mock.add_response(json={"patched": True})

        async with AuthenticatedClient("https://api.example.com") as client:
            await client.patch("/items/1", json={"name": "patched"})

        request = httpx_mock.get_request()
        assert request.method == "PATCH"

    async def test_delete_method(self, httpx_mock: HTTPXMock):
        """Test DELETE convenience method."""
        httpx_mock.add_response(status_code=204)

        async with AuthenticatedClient("https://api.example.com") as client:
            await client.delete("/items/1")

        request = httpx_mock.get_request()
        assert request.method == "DELETE"


class TestAuthenticatedClientHelperMethods:
    """Tests for helper methods."""

    def test_get_domain_extraction(self):
        """Test _get_domain extracts hostname from base_url."""
        client = AuthenticatedClient("https://api.example.com/v1")
        assert client._get_domain() == "api.example.com"

    def test_get_domain_with_port(self):
        """Test _get_domain with port in URL."""
        client = AuthenticatedClient("http://localhost:8080/api")
        assert client._get_domain() == "localhost"

    def test_get_domain_fallback(self):
        """Test _get_domain fallback to localhost."""
        # This is a edge case - unusual URL format
        client = AuthenticatedClient("")
        client.base_url = ""
        assert client._get_domain() == "localhost"

    def test_get_auth_headers_none(self):
        """Test _get_auth_headers returns empty dict for NONE auth type."""
        client = AuthenticatedClient("https://api.example.com")
        assert client._get_auth_headers() == {}

    def test_get_auth_params_none(self):
        """Test _get_auth_params returns empty dict for non-query auth types."""
        client = AuthenticatedClient("https://api.example.com")
        assert client._get_auth_params() == {}

    def test_extract_error_json_detail(self):
        """Test _extract_error extracts 'detail' from JSON response."""
        client = AuthenticatedClient("https://api.example.com")
        response = httpx.Response(
            status_code=400,
            json={"detail": "Bad request message"},
        )
        assert client._extract_error(response) == "Bad request message"

    def test_extract_error_json_error_description(self):
        """Test _extract_error extracts 'error_description' from JSON response."""
        client = AuthenticatedClient("https://api.example.com")
        response = httpx.Response(
            status_code=401,
            json={"error_description": "OAuth error description"},
        )
        assert client._extract_error(response) == "OAuth error description"

    def test_extract_error_json_error(self):
        """Test _extract_error extracts 'error' from JSON response."""
        client = AuthenticatedClient("https://api.example.com")
        response = httpx.Response(
            status_code=401,
            json={"error": "invalid_grant"},
        )
        assert client._extract_error(response) == "invalid_grant"

    def test_extract_error_text_fallback(self):
        """Test _extract_error falls back to text for non-JSON response."""
        client = AuthenticatedClient("https://api.example.com")
        response = httpx.Response(
            status_code=500,
            text="Internal Server Error",
        )
        assert "Internal Server Error" in client._extract_error(response)


# =============================================================================
# AuthenticationError Tests
# =============================================================================


class TestAuthenticationError:
    """Tests for the AuthenticationError exception."""

    def test_authentication_error_is_exception(self):
        """Test that AuthenticationError is an Exception."""
        error = AuthenticationError("Test error")
        assert isinstance(error, Exception)

    def test_authentication_error_message(self):
        """Test that AuthenticationError stores message."""
        error = AuthenticationError("Authentication failed")
        assert str(error) == "Authentication failed"

    def test_authentication_error_can_be_raised(self):
        """Test that AuthenticationError can be raised and caught."""
        with pytest.raises(AuthenticationError) as exc_info:
            raise AuthenticationError("Test raise")

        assert str(exc_info.value) == "Test raise"


# =============================================================================
# Integration-style Tests (testing multiple components together)
# =============================================================================


class TestAuthFlowIntegration:
    """Integration tests for complete authentication flows."""

    async def test_no_auth_request(self, httpx_mock: HTTPXMock):
        """Test request without any authentication."""
        httpx_mock.add_response(json={"public": True})

        async with AuthenticatedClient("https://api.example.com") as client:
            response = await client.get("/public")

        request = httpx_mock.get_request()
        assert "Authorization" not in request.headers
        assert response.json() == {"public": True}

    async def test_oauth2_full_flow(self, httpx_mock: HTTPXMock):
        """Test complete OAuth2 flow from token to API request."""
        auth = AuthConfig(
            auth_type=AuthType.OAUTH2_PASSWORD,
            username="user",
            password="pass",
            token_url="https://auth.example.com/token",
        )

        # Token endpoint
        httpx_mock.add_response(
            url="https://auth.example.com/token",
            json={"access_token": "full-flow-token", "token_type": "Bearer"},
        )

        # First API call
        httpx_mock.add_response(
            url="https://api.example.com/users/me",
            json={"id": 1, "name": "Test User"},
        )

        # Second API call
        httpx_mock.add_response(
            url="https://api.example.com/items",
            json={"items": [{"id": 1}]},
        )

        async with AuthenticatedClient("https://api.example.com", auth=auth) as client:
            await client.get("/users/me")
            await client.get("/items")

        requests = httpx_mock.get_requests()
        assert len(requests) == 3

        # Both API requests should have the token
        assert requests[1].headers["Authorization"] == "Bearer full-flow-token"
        assert requests[2].headers["Authorization"] == "Bearer full-flow-token"

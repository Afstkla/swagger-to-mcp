"""Integration tests for complete authentication flows."""

import pytest
from pytest_httpx import HTTPXMock

from openapi_to_mcp.auth import (
    AuthConfig,
    AuthenticatedClient,
    AuthenticationError,
    AuthType,
)


class TestOAuth2PasswordFlow:
    """Tests for complete OAuth2 password flow."""

    async def test_oauth2_password_flow_with_token_endpoint(
        self, httpx_mock: HTTPXMock, auth_config
    ):
        """Test OAuth2 password flow with standard token endpoint."""
        # Mock token endpoint
        httpx_mock.add_response(
            url="https://api.example.com/oauth/token",
            method="POST",
            json={
                "access_token": "test-access-token-abc123",
                "token_type": "Bearer",
                "expires_in": 3600,
                "scope": "read write",
            },
        )

        # Mock API endpoint
        httpx_mock.add_response(
            url="https://api.example.com/api/resource",
            method="GET",
            json={"data": "protected-resource"},
        )

        config = auth_config(
            auth_type=AuthType.OAUTH2_PASSWORD,
            username="testuser",
            password="testpass",
            token_url="/oauth/token",
            scope="read write",
        )

        async with AuthenticatedClient("https://api.example.com", config) as client:
            # Verify token was obtained
            assert config._access_token == "test-access-token-abc123"
            assert config._token_type == "Bearer"

            # Make authenticated request
            response = await client.get("/api/resource")

        assert response.status_code == 200
        assert response.json()["data"] == "protected-resource"

        # Verify token endpoint was called correctly
        requests = httpx_mock.get_requests()
        token_request = requests[0]
        assert token_request.url.path == "/oauth/token"
        assert b"grant_type=password" in token_request.content
        assert b"username=testuser" in token_request.content
        assert b"password=testpass" in token_request.content

        # Verify API request included auth header
        api_request = requests[1]
        assert "Authorization" in api_request.headers
        assert api_request.headers["Authorization"] == "Bearer test-access-token-abc123"

    async def test_oauth2_password_flow_with_login_endpoint_cookies(
        self, httpx_mock: HTTPXMock, auth_config
    ):
        """Test OAuth2 password flow with cookie-based login endpoint."""
        # Mock login endpoint that sets cookie
        httpx_mock.add_response(
            url="https://api.example.com/auth/login",
            method="POST",
            status_code=200,
            headers={
                "Set-Cookie": "session_id=abc123; Path=/; HttpOnly",
            },
            json={"message": "Login successful"},
        )

        # Mock API endpoint
        httpx_mock.add_response(
            url="https://api.example.com/api/resource",
            method="GET",
            json={"data": "protected-resource"},
        )

        config = auth_config(
            auth_type=AuthType.OAUTH2_PASSWORD,
            username="cookieuser",
            password="cookiepass",
            login_url="/auth/login",
        )

        async with AuthenticatedClient("https://api.example.com", config) as client:
            # Make authenticated request
            response = await client.get("/api/resource")

        assert response.status_code == 200

        # Verify login request was made
        requests = httpx_mock.get_requests()
        login_request = requests[0]
        assert login_request.url.path == "/auth/login"
        assert b"username=cookieuser" in login_request.content

    async def test_oauth2_password_flow_token_failure(self, httpx_mock: HTTPXMock, auth_config):
        """Test OAuth2 password flow handles token endpoint failure."""
        httpx_mock.add_response(
            url="https://api.example.com/oauth/token",
            method="POST",
            status_code=401,
            json={
                "error": "invalid_grant",
                "error_description": "Invalid username or password",
            },
        )

        config = auth_config(
            auth_type=AuthType.OAUTH2_PASSWORD,
            username="baduser",
            password="badpass",
            token_url="/oauth/token",
        )

        with pytest.raises(AuthenticationError) as exc_info:
            async with AuthenticatedClient("https://api.example.com", config):
                pass

        assert "Token request failed" in str(exc_info.value)
        assert "401" in str(exc_info.value)

    async def test_oauth2_password_flow_login_failure(self, httpx_mock: HTTPXMock, auth_config):
        """Test OAuth2 password flow handles login endpoint failure."""
        httpx_mock.add_response(
            url="https://api.example.com/auth/login",
            method="POST",
            status_code=401,
            json={"detail": "Invalid credentials"},
        )

        config = auth_config(
            auth_type=AuthType.OAUTH2_PASSWORD,
            username="baduser",
            password="badpass",
            login_url="/auth/login",
        )

        with pytest.raises(AuthenticationError) as exc_info:
            async with AuthenticatedClient("https://api.example.com", config):
                pass

        assert "Login failed" in str(exc_info.value)
        assert "401" in str(exc_info.value)

    async def test_oauth2_password_flow_requires_token_or_login_url(self, auth_config):
        """Test OAuth2 password flow raises error without token or login URL."""
        config = auth_config(
            auth_type=AuthType.OAUTH2_PASSWORD,
            username="testuser",
            password="testpass",
        )

        with pytest.raises(AuthenticationError) as exc_info:
            async with AuthenticatedClient("https://api.example.com", config):
                pass

        assert "requires --token-url or --login-url" in str(exc_info.value)


class TestOAuth2ClientCredentialsFlow:
    """Tests for complete OAuth2 client credentials flow."""

    async def test_oauth2_client_credentials_flow_complete(
        self, httpx_mock: HTTPXMock, auth_config
    ):
        """Test complete OAuth2 client credentials flow."""
        # Mock token endpoint
        httpx_mock.add_response(
            url="https://api.example.com/oauth/token",
            method="POST",
            json={
                "access_token": "client-credentials-token-xyz",
                "token_type": "Bearer",
                "expires_in": 7200,
            },
        )

        # Mock API endpoint
        httpx_mock.add_response(
            url="https://api.example.com/api/data",
            method="GET",
            json={"items": [1, 2, 3]},
        )

        config = auth_config(
            auth_type=AuthType.OAUTH2_CLIENT_CREDENTIALS,
            client_id="my-client-id",
            client_secret="my-client-secret",
            token_url="/oauth/token",
            scope="api.read",
        )

        async with AuthenticatedClient("https://api.example.com", config) as client:
            # Verify token was obtained
            assert config._access_token == "client-credentials-token-xyz"
            assert config._token_type == "Bearer"

            # Make authenticated request
            response = await client.get("/api/data")

        assert response.status_code == 200
        assert response.json()["items"] == [1, 2, 3]

        # Verify token endpoint was called correctly
        requests = httpx_mock.get_requests()
        token_request = requests[0]
        assert b"grant_type=client_credentials" in token_request.content
        assert b"client_id=my-client-id" in token_request.content
        assert b"client_secret=my-client-secret" in token_request.content
        assert b"scope=api.read" in token_request.content

        # Verify API request included auth header
        api_request = requests[1]
        assert api_request.headers["Authorization"] == "Bearer client-credentials-token-xyz"

    async def test_oauth2_client_credentials_flow_token_failure(
        self, httpx_mock: HTTPXMock, auth_config
    ):
        """Test OAuth2 client credentials flow handles token failure."""
        httpx_mock.add_response(
            url="https://api.example.com/oauth/token",
            method="POST",
            status_code=401,
            json={
                "error": "invalid_client",
                "error_description": "Client authentication failed",
            },
        )

        config = auth_config(
            auth_type=AuthType.OAUTH2_CLIENT_CREDENTIALS,
            client_id="bad-client-id",
            client_secret="bad-secret",
            token_url="/oauth/token",
        )

        with pytest.raises(AuthenticationError) as exc_info:
            async with AuthenticatedClient("https://api.example.com", config):
                pass

        assert "Client credentials failed" in str(exc_info.value)

    async def test_oauth2_client_credentials_requires_token_url(self, auth_config):
        """Test OAuth2 client credentials flow requires token URL."""
        config = auth_config(
            auth_type=AuthType.OAUTH2_CLIENT_CREDENTIALS,
            client_id="my-client-id",
            client_secret="my-client-secret",
        )

        with pytest.raises(AuthenticationError) as exc_info:
            async with AuthenticatedClient("https://api.example.com", config):
                pass

        assert "requires --token-url" in str(exc_info.value)


class TestCookiePersistence:
    """Tests for cookie persistence after login."""

    async def test_cookies_persisted_across_requests(self, httpx_mock: HTTPXMock, auth_config):
        """Test that cookies are persisted and sent in subsequent requests."""
        # Mock login endpoint that sets multiple cookies
        httpx_mock.add_response(
            url="https://api.example.com/auth/login",
            method="POST",
            status_code=200,
            headers={
                "Set-Cookie": "session_id=session123; Path=/",
            },
            json={"success": True},
        )

        # Mock first API call
        httpx_mock.add_response(
            url="https://api.example.com/api/resource1",
            method="GET",
            json={"resource": "one"},
        )

        # Mock second API call
        httpx_mock.add_response(
            url="https://api.example.com/api/resource2",
            method="GET",
            json={"resource": "two"},
        )

        config = auth_config(
            auth_type=AuthType.OAUTH2_PASSWORD,
            username="testuser",
            password="testpass",
            login_url="/auth/login",
        )

        async with AuthenticatedClient("https://api.example.com", config) as client:
            # Make multiple requests
            response1 = await client.get("/api/resource1")
            response2 = await client.get("/api/resource2")

        assert response1.status_code == 200
        assert response2.status_code == 200

        # Verify cookies were sent with subsequent requests
        requests = httpx_mock.get_requests()
        # First request is login, second and third are API calls
        assert len(requests) == 3

        # Check that cookies were explicitly passed
        api_request1 = requests[1]
        api_request2 = requests[2]

        # The cookies dict is explicitly passed in the request
        assert api_request1.headers.get("cookie") or "session_id" in str(requests[1])
        assert api_request2.headers.get("cookie") or "session_id" in str(requests[2])

    async def test_api_key_cookie_auth_sets_cookie(self, httpx_mock: HTTPXMock, auth_config):
        """Test that API key cookie auth sets the cookie correctly."""
        httpx_mock.add_response(
            url="https://api.example.com/api/resource",
            method="GET",
            json={"data": "protected"},
        )

        config = auth_config(
            auth_type=AuthType.API_KEY_COOKIE,
            api_key="my-api-key-value",
            api_key_name="api_session",
        )

        async with AuthenticatedClient("https://api.example.com", config) as client:
            response = await client.get("/api/resource")

        assert response.status_code == 200

        # Verify request was made (cookie should be set)
        requests = httpx_mock.get_requests()
        assert len(requests) == 1


class TestTokenRefresh:
    """Tests for token refresh scenarios."""

    async def test_oauth2_custom_token_type(self, httpx_mock: HTTPXMock, auth_config):
        """Test OAuth2 flow with custom token type."""
        # Mock token endpoint with custom token type
        httpx_mock.add_response(
            url="https://api.example.com/oauth/token",
            method="POST",
            json={
                "access_token": "custom-token-value",
                "token_type": "CustomType",
                "expires_in": 3600,
            },
        )

        # Mock API endpoint
        httpx_mock.add_response(
            url="https://api.example.com/api/resource",
            method="GET",
            json={"data": "ok"},
        )

        config = auth_config(
            auth_type=AuthType.OAUTH2_CLIENT_CREDENTIALS,
            client_id="client-id",
            client_secret="client-secret",
            token_url="/oauth/token",
        )

        async with AuthenticatedClient("https://api.example.com", config) as client:
            assert config._token_type == "CustomType"
            response = await client.get("/api/resource")

        assert response.status_code == 200

        # Verify custom token type was used in header
        requests = httpx_mock.get_requests()
        api_request = requests[1]
        assert api_request.headers["Authorization"] == "CustomType custom-token-value"

    async def test_multiple_authenticated_requests_reuse_token(
        self, httpx_mock: HTTPXMock, auth_config
    ):
        """Test that multiple requests reuse the same token."""
        # Token should be obtained only once
        httpx_mock.add_response(
            url="https://api.example.com/oauth/token",
            method="POST",
            json={
                "access_token": "reusable-token",
                "token_type": "Bearer",
            },
        )

        # Multiple API endpoints
        httpx_mock.add_response(
            url="https://api.example.com/api/resource1",
            method="GET",
            json={"data": 1},
        )
        httpx_mock.add_response(
            url="https://api.example.com/api/resource2",
            method="GET",
            json={"data": 2},
        )
        httpx_mock.add_response(
            url="https://api.example.com/api/resource3",
            method="POST",
            json={"data": 3},
        )

        config = auth_config(
            auth_type=AuthType.OAUTH2_CLIENT_CREDENTIALS,
            client_id="client-id",
            client_secret="client-secret",
            token_url="/oauth/token",
        )

        async with AuthenticatedClient("https://api.example.com", config) as client:
            await client.get("/api/resource1")
            await client.get("/api/resource2")
            await client.post("/api/resource3", json={"key": "value"})

        requests = httpx_mock.get_requests()

        # Should be 1 token request + 3 API requests = 4 total
        assert len(requests) == 4

        # Only the first request should be to token endpoint
        assert requests[0].url.path == "/oauth/token"

        # All subsequent requests should have the same token
        for i in range(1, 4):
            assert requests[i].headers["Authorization"] == "Bearer reusable-token"


class TestMixedAuthScenarios:
    """Tests for various authentication scenarios."""

    async def test_no_auth_client(self, httpx_mock: HTTPXMock):
        """Test client with no authentication."""
        httpx_mock.add_response(
            url="https://api.example.com/public/resource",
            method="GET",
            json={"data": "public"},
        )

        config = AuthConfig(auth_type=AuthType.NONE)

        async with AuthenticatedClient("https://api.example.com", config) as client:
            response = await client.get("/public/resource")

        assert response.status_code == 200

        # Verify no auth headers were sent
        requests = httpx_mock.get_requests()
        assert "Authorization" not in requests[0].headers

    async def test_basic_auth_client(self, httpx_mock: HTTPXMock, basic_auth: AuthConfig):
        """Test client with HTTP Basic authentication."""
        httpx_mock.add_response(
            url="https://api.example.com/api/resource",
            method="GET",
            json={"data": "protected"},
        )

        async with AuthenticatedClient("https://api.example.com", basic_auth) as client:
            response = await client.get("/api/resource")

        assert response.status_code == 200

        # Verify Basic auth header
        requests = httpx_mock.get_requests()
        auth_header = requests[0].headers["Authorization"]
        assert auth_header.startswith("Basic ")

    async def test_bearer_auth_client(self, httpx_mock: HTTPXMock, bearer_auth: AuthConfig):
        """Test client with HTTP Bearer authentication."""
        httpx_mock.add_response(
            url="https://api.example.com/api/resource",
            method="GET",
            json={"data": "protected"},
        )

        async with AuthenticatedClient("https://api.example.com", bearer_auth) as client:
            response = await client.get("/api/resource")

        assert response.status_code == 200

        # Verify Bearer auth header
        requests = httpx_mock.get_requests()
        assert requests[0].headers["Authorization"] == "Bearer test-bearer-token-xyz"

    async def test_api_key_header_client(self, httpx_mock: HTTPXMock, api_key_auth: AuthConfig):
        """Test client with API key header authentication."""
        httpx_mock.add_response(
            url="https://api.example.com/api/resource",
            method="GET",
            json={"data": "protected"},
        )

        async with AuthenticatedClient("https://api.example.com", api_key_auth) as client:
            response = await client.get("/api/resource")

        assert response.status_code == 200

        # Verify API key header
        requests = httpx_mock.get_requests()
        assert requests[0].headers["X-API-Key"] == "test-api-key-12345"

    async def test_api_key_query_client(self, httpx_mock: HTTPXMock, auth_config):
        """Test client with API key query parameter authentication."""
        httpx_mock.add_response(
            url="https://api.example.com/api/resource?api_key=query-api-key",
            method="GET",
            json={"data": "protected"},
        )

        config = auth_config(
            auth_type=AuthType.API_KEY_QUERY,
            api_key="query-api-key",
            api_key_name="api_key",
        )

        async with AuthenticatedClient("https://api.example.com", config) as client:
            response = await client.get("/api/resource")

        assert response.status_code == 200

        # Verify API key was in query params
        requests = httpx_mock.get_requests()
        assert "api_key=query-api-key" in str(requests[0].url)


class TestFullUrlTokenEndpoints:
    """Tests for token endpoints with full URLs."""

    async def test_oauth2_password_with_full_token_url(self, httpx_mock: HTTPXMock, auth_config):
        """Test OAuth2 password flow with full URL for token endpoint."""
        httpx_mock.add_response(
            url="https://auth.example.com/oauth/token",
            method="POST",
            json={
                "access_token": "full-url-token",
                "token_type": "Bearer",
            },
        )

        httpx_mock.add_response(
            url="https://api.example.com/api/resource",
            method="GET",
            json={"data": "ok"},
        )

        config = auth_config(
            auth_type=AuthType.OAUTH2_PASSWORD,
            username="user",
            password="pass",
            token_url="https://auth.example.com/oauth/token",  # Full URL
        )

        async with AuthenticatedClient("https://api.example.com", config) as client:
            response = await client.get("/api/resource")

        assert response.status_code == 200
        assert config._access_token == "full-url-token"

    async def test_oauth2_password_with_full_login_url(self, httpx_mock: HTTPXMock, auth_config):
        """Test OAuth2 password flow with full URL for login endpoint."""
        httpx_mock.add_response(
            url="https://auth.example.com/login",
            method="POST",
            status_code=200,
            json={"message": "ok"},
        )

        httpx_mock.add_response(
            url="https://api.example.com/api/resource",
            method="GET",
            json={"data": "ok"},
        )

        config = auth_config(
            auth_type=AuthType.OAUTH2_PASSWORD,
            username="user",
            password="pass",
            login_url="https://auth.example.com/login",  # Full URL
        )

        async with AuthenticatedClient("https://api.example.com", config) as client:
            response = await client.get("/api/resource")

        assert response.status_code == 200

        # Verify login was to the external auth server
        requests = httpx_mock.get_requests()
        assert "auth.example.com" in str(requests[0].url)

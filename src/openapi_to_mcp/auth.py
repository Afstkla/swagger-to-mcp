"""Authentication handling for API requests - supports all OpenAPI security schemes."""

import base64
import sys
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import httpx


class AuthType(Enum):
    """OpenAPI security scheme types."""

    NONE = "none"
    HTTP_BASIC = "http_basic"  # HTTP Basic Authentication
    HTTP_BEARER = "http_bearer"  # HTTP Bearer Token
    API_KEY_HEADER = "api_key_header"  # API Key in header
    API_KEY_QUERY = "api_key_query"  # API Key in query param
    API_KEY_COOKIE = "api_key_cookie"  # API Key in cookie
    OAUTH2_PASSWORD = "oauth2_password"  # OAuth2 Resource Owner Password
    OAUTH2_CLIENT_CREDENTIALS = "oauth2_client_credentials"  # OAuth2 Client Credentials


@dataclass
class AuthConfig:
    """Authentication configuration supporting all OpenAPI security schemes."""

    auth_type: AuthType = AuthType.NONE

    # HTTP Basic / OAuth2 Password
    username: str | None = None
    password: str | None = None

    # HTTP Bearer
    bearer_token: str | None = None

    # API Key
    api_key: str | None = None
    api_key_name: str = "X-API-Key"  # Header/query/cookie name

    # OAuth2 endpoints
    token_url: str | None = None  # For OAuth2 flows
    login_url: str | None = None  # For cookie-based login

    # OAuth2 Client Credentials
    client_id: str | None = None
    client_secret: str | None = None
    scope: str = ""

    # Stored tokens/cookies after auth
    _access_token: str | None = field(default=None, repr=False)
    _token_type: str = field(default="Bearer", repr=False)


class AuthenticatedClient:
    """HTTP client with authentication support for all OpenAPI security schemes."""

    def __init__(self, base_url: str, auth: AuthConfig | None = None, timeout: float = 60):
        self.base_url = base_url.rstrip("/")
        self.auth = auth or AuthConfig()
        self.timeout = timeout
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> "AuthenticatedClient":
        self._client = httpx.AsyncClient(timeout=self.timeout)
        await self._authenticate()
        return self

    async def __aexit__(self, *args):
        if self._client:
            await self._client.aclose()
            self._client = None

    async def _authenticate(self):
        """Perform authentication based on configured auth type."""
        match self.auth.auth_type:
            case AuthType.NONE:
                pass

            case AuthType.HTTP_BASIC:
                # Basic auth is handled per-request via headers
                pass

            case AuthType.HTTP_BEARER:
                # Bearer token is handled per-request via headers
                pass

            case AuthType.API_KEY_HEADER | AuthType.API_KEY_QUERY | AuthType.API_KEY_COOKIE:
                # API key is handled per-request
                if self.auth.auth_type == AuthType.API_KEY_COOKIE:
                    self._client.cookies.set(
                        self.auth.api_key_name, self.auth.api_key, domain=self._get_domain()
                    )

            case AuthType.OAUTH2_PASSWORD:
                await self._oauth2_password_flow()

            case AuthType.OAUTH2_CLIENT_CREDENTIALS:
                await self._oauth2_client_credentials_flow()

    async def _oauth2_password_flow(self):
        """OAuth2 Resource Owner Password Credentials flow."""
        if self.auth.login_url:
            # Cookie-based: form login that sets a session cookie
            await self._cookie_login()
        elif self.auth.token_url:
            # Standard OAuth2: POST to token URL, get access_token
            await self._token_login()
        else:
            raise AuthenticationError("OAuth2 password flow requires --token-url or --login-url")

    async def _cookie_login(self):
        """Login via form POST that sets a session cookie."""
        login_url = (
            self.auth.login_url
            if self.auth.login_url.startswith("http")
            else f"{self.base_url}{self.auth.login_url}"
        )

        print(f"Logging in to {login_url}...", file=sys.stderr)

        response = await self._client.post(
            login_url,
            data={"username": self.auth.username, "password": self.auth.password},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )

        if response.status_code not in (200, 204):
            error_detail = self._extract_error(response)
            raise AuthenticationError(f"Login failed ({response.status_code}): {error_detail}")

        cookies = dict(self._client.cookies)
        print(f"Login successful, cookies: {list(cookies.keys())}", file=sys.stderr)

    async def _token_login(self):
        """Standard OAuth2 token endpoint login."""
        token_url = (
            self.auth.token_url
            if self.auth.token_url.startswith("http")
            else f"{self.base_url}{self.auth.token_url}"
        )

        print(f"Getting token from {token_url}...", file=sys.stderr)

        response = await self._client.post(
            token_url,
            data={
                "grant_type": "password",
                "username": self.auth.username,
                "password": self.auth.password,
                "scope": self.auth.scope,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )

        if response.status_code != 200:
            error_detail = self._extract_error(response)
            raise AuthenticationError(
                f"Token request failed ({response.status_code}): {error_detail}"
            )

        token_data = response.json()
        self.auth._access_token = token_data.get("access_token")
        self.auth._token_type = token_data.get("token_type", "Bearer")

        print(f"Got {self.auth._token_type} token", file=sys.stderr)

    async def _oauth2_client_credentials_flow(self):
        """OAuth2 Client Credentials flow for machine-to-machine auth."""
        if not self.auth.token_url:
            raise AuthenticationError("OAuth2 client credentials flow requires --token-url")

        token_url = (
            self.auth.token_url
            if self.auth.token_url.startswith("http")
            else f"{self.base_url}{self.auth.token_url}"
        )

        print(f"Getting client credentials token from {token_url}...", file=sys.stderr)

        # Client credentials can be sent in body or as Basic auth header
        response = await self._client.post(
            token_url,
            data={
                "grant_type": "client_credentials",
                "client_id": self.auth.client_id,
                "client_secret": self.auth.client_secret,
                "scope": self.auth.scope,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )

        if response.status_code != 200:
            error_detail = self._extract_error(response)
            raise AuthenticationError(
                f"Client credentials failed ({response.status_code}): {error_detail}"
            )

        token_data = response.json()
        self.auth._access_token = token_data.get("access_token")
        self.auth._token_type = token_data.get("token_type", "Bearer")

        print(f"Got {self.auth._token_type} token", file=sys.stderr)

    def _extract_error(self, response: httpx.Response) -> str:
        """Extract error message from response."""
        try:
            data = response.json()
            return (
                data.get("detail")
                or data.get("error_description")
                or data.get("error")
                or str(data)
            )
        except Exception:
            return response.text[:200]

    def _get_domain(self) -> str:
        """Extract domain from base URL."""
        from urllib.parse import urlparse

        parsed = urlparse(self.base_url)
        return parsed.hostname or "localhost"

    def _get_auth_headers(self) -> dict[str, str]:
        """Get authentication headers based on auth type."""
        headers = {}

        match self.auth.auth_type:
            case AuthType.HTTP_BASIC:
                if self.auth.username and self.auth.password:
                    credentials = f"{self.auth.username}:{self.auth.password}"
                    encoded = base64.b64encode(credentials.encode()).decode()
                    headers["Authorization"] = f"Basic {encoded}"

            case AuthType.HTTP_BEARER:
                if self.auth.bearer_token:
                    headers["Authorization"] = f"Bearer {self.auth.bearer_token}"

            case AuthType.API_KEY_HEADER:
                if self.auth.api_key:
                    headers[self.auth.api_key_name] = self.auth.api_key

            case AuthType.OAUTH2_PASSWORD | AuthType.OAUTH2_CLIENT_CREDENTIALS:
                if self.auth._access_token:
                    headers["Authorization"] = f"{self.auth._token_type} {self.auth._access_token}"

        return headers

    def _get_auth_params(self) -> dict[str, str]:
        """Get authentication query parameters."""
        params = {}

        if self.auth.auth_type == AuthType.API_KEY_QUERY and self.auth.api_key:
            params[self.auth.api_key_name] = self.auth.api_key

        return params

    async def request(
        self,
        method: str,
        path: str,
        params: dict | None = None,
        headers: dict | None = None,
        json: Any | None = None,
        data: dict | None = None,
    ) -> httpx.Response:
        """Make an authenticated request."""
        url = f"{self.base_url}{path}"

        # Merge auth headers/params with provided ones
        request_headers = self._get_auth_headers()
        if headers:
            request_headers.update(headers)

        request_params = self._get_auth_params()
        if params:
            request_params.update(params)

        # Explicitly pass cookies (httpx doesn't auto-send Domain=localhost cookies)
        cookies = dict(self._client.cookies)

        return await self._client.request(
            method=method,
            url=url,
            params=request_params or None,
            headers=request_headers or None,
            cookies=cookies or None,
            json=json,
            data=data,
        )

    async def get(self, path: str, **kwargs) -> httpx.Response:
        return await self.request("GET", path, **kwargs)

    async def post(self, path: str, **kwargs) -> httpx.Response:
        return await self.request("POST", path, **kwargs)

    async def put(self, path: str, **kwargs) -> httpx.Response:
        return await self.request("PUT", path, **kwargs)

    async def patch(self, path: str, **kwargs) -> httpx.Response:
        return await self.request("PATCH", path, **kwargs)

    async def delete(self, path: str, **kwargs) -> httpx.Response:
        return await self.request("DELETE", path, **kwargs)


class AuthenticationError(Exception):
    """Raised when authentication fails."""

    pass

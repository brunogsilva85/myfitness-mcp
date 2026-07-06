"""Minimal single-operator OAuth 2.1 authorization server for the HTTP transport.

Remote MCP connectors (Claude, ChatGPT) expect the server they connect to
speak full OAuth 2.1 with dynamic client registration and PKCE - a bare
bearer token isn't enough for their "add custom connector" flow. This
implements just enough of OAuthAuthorizationServerProvider to satisfy that,
with a single shared passcode standing in for a real login screen since
there is exactly one operator of this server.

This proves "the caller knows the passcode", not a real user identity -
network-level access control (e.g. an IP allowlist in front of this
deployment) is what actually restricts who can reach /login at all.
"""

import logging
import os
import secrets
import time
from dataclasses import dataclass

from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    OAuthAuthorizationServerProvider,
    RefreshToken,
    construct_redirect_uri,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

logger = logging.getLogger(__name__)

_DEFAULT_ACCESS_TOKEN_TTL_SECONDS = 30 * 24 * 3600  # 30 days


def _access_token_ttl_seconds() -> int:
    """Access-token lifetime in seconds, from MCP_ACCESS_TOKEN_TTL (default 30 days).

    The shared passcode is the only interactive login step, so a short-lived
    access token means re-entering the passcode every time it expires -- when a
    connector doesn't silently refresh, a 24h token forces a daily re-login.
    Default to a long lifetime; operators who want tighter tokens can lower it
    (e.g. MCP_ACCESS_TOKEN_TTL=86400 for 24h).
    """
    raw = os.environ.get("MCP_ACCESS_TOKEN_TTL", "").strip()
    if not raw:
        return _DEFAULT_ACCESS_TOKEN_TTL_SECONDS
    try:
        value = int(raw)
    except ValueError:
        logger.warning(
            "MCP_ACCESS_TOKEN_TTL=%r is not an integer; using default %ds",
            raw, _DEFAULT_ACCESS_TOKEN_TTL_SECONDS,
        )
        return _DEFAULT_ACCESS_TOKEN_TTL_SECONDS
    if value <= 0:
        logger.warning(
            "MCP_ACCESS_TOKEN_TTL=%r must be a positive number of seconds; using default %ds",
            raw, _DEFAULT_ACCESS_TOKEN_TTL_SECONDS,
        )
        return _DEFAULT_ACCESS_TOKEN_TTL_SECONDS
    return value


# Access token lifetime, resolved once at import from the environment.
ACCESS_TOKEN_TTL_SECONDS = _access_token_ttl_seconds()
AUTH_CODE_TTL_SECONDS = 300
LOGIN_TTL_SECONDS = 600

# This server has exactly one access tier, so always grant it in full rather
# than propagating whatever (possibly empty) scope the client requested -
# some MCP clients omit `scope` from the /authorize request entirely, and the
# SDK's own validate_scope(None) returns None rather than the client's
# registered default, which would otherwise silently mint a zero-scope token.
DEFAULT_SCOPES = ["mcp"]


@dataclass
class _PendingAuthorization:
    client_id: str
    params: AuthorizationParams
    created_at: float


class SinglePasscodeOAuthProvider(OAuthAuthorizationServerProvider[AuthorizationCode, RefreshToken, AccessToken]):
    """OAuth authorization server gated by one shared passcode."""

    def __init__(self, passcode: str):
        self._passcode = passcode
        self._clients: dict[str, OAuthClientInformationFull] = {}
        self._pending: dict[str, _PendingAuthorization] = {}
        self._auth_codes: dict[str, AuthorizationCode] = {}
        self._access_tokens: dict[str, AccessToken] = {}
        self._refresh_tokens: dict[str, RefreshToken] = {}

    def verify_passcode(self, candidate: str) -> bool:
        return secrets.compare_digest(candidate or "", self._passcode)

    # --- Dynamic client registration ---

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        return self._clients.get(client_id)

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        self._clients[client_info.client_id] = client_info

    # --- Authorization ("login") ---

    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        login_id = secrets.token_urlsafe(24)
        self._pending[login_id] = _PendingAuthorization(
            client_id=client.client_id, params=params, created_at=time.time()
        )
        return f"/login?login_id={login_id}"

    def get_pending(self, login_id: str) -> _PendingAuthorization | None:
        pending = self._pending.get(login_id)
        if pending is None:
            return None
        if pending.created_at + LOGIN_TTL_SECONDS < time.time():
            del self._pending[login_id]
            return None
        return pending

    def complete_login(self, login_id: str) -> str | None:
        """Issue an authorization code and return the client's redirect URL.

        Returns None if login_id is unknown or expired.
        """
        pending = self.get_pending(login_id)
        if pending is None:
            return None
        del self._pending[login_id]

        code = secrets.token_urlsafe(32)
        self._auth_codes[code] = AuthorizationCode(
            code=code,
            scopes=pending.params.scopes or DEFAULT_SCOPES,
            expires_at=time.time() + AUTH_CODE_TTL_SECONDS,
            client_id=pending.client_id,
            code_challenge=pending.params.code_challenge,
            redirect_uri=pending.params.redirect_uri,
            redirect_uri_provided_explicitly=pending.params.redirect_uri_provided_explicitly,
            resource=pending.params.resource,
        )
        return construct_redirect_uri(
            str(pending.params.redirect_uri), code=code, state=pending.params.state
        )

    # --- Token issuance ---

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> AuthorizationCode | None:
        code = self._auth_codes.get(authorization_code)
        if code is None or code.client_id != client.client_id:
            return None
        if code.expires_at < time.time():
            del self._auth_codes[authorization_code]
            return None
        return code

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode
    ) -> OAuthToken:
        self._auth_codes.pop(authorization_code.code, None)
        return self._issue_token(client.client_id, authorization_code.scopes)

    async def load_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: str
    ) -> RefreshToken | None:
        token = self._refresh_tokens.get(refresh_token)
        if token is None or token.client_id != client.client_id:
            return None
        return token

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        self._refresh_tokens.pop(refresh_token.token, None)
        return self._issue_token(client.client_id, scopes or refresh_token.scopes or DEFAULT_SCOPES)

    async def load_access_token(self, token: str) -> AccessToken | None:
        access = self._access_tokens.get(token)
        if access is None:
            return None
        if access.expires_at is not None and access.expires_at < time.time():
            del self._access_tokens[token]
            return None
        return access

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        self._access_tokens.pop(token.token, None)
        self._refresh_tokens.pop(token.token, None)

    def _issue_token(self, client_id: str, scopes: list[str]) -> OAuthToken:
        access_token = secrets.token_urlsafe(32)
        refresh_token = secrets.token_urlsafe(32)
        expires_at = int(time.time()) + ACCESS_TOKEN_TTL_SECONDS
        self._access_tokens[access_token] = AccessToken(
            token=access_token, client_id=client_id, scopes=scopes, expires_at=expires_at
        )
        self._refresh_tokens[refresh_token] = RefreshToken(
            token=refresh_token, client_id=client_id, scopes=scopes
        )
        return OAuthToken(
            access_token=access_token,
            token_type="Bearer",
            expires_in=ACCESS_TOKEN_TTL_SECONDS,
            refresh_token=refresh_token,
            scope=" ".join(scopes) or None,
        )

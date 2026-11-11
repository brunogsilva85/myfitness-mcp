"""Minimal single-operator OAuth 2.1 authorization server for the HTTP transport.

Remote MCP connectors (Claude, ChatGPT) expect the server they connect to
speak full OAuth 2.1 with dynamic client registration and PKCE - a bare
bearer token isn't enough for their "add custom connector" flow. This
implements just enough of OAuthAuthorizationServerProvider to satisfy that,
with a single shared passcode standing in for a real login screen since
there is exactly one operator of this server.

Persistence (optional): set MCP_OAUTH_STATE_FILE to keep registered clients
and issued tokens across restarts, so a container restart doesn't force the
passcode login again. Tokens are never written in clear: the file only holds
HMAC-SHA256(passcode, token), so a leaked file can't be replayed, and changing
the passcode invalidates every stored token. Short-lived state (pending logins,
authorization codes) stays in memory.
"""

import hashlib
import hmac
import json
import logging
import os
import secrets
import tempfile
import threading
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
_DEFAULT_REFRESH_TOKEN_TTL_SECONDS = 90 * 24 * 3600  # 90 days, renewed on every refresh
_STATE_VERSION = 1


def _ttl_from_env(name: str, default: int) -> int:
    """Positive integer seconds from env var `name`, else `default`."""
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        logger.warning("%s=%r is not an integer; using default %ds", name, raw, default)
        return default
    if value <= 0:
        logger.warning("%s=%r must be a positive number of seconds; using default %ds", name, raw, default)
        return default
    return value


def _access_token_ttl_seconds() -> int:
    """Access-token lifetime in seconds, from MCP_ACCESS_TOKEN_TTL (default 30 days)."""
    return _ttl_from_env("MCP_ACCESS_TOKEN_TTL", _DEFAULT_ACCESS_TOKEN_TTL_SECONDS)


ACCESS_TOKEN_TTL_SECONDS = _access_token_ttl_seconds()
REFRESH_TOKEN_TTL_SECONDS = _ttl_from_env("MCP_REFRESH_TOKEN_TTL", _DEFAULT_REFRESH_TOKEN_TTL_SECONDS)
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


@dataclass
class _StoredToken:
    client_id: str
    scopes: list[str]
    expires_at: int | None


class SinglePasscodeOAuthProvider(OAuthAuthorizationServerProvider[AuthorizationCode, RefreshToken, AccessToken]):
    """OAuth authorization server gated by one shared passcode."""

    def __init__(self, passcode: str, state_file: str | None = None):
        self._passcode = passcode
        self._hmac_key = passcode.encode()
        self._state_file = state_file if state_file is not None else (os.environ.get("MCP_OAUTH_STATE_FILE") or None)
        self._lock = threading.Lock()
        self._clients: dict[str, OAuthClientInformationFull] = {}
        self._pending: dict[str, _PendingAuthorization] = {}
        self._auth_codes: dict[str, AuthorizationCode] = {}
        # Keyed by HMAC digest of the token, never by the token itself.
        self._access_tokens: dict[str, _StoredToken] = {}
        self._refresh_tokens: dict[str, _StoredToken] = {}
        self._load_state()

    def verify_passcode(self, candidate: str) -> bool:
        return secrets.compare_digest(candidate or "", self._passcode)

    # --- Persistence ---

    def _digest(self, token: str) -> str:
        return hmac.new(self._hmac_key, token.encode(), hashlib.sha256).hexdigest()

    def _key_id(self) -> str:
        # Detects a passcode change without storing anything that helps guess it.
        return self._digest("mfp-oauth-state-key-id")

    def _load_state(self) -> None:
        if not self._state_file:
            return
        try:
            with open(self._state_file, encoding="utf-8") as f:
                data = json.load(f)
        except FileNotFoundError:
            logger.info("OAuth state file %s not found; starting empty", self._state_file)
            return
        except (OSError, ValueError) as e:
            logger.warning("Could not read OAuth state file %s (%r); starting empty", self._state_file, e)
            return

        if data.get("version") != _STATE_VERSION:
            logger.warning("OAuth state file has unknown version; starting empty")
            return

        for raw in data.get("clients", []):
            try:
                client = OAuthClientInformationFull.model_validate(raw)
                self._clients[client.client_id] = client
            except Exception as e:  # noqa: BLE001 - skip one bad record, keep the rest
                logger.warning("Skipping invalid stored client: %r", e)

        if data.get("key_id") != self._key_id():
            logger.warning("Passcode changed since OAuth state was saved; dropping stored tokens")
            self._save_state()
            return

        now = time.time()
        for attr in ("access_tokens", "refresh_tokens"):
            target = getattr(self, "_" + attr)
            for digest, rec in data.get(attr, {}).items():
                tok = _StoredToken(rec["client_id"], list(rec["scopes"]), rec.get("expires_at"))
                if tok.expires_at is not None and tok.expires_at < now:
                    continue
                if tok.client_id not in self._clients:
                    continue
                target[digest] = tok
        logger.info(
            "Loaded OAuth state: %d clients, %d access tokens, %d refresh tokens",
            len(self._clients), len(self._access_tokens), len(self._refresh_tokens),
        )

    def _save_state(self) -> None:
        if not self._state_file:
            return
        now = time.time()

        def live(store: dict[str, _StoredToken]) -> dict:
            return {
                d: {"client_id": t.client_id, "scopes": t.scopes, "expires_at": t.expires_at}
                for d, t in store.items()
                if t.expires_at is None or t.expires_at >= now
            }

        data = {
            "version": _STATE_VERSION,
            "key_id": self._key_id(),
            "clients": [c.model_dump(mode="json", exclude_none=True) for c in self._clients.values()],
            "access_tokens": live(self._access_tokens),
            "refresh_tokens": live(self._refresh_tokens),
        }
        directory = os.path.dirname(os.path.abspath(self._state_file))
        with self._lock:
            try:
                fd, tmp = tempfile.mkstemp(prefix=".oauth-state-", dir=directory)
                try:
                    os.fchmod(fd, 0o600)
                    with os.fdopen(fd, "w", encoding="utf-8") as f:
                        json.dump(data, f)
                        f.flush()
                        os.fsync(f.fileno())
                    os.replace(tmp, self._state_file)
                except BaseException:
                    if os.path.exists(tmp):
                        os.unlink(tmp)
                    raise
            except OSError as e:
                # Never break auth because the disk write failed; tokens still work until restart.
                logger.error("Could not write OAuth state file %s: %r", self._state_file, e)

    # --- Dynamic client registration ---

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        return self._clients.get(client_id)

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        self._clients[client_info.client_id] = client_info
        self._save_state()

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
        digest = self._digest(refresh_token)
        stored = self._refresh_tokens.get(digest)
        if stored is None or stored.client_id != client.client_id:
            return None
        if stored.expires_at is not None and stored.expires_at < time.time():
            del self._refresh_tokens[digest]
            self._save_state()
            return None
        return RefreshToken(
            token=refresh_token, client_id=stored.client_id, scopes=stored.scopes, expires_at=stored.expires_at
        )

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        # Rotation: the old refresh token stops working as soon as it's used.
        self._refresh_tokens.pop(self._digest(refresh_token.token), None)
        return self._issue_token(client.client_id, scopes or refresh_token.scopes or DEFAULT_SCOPES)

    async def load_access_token(self, token: str) -> AccessToken | None:
        digest = self._digest(token)
        stored = self._access_tokens.get(digest)
        if stored is None:
            return None
        if stored.expires_at is not None and stored.expires_at < time.time():
            del self._access_tokens[digest]
            self._save_state()
            return None
        return AccessToken(token=token, client_id=stored.client_id, scopes=stored.scopes, expires_at=stored.expires_at)

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        digest = self._digest(token.token)
        self._access_tokens.pop(digest, None)
        self._refresh_tokens.pop(digest, None)
        self._save_state()

    def _issue_token(self, client_id: str, scopes: list[str]) -> OAuthToken:
        access_token = secrets.token_urlsafe(32)
        refresh_token = secrets.token_urlsafe(32)
        now = int(time.time())
        self._access_tokens[self._digest(access_token)] = _StoredToken(
            client_id, list(scopes), now + ACCESS_TOKEN_TTL_SECONDS
        )
        self._refresh_tokens[self._digest(refresh_token)] = _StoredToken(
            client_id, list(scopes), now + REFRESH_TOKEN_TTL_SECONDS
        )
        self._save_state()
        return OAuthToken(
            access_token=access_token,
            token_type="Bearer",
            expires_in=ACCESS_TOKEN_TTL_SECONDS,
            refresh_token=refresh_token,
            scope=" ".join(scopes) or None,
        )

"""OAuth state persistence: survives restarts, rotates refresh tokens, never stores tokens in clear."""
import json, os, stat

import pytest

from myfitnesspal_mcp import oauth_provider as op
from mcp.shared.auth import OAuthClientInformationFull


@pytest.mark.asyncio
async def test_oauth_state_persistence(tmp_path, monkeypatch):
    sf = str(tmp_path / "oauth_state.json")
    p = op.SinglePasscodeOAuthProvider("segredo-1", state_file=sf)
    client = OAuthClientInformationFull(client_id="c1", redirect_uris=["https://claude.ai/cb"], token_endpoint_auth_method="none")
    await p.register_client(client)
    tok = p._issue_token("c1", ["mcp"])

    raw = open(sf).read()
    assert tok.access_token not in raw and tok.refresh_token not in raw, "token stored in clear"
    assert stat.S_IMODE(os.stat(sf).st_mode) == 0o600, oct(os.stat(sf).st_mode)

    # "Restart": a new instance reads the file back
    p2 = op.SinglePasscodeOAuthProvider("segredo-1", state_file=sf)
    assert await p2.get_client("c1") is not None
    at = await p2.load_access_token(tok.access_token)
    assert at and at.client_id == "c1" and at.scopes == ["mcp"]
    rt = await p2.load_refresh_token(client, tok.refresh_token)
    assert rt is not None and rt.expires_at

    # Rotation: the used refresh token dies, the new one survives another restart
    new = await p2.exchange_refresh_token(client, rt, [])
    p3 = op.SinglePasscodeOAuthProvider("segredo-1", state_file=sf)
    assert await p3.load_refresh_token(client, tok.refresh_token) is None
    assert await p3.load_refresh_token(client, new.refresh_token) is not None
    assert await p3.load_access_token(new.access_token) is not None

    # Another client can't use it
    other = OAuthClientInformationFull(client_id="c2", redirect_uris=["https://x/cb"])
    assert await p3.load_refresh_token(other, new.refresh_token) is None

    # Revocation is persisted
    await p3.revoke_token(await p3.load_access_token(new.access_token))
    p4 = op.SinglePasscodeOAuthProvider("segredo-1", state_file=sf)
    assert await p4.load_access_token(new.access_token) is None

    # Passcode change invalidates every token (clients stay)
    p5 = op.SinglePasscodeOAuthProvider("segredo-2", state_file=sf)
    assert await p5.load_refresh_token(client, new.refresh_token) is None
    assert await p5.get_client("c1") is not None
    assert json.load(open(sf))["refresh_tokens"] == {}

    # Expired tokens are dropped on load
    p6 = op.SinglePasscodeOAuthProvider("segredo-2", state_file=sf)
    t6 = p6._issue_token("c1", ["mcp"])
    data = json.load(open(sf))
    for v in data["access_tokens"].values():
        v["expires_at"] = 1
    json.dump(data, open(sf, "w"))
    p7 = op.SinglePasscodeOAuthProvider("segredo-2", state_file=sf)
    assert await p7.load_access_token(t6.access_token) is None
    assert await p7.load_refresh_token(client, t6.refresh_token) is not None

    # No state file: in-memory only (previous behaviour)
    monkeypatch.delenv("MCP_OAUTH_STATE_FILE", raising=False)
    pm = op.SinglePasscodeOAuthProvider("x")
    tm = pm._issue_token("c1", ["mcp"])
    assert await pm.load_access_token(tm.access_token) is not None

    # A corrupt file doesn't crash startup
    open(sf, "w").write("{lixo")
    op.SinglePasscodeOAuthProvider("segredo-2", state_file=sf)

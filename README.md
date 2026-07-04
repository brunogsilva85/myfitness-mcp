# MyFitnessPal MCP Service

A deployable [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server for MyFitnessPal that works as a **remote Claude connector**: food diary, food search, exercises, body measurements, nutrition goals, water intake, and nutrition reports.

This is a fork of [AdamWalt/myfitnesspal-mcp-python](https://github.com/AdamWalt/myfitnesspal-mcp-python) (MIT, tool implementations) restructured for remote deployment with the OAuth 2.1 / streamable-http transport skeleton from [garmin-mcp-service](https://github.com/delize/garmin-mcp-service). MyFitnessPal access is via [coddingtonbear/python-myfitnesspal](https://github.com/coddingtonbear/python-myfitnesspal).

## Tools

| Tool | Type | Description |
|------|------|-------------|
| `mfp_get_diary` | Read | Food diary (meals, entries, nutrition, totals, goals) for a date |
| `mfp_search_food` | Read | Search the MyFitnessPal food database |
| `mfp_get_food_details` | Read | Full nutrition breakdown for a food by MFP ID |
| `mfp_get_recent_foods` | Read | Recently used foods from the authenticated account |
| `mfp_get_frequent_foods` | Read | Most-used foods from the authenticated account |
| `mfp_get_my_foods` | Read | Foods created or saved by the authenticated account |
| `mfp_get_measurements` | Read | Body measurement history (Weight, Body Fat, ...) |
| `mfp_set_measurement` | Write | Log a body measurement for today |
| `mfp_get_exercises` | Read | Logged cardio/strength exercises for a date |
| `mfp_get_goals` | Read | Daily nutrition goals |
| `mfp_set_goals` | Write | Update daily nutrition goals |
| `mfp_get_water` | Read | Water intake for a date |
| `mfp_set_water` | Write | Log water intake for a date |
| `mfp_add_food_to_diary` | Write | Add a food entry to a meal |
| `mfp_update_food_entry` | Write | Update an existing diary entry by `entry_id` |
| `mfp_delete_food_entry` | Write | Delete an existing diary entry by `entry_id` |
| `mfp_get_report` | Read | Nutrition report (e.g. Net Calories) over a date range |

### Food collections (recent / frequent / my foods)

`mfp_get_recent_foods`, `mfp_get_frequent_foods`, and `mfp_get_my_foods` each take an optional `limit` (recent/frequent default 10, my-foods default 100, max 100) and `response_format` (`markdown` or `json`). They intentionally use the **legacy add-to-diary AJAX endpoints** (`/food/load_recent`, `/food/load_most_used`, `/food/load_my_foods`) rather than the newer `/food/mine`, `/meal/mine`, or `/food/new` pages, which can redirect to `/account/logout` even when diary reads and API-token fetches still work.

### Editing diary entries

`mfp_get_diary` with `response_format=json` now surfaces an `entry_id` for each meal entry. Pass that id to:

- `mfp_update_food_entry` - change `meal`, `quantity`, `unit` (serving-size label, e.g. `"350 ml"`), or `weight_id` (raw MFP serving-size option id, overrides `unit`) for an entry; requires `date` for historical entries. MyFitnessPal can rewrite an entry during edit, so the response reports `current_entry_id` and `entry_id_changed` so you can keep tracking the right row.
- `mfp_delete_food_entry` - delete an entry by `entry_id` (requires `date` for historical entries).

## Authentication: the cookie strategy

MyFitnessPal's login page is **captcha-protected**, so headless password login is dead - this server never asks for your MFP password. Instead it reads session cookies from one of:

1. **Firefox profile sidecar (recommended):** log into myfitnesspal.com once, interactively, in a Firefox profile; mount that profile directory read-only into the container at `/profile`. The server copies `cookies.sqlite` (and its WAL) to a temp file on each refresh - Firefox's locks don't matter - and extracts the `myfitnesspal.com` cookies. The copy is cached and only re-read when the file changes, so Firefox can keep running (e.g. a headless Firefox sidecar container you occasionally VNC into to re-login).
2. **JSON cookies file:** `MFP_COOKIES_FILE` pointing at `{"cookies": {name: value}}` (AdamWalt's `~/.mfp_mcp/cookies.json` format) or a plain `{name: value}` dict.

Session cookies expire eventually (~30 days); when tools start failing with auth errors, log into MFP again in that Firefox profile.

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `MFP_FIREFOX_PROFILE_DIR` | `/profile` (Docker) | Firefox profile dir (or parent dir of profiles) containing `cookies.sqlite` with a logged-in MFP session |
| `MFP_COOKIES_FILE` | - | JSON cookies file; used if set and no `cookies.sqlite` is found |
| `MCP_TRANSPORT` | `stdio` (`streamable-http` in Docker) | Transport: `stdio` or `streamable-http` |
| `MCP_HOST` | `127.0.0.1` (`0.0.0.0` in Docker) | Bind address for HTTP mode |
| `MCP_PORT` | `8000` | Port for HTTP mode |
| `MCP_ALLOWED_HOSTS` | - | Comma-separated allowed `Host` headers (reverse proxy domains). Enables DNS-rebinding protection; if unset, protection is disabled in HTTP mode |
| `MCP_OAUTH_PASSCODE` | - | Shared passcode for the OAuth login page (remote connectors). Omit for unauthenticated LAN-only use |
| `MCP_RESOURCE_URL` | - | Exact public URL clients use (no path), e.g. `https://mfp.example.com`. Required together with the passcode |

## Docker

```bash
docker build -t myfitnesspal-mcp-service .

docker run -d -p 8000:8000 \
  -v ~/.mozilla/firefox/abcd1234.default-release:/profile:ro \
  -e MCP_ALLOWED_HOSTS=mfp.example.com \
  -e MCP_RESOURCE_URL=https://mfp.example.com \
  -e MCP_OAUTH_PASSCODE="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')" \
  ghcr.io/delize/myfitnesspal-mcp-service:latest
```

CI builds and pushes `ghcr.io/delize/myfitnesspal-mcp-service` (amd64 + arm64) on pushes to `main` and `v*` tags.

## Claude Connector Setup

Same flow as garmin-mcp-service:

1. Deploy behind HTTPS (reverse proxy) with `MCP_TRANSPORT=streamable-http`, `MCP_RESOURCE_URL`, and `MCP_OAUTH_PASSCODE` set.
2. In Claude, add a custom connector with URL `https://mfp.example.com/mcp`. Leave OAuth Client ID/Secret blank - the server supports dynamic client registration (`/register`), authorization + PKCE (`/authorize`, `/token`).
3. Claude redirects you to the `/login` passcode page once; enter `MCP_OAUTH_PASSCODE`. After that the client holds and refreshes its own token.

The passcode proves "the caller knows the passcode", not identity - keep network-level access control (IP allowlist, VPN) in front of any internet-facing deployment. Omitting `MCP_OAUTH_PASSCODE`/`MCP_RESOURCE_URL` runs the HTTP server unauthenticated (a warning is logged); only do that on a trusted network.

For local stdio use (Claude Desktop):

```json
{
  "mcpServers": {
    "myfitnesspal": {
      "command": "python",
      "args": ["-m", "myfitnesspal_mcp.server"],
      "env": {
        "MFP_FIREFOX_PROFILE_DIR": "/home/you/.mozilla/firefox/abcd1234.default-release"
      }
    }
  }
}
```

## Troubleshooting

### Tools don't appear even though the connector shows "Connected"

**Problem**: The connector authorizes and shows as Connected, but its tools never
surface in a conversation - asking the model to use them, or searching for them,
turns up nothing. No error is shown.

**Cause**: This is almost always a **client-side tool-budget limit, not a problem
with this server**. Claude caps how many tools can be active in a single
conversation across *all* connected servers combined. If another connector exposes
a very large tool set, it can consume that budget and silently crowd this server's
tools out of the conversation. (Seen in practice with a connector exposing ~170
tools starving this server's handful.)

**Confirm / fix**:
1. In a **fresh conversation**, disable the other large connector(s) and check
   whether these tools now appear. If they do, it was the budget.
2. Keep high-tool-count connectors in **separate conversations**, or trim their
   active tools if the client supports per-tool toggles.
3. This server always returns its full tool list regardless - you can verify
   independently with an authenticated `tools/list` call against `/mcp`. If that
   returns the tools but the client doesn't show them, the gap is on the client
   side, not here.

## Attribution

- Tool implementations: [AdamWalt/myfitnesspal-mcp-python](https://github.com/AdamWalt/myfitnesspal-mcp-python) (MIT, this repo is a fork - full history preserved)
- MyFitnessPal client library: [coddingtonbear/python-myfitnesspal](https://github.com/coddingtonbear/python-myfitnesspal)
- OAuth/transport skeleton: garmin-mcp-service

## License

MIT - see [LICENSE](LICENSE) (preserves the original copyright).

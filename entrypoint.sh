#!/bin/bash
set -e

# Validate cookie-source configuration: either a mounted Firefox profile with
# a cookies.sqlite (directly or one level down), or a JSON cookies file.
profile_dir="${MFP_FIREFOX_PROFILE_DIR:-}"
has_profile_cookies=""
if [ -n "$profile_dir" ]; then
    if [ -f "$profile_dir/cookies.sqlite" ] || compgen -G "$profile_dir/*/cookies.sqlite" > /dev/null 2>&1; then
        has_profile_cookies="yes"
    fi
fi

if [ -z "$has_profile_cookies" ] && [ ! -f "${MFP_COOKIES_FILE:-/nonexistent}" ]; then
    echo "ERROR: No MyFitnessPal cookie source found!"
    echo ""
    echo "MyFitnessPal's login is captcha-protected, so this server reads session"
    echo "cookies instead of logging in with a password. Provide one of:"
    echo ""
    echo "  - MFP_FIREFOX_PROFILE_DIR (default: /profile) - mount a Firefox profile"
    echo "    directory that is logged into myfitnesspal.com, e.g.:"
    echo "      docker run -v ~/.mozilla/firefox/abcd1234.default-release:/profile:ro ..."
    echo ""
    echo "  - MFP_COOKIES_FILE - path to a JSON cookies file"
    echo "    ({\"cookies\": {name: value}} or a plain {name: value} dict), e.g.:"
    echo "      docker run -v ~/.mfp_mcp/cookies.json:/cookies.json:ro -e MFP_COOKIES_FILE=/cookies.json ..."
    echo ""
    exit 1
fi

echo "MyFitnessPal MCP Server starting..."
echo "Transport: ${MCP_TRANSPORT:-stdio}"
if [ "$MCP_TRANSPORT" = "streamable-http" ]; then
    echo "Listening on: ${MCP_HOST:-0.0.0.0}:${MCP_PORT:-8000}"
fi

exec "$@"

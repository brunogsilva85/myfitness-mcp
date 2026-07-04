"""MyFitnessPal MCP Server - Main entry point.

A Model Context Protocol (MCP) server that provides tools for interacting
with MyFitnessPal data including food diary, exercises, measurements, goals,
water intake, and food search.

Tool implementations are ported from AdamWalt/myfitnesspal-mcp-python (MIT).
The OAuth 2.1 / transport skeleton (streamable-http, single-passcode OAuth
provider, allowed-hosts DNS-rebinding protection) mirrors garmin-mcp-service
so this can be used as a remote Claude connector.

Authentication: MyFitnessPal's login page is captcha-protected, so password
login is not supported. Session cookies are read from a mounted Firefox
profile (MFP_FIREFOX_PROFILE_DIR) or a JSON cookies file (MFP_COOKIES_FILE) -
see cookie_loader.
"""

import json
import logging
import os
import sys
import threading
from collections import OrderedDict
from datetime import date, datetime, timedelta
from enum import Enum
from http.cookiejar import CookieJar
from typing import Any, Dict, Optional

from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from pydantic import BaseModel, ConfigDict, Field
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response

from . import cookie_loader
from .oauth_provider import SinglePasscodeOAuthProvider

# Configure logging to stderr (required for stdio transport)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stderr)],
)
logger = logging.getLogger("myfitnesspal_mcp")


# Configure transport security based on mode
# When running in HTTP mode (0.0.0.0), we need to either disable DNS rebinding
# protection or configure allowed hosts via MCP_ALLOWED_HOSTS env var
def _get_transport_security() -> TransportSecuritySettings | None:
    """Get transport security settings based on environment."""
    transport = os.getenv("MCP_TRANSPORT", "stdio")
    if transport != "streamable-http":
        return None  # Use FastMCP defaults for stdio

    # Check for explicitly configured allowed hosts
    allowed_hosts_str = os.getenv("MCP_ALLOWED_HOSTS", "")
    if allowed_hosts_str:
        allowed_hosts = [h.strip() for h in allowed_hosts_str.split(",") if h.strip()]
        # Also allow localhost for local testing
        allowed_hosts.extend(["127.0.0.1:*", "localhost:*", "[::1]:*"])
        return TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=allowed_hosts,
            allowed_origins=[],  # Allow any origin (MCP clients aren't browsers)
        )

    # No allowed hosts configured - disable DNS rebinding protection for remote access
    return TransportSecuritySettings(enable_dns_rebinding_protection=False)


# Configure OAuth for remote MCP connectors (Claude, ChatGPT), which require
# full OAuth 2.1 + dynamic client registration rather than a bare bearer
# token. Gated behind MCP_OAUTH_PASSCODE/MCP_RESOURCE_URL so local stdio use
# and simple Docker testing don't need to set any of this up.
def _build_oauth() -> tuple[SinglePasscodeOAuthProvider | None, AuthSettings | None]:
    """Build the OAuth provider/settings pair, or (None, None) if unconfigured.

    Raises RuntimeError if exactly one of MCP_OAUTH_PASSCODE/MCP_RESOURCE_URL
    is set. That combination is almost always a misconfiguration (e.g. a
    passcode that resolved empty due to a missing .env line or shell/compose
    variable-expansion mangling it), not an intentional choice - silently
    falling back to no-auth in that case would serve every tool unauthenticated
    on the public internet with nothing louder than a warning log line.
    """
    transport = os.getenv("MCP_TRANSPORT", "stdio")
    if transport != "streamable-http":
        return None, None

    passcode = os.getenv("MCP_OAUTH_PASSCODE")
    resource_url = os.getenv("MCP_RESOURCE_URL")

    if not passcode and not resource_url:
        logging.getLogger(__name__).warning(
            "MCP_TRANSPORT=streamable-http with no MCP_OAUTH_PASSCODE/"
            "MCP_RESOURCE_URL set - running WITHOUT OAuth. Do not expose "
            "this deployment to the internet without configuring both."
        )
        return None, None

    if not passcode or not resource_url:
        missing = "MCP_OAUTH_PASSCODE" if not passcode else "MCP_RESOURCE_URL"
        raise RuntimeError(
            f"{missing} is unset but the other OAuth variable is set - this "
            "looks like a misconfiguration, not an intentional no-auth "
            "deployment. Refusing to start rather than silently serving the "
            "MCP endpoint without authentication. Set both "
            "MCP_OAUTH_PASSCODE and MCP_RESOURCE_URL, or neither."
        )

    provider = SinglePasscodeOAuthProvider(passcode)
    auth_settings = AuthSettings(
        issuer_url=resource_url,
        resource_server_url=resource_url,
        client_registration_options=ClientRegistrationOptions(
            enabled=True, valid_scopes=["mcp"], default_scopes=["mcp"]
        ),
        required_scopes=["mcp"],
    )
    return provider, auth_settings


_oauth_provider, _auth_settings = _build_oauth()

# Initialize MCP server
mcp = FastMCP(
    "MyFitnessPal MCP",
    dependencies=["myfitnesspal", "httpx"],
    host=os.getenv("MCP_HOST", "127.0.0.1"),
    port=int(os.getenv("MCP_PORT", "8000")),
    transport_security=_get_transport_security(),
    auth=_auth_settings,
    auth_server_provider=_oauth_provider,
)

_LOGIN_FORM = """
<!doctype html>
<html>
<head><title>MyFitnessPal MCP - Sign in</title></head>
<body style="font-family: sans-serif; max-width: 24rem; margin: 4rem auto;">
  <h2>MyFitnessPal MCP</h2>
  <p>{message}</p>
  <form method="post">
    <input type="hidden" name="login_id" value="{login_id}">
    <input type="password" name="passcode" placeholder="Passcode" autofocus
           style="width: 100%; padding: 0.5rem; font-size: 1rem;">
    <button type="submit" style="margin-top: 0.75rem; padding: 0.5rem 1rem;">Continue</button>
  </form>
</body>
</html>
"""


if _oauth_provider is not None:

    @mcp.custom_route("/login", methods=["GET", "POST"])
    async def login(request: Request) -> Response:
        """Passcode gate standing in for a real login screen (see oauth_provider)."""
        if request.method == "GET":
            login_id = request.query_params.get("login_id", "")
        else:
            form = await request.form()
            login_id = str(form.get("login_id", ""))

        if not login_id or _oauth_provider.get_pending(login_id) is None:
            return HTMLResponse(
                _LOGIN_FORM.format(message="This login link has expired. Please retry from your MCP client.", login_id=""),
                status_code=400,
            )

        if request.method == "GET":
            return HTMLResponse(_LOGIN_FORM.format(message="Enter the server passcode to continue.", login_id=login_id))

        form = await request.form()
        passcode = str(form.get("passcode", ""))
        if not _oauth_provider.verify_passcode(passcode):
            return HTMLResponse(
                _LOGIN_FORM.format(message="Incorrect passcode, try again.", login_id=login_id),
                status_code=401,
            )

        redirect_url = _oauth_provider.complete_login(login_id)
        if redirect_url is None:
            return HTMLResponse(
                _LOGIN_FORM.format(message="This login link has expired. Please retry from your MCP client.", login_id=""),
                status_code=400,
            )
        return RedirectResponse(redirect_url, status_code=302)


# ============================================================================
# Authentication
# ============================================================================

_client_lock = threading.Lock()
_cached_client: Any = None
_cached_jar: Optional[CookieJar] = None


def get_mfp_client():
    """
    Get an authenticated MyFitnessPal client.

    Session cookies are loaded via cookie_loader (Firefox profile mount or
    JSON cookies file). The client is cached and only rebuilt when the
    underlying cookie source changes (cookie_loader returns the same jar
    object while the source file is unchanged).

    Returns:
        myfitnesspal.Client: Authenticated client instance

    Raises:
        RuntimeError: If no cookie source is configured or readable
    """
    import myfitnesspal

    global _cached_client, _cached_jar

    jar = cookie_loader.get_cookiejar()
    with _client_lock:
        if _cached_client is not None and _cached_jar is jar:
            return _cached_client
        logger.info("Building MyFitnessPal client from cookie jar (%d cookies)", len(jar))
        client = myfitnesspal.Client(cookiejar=jar)
        _cached_client = client
        _cached_jar = jar
        return client


# ============================================================================
# Data Formatting Helper Functions
# ============================================================================


def parse_date(date_str: Optional[str] = None) -> date:
    """
    Parse a date string or return today's date.

    Args:
        date_str: Date in YYYY-MM-DD format, or None for today

    Returns:
        date: Parsed date object
    """
    if date_str is None:
        return date.today()
    return datetime.strptime(date_str, "%Y-%m-%d").date()


def format_nutrition_dict(nutrition: Dict[str, Any]) -> Dict[str, Any]:
    """
    Format nutrition dictionary for consistent output.

    Args:
        nutrition: Raw nutrition dictionary

    Returns:
        dict: Formatted nutrition data
    """
    formatted = {}
    for key, value in nutrition.items():
        if hasattr(value, "magnitude"):
            # Handle pint quantities
            formatted[key] = float(value.magnitude)
        else:
            formatted[key] = value
    return formatted


def format_meal_entry(entry) -> Dict[str, Any]:
    """
    Format a meal entry for output.

    Args:
        entry: MFP Entry object

    Returns:
        dict: Formatted entry data
    """
    return {
        "name": entry.name,
        "short_name": getattr(entry, "short_name", None),
        "quantity": getattr(entry, "quantity", None),
        "unit": getattr(entry, "unit", None),
        "nutrition": format_nutrition_dict(entry.totals),
    }


def format_exercise(exercise) -> Dict[str, Any]:
    """
    Format an exercise object for output.

    Args:
        exercise: MFP Exercise object

    Returns:
        dict: Formatted exercise data
    """
    entries = exercise.get_as_list()
    return {"name": exercise.name, "entries": entries}


def ordered_dict_to_dict(od: OrderedDict) -> Dict[str, Any]:
    """
    Convert OrderedDict with date keys to regular dict with string keys.

    Args:
        od: OrderedDict with date keys

    Returns:
        dict: Regular dict with string keys
    """
    return {str(k): v for k, v in od.items()}


class ResponseFormat(str, Enum):
    """Output format for tool responses."""

    MARKDOWN = "markdown"
    JSON = "json"


def format_response(data: Any, format_type: ResponseFormat, title: str = "") -> str:
    """
    Format response data based on requested format.

    Args:
        data: Data to format
        format_type: Output format (markdown or json)
        title: Optional title for markdown format

    Returns:
        str: Formatted response string
    """
    if format_type == ResponseFormat.JSON:
        return json.dumps(data, indent=2, default=str)

    # Markdown format
    lines = []
    if title:
        lines.append(f"## {title}\n")

    if isinstance(data, dict):
        for key, value in data.items():
            if isinstance(value, dict):
                lines.append(f"### {key}")
                for k, v in value.items():
                    lines.append(f"- **{k}**: {v}")
            elif isinstance(value, list):
                lines.append(f"### {key}")
                for item in value:
                    if isinstance(item, dict):
                        lines.append(f"- {item.get('name', str(item))}")
                        for k, v in item.items():
                            if k != "name":
                                lines.append(f"  - {k}: {v}")
                    else:
                        lines.append(f"- {item}")
            else:
                lines.append(f"- **{key}**: {value}")
    else:
        lines.append(str(data))

    return "\n".join(lines)


# ============================================================================
# Pydantic Input Models
# ============================================================================


class GetDiaryInput(BaseModel):
    """Input model for getting food diary."""

    model_config = ConfigDict(str_strip_whitespace=True)

    date: Optional[str] = Field(
        default=None,
        description="Date in YYYY-MM-DD format. Defaults to today if not specified.",
        pattern=r"^\d{4}-\d{2}-\d{2}$",
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format: 'markdown' for human-readable or 'json' for structured data",
    )


class SearchFoodInput(BaseModel):
    """Input model for searching foods."""

    model_config = ConfigDict(str_strip_whitespace=True)

    query: str = Field(
        ...,
        description="Search query for food items (e.g., 'chicken breast', 'apple')",
        min_length=1,
        max_length=200,
    )
    limit: int = Field(
        default=10,
        description="Maximum number of results to return",
        ge=1,
        le=50,
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format: 'markdown' for human-readable or 'json' for structured data",
    )


class GetFoodDetailsInput(BaseModel):
    """Input model for getting food item details."""

    model_config = ConfigDict(str_strip_whitespace=True)

    mfp_id: str = Field(
        ...,
        description="MyFitnessPal food item ID (obtained from search results)",
        min_length=1,
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format: 'markdown' for human-readable or 'json' for structured data",
    )


class GetMeasurementsInput(BaseModel):
    """Input model for getting measurements."""

    model_config = ConfigDict(str_strip_whitespace=True)

    measurement: str = Field(
        default="Weight",
        description="Type of measurement to retrieve (e.g., 'Weight', 'Body Fat', 'Waist')",
    )
    start_date: Optional[str] = Field(
        default=None,
        description="Start date in YYYY-MM-DD format. Defaults to 30 days ago.",
        pattern=r"^\d{4}-\d{2}-\d{2}$",
    )
    end_date: Optional[str] = Field(
        default=None,
        description="End date in YYYY-MM-DD format. Defaults to today.",
        pattern=r"^\d{4}-\d{2}-\d{2}$",
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format: 'markdown' for human-readable or 'json' for structured data",
    )


class SetMeasurementInput(BaseModel):
    """Input model for setting a measurement."""

    model_config = ConfigDict(str_strip_whitespace=True)

    measurement: str = Field(
        default="Weight",
        description="Type of measurement to set (e.g., 'Weight', 'Body Fat', 'Waist')",
    )
    value: float = Field(
        ...,
        description="Measurement value (e.g., 185.5 for weight in lbs)",
        gt=0,
    )


class GetExercisesInput(BaseModel):
    """Input model for getting exercises."""

    model_config = ConfigDict(str_strip_whitespace=True)

    date: Optional[str] = Field(
        default=None,
        description="Date in YYYY-MM-DD format. Defaults to today if not specified.",
        pattern=r"^\d{4}-\d{2}-\d{2}$",
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format: 'markdown' for human-readable or 'json' for structured data",
    )


class GetGoalsInput(BaseModel):
    """Input model for getting nutrition goals."""

    model_config = ConfigDict(str_strip_whitespace=True)

    date: Optional[str] = Field(
        default=None,
        description="Date in YYYY-MM-DD format. Defaults to today if not specified.",
        pattern=r"^\d{4}-\d{2}-\d{2}$",
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format: 'markdown' for human-readable or 'json' for structured data",
    )


class SetGoalsInput(BaseModel):
    """Input model for setting nutrition goals."""

    model_config = ConfigDict(str_strip_whitespace=True)

    calories: Optional[int] = Field(
        default=None,
        description="Daily calorie goal (e.g., 2000)",
        ge=500,
        le=10000,
    )
    protein: Optional[int] = Field(
        default=None,
        description="Daily protein goal in grams (e.g., 150)",
        ge=0,
        le=1000,
    )
    carbohydrates: Optional[int] = Field(
        default=None,
        description="Daily carbohydrate goal in grams (e.g., 200)",
        ge=0,
        le=2000,
    )
    fat: Optional[int] = Field(
        default=None,
        description="Daily fat goal in grams (e.g., 65)",
        ge=0,
        le=500,
    )


class GetWaterInput(BaseModel):
    """Input model for getting water intake."""

    model_config = ConfigDict(str_strip_whitespace=True)

    date: Optional[str] = Field(
        default=None,
        description="Date in YYYY-MM-DD format. Defaults to today if not specified.",
        pattern=r"^\d{4}-\d{2}-\d{2}$",
    )


class GetReportInput(BaseModel):
    """Input model for getting nutrition reports."""

    model_config = ConfigDict(str_strip_whitespace=True)

    report_name: str = Field(
        default="Net Calories",
        description="Report name (e.g., 'Net Calories', 'Total Calories', 'Protein', 'Fat', 'Carbs')",
    )
    start_date: Optional[str] = Field(
        default=None,
        description="Start date in YYYY-MM-DD format. Defaults to 7 days ago.",
        pattern=r"^\d{4}-\d{2}-\d{2}$",
    )
    end_date: Optional[str] = Field(
        default=None,
        description="End date in YYYY-MM-DD format. Defaults to today.",
        pattern=r"^\d{4}-\d{2}-\d{2}$",
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format: 'markdown' for human-readable or 'json' for structured data",
    )


class AddFoodToDiaryInput(BaseModel):
    """Input model for adding food to diary."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    mfp_id: str = Field(
        ...,
        description="MyFitnessPal food item ID (obtained from mfp_search_food)",
        min_length=1,
    )
    meal: str = Field(
        default="Breakfast",
        description="Meal name (e.g., 'Breakfast', 'Lunch', 'Dinner', 'Snacks')",
    )
    date: Optional[str] = Field(
        default=None,
        description="Date in YYYY-MM-DD format. Defaults to today if not specified.",
        pattern=r"^\d{4}-\d{2}-\d{2}$",
    )
    quantity: float = Field(
        default=1.0,
        description=(
            "Quantity in number of default servings (e.g., 1.5 for 1.5 servings). "
            "The 'default serving' is the first weight option for the food in "
            "MyFitnessPal -- call mfp_get_food_details(mfp_id) to see what the "
            "default unit actually is for any given food."
        ),
        gt=0,
        le=10000,
    )


class SetWaterInput(BaseModel):
    """Input model for setting water intake."""

    model_config = ConfigDict(str_strip_whitespace=True)

    cups: float = Field(
        ...,
        description="Number of cups of water (e.g., 2.5 for 2.5 cups). Note: MyFitnessPal uses cups as the unit.",
        ge=0,
        le=50,
    )
    date: Optional[str] = Field(
        default=None,
        description="Date in YYYY-MM-DD format. Defaults to today if not specified.",
        pattern=r"^\d{4}-\d{2}-\d{2}$",
    )


# ============================================================================
# Diary Entry Creation Helper Functions
# ============================================================================


def add_food_to_diary(
    client, mfp_id: str, meal: str, target_date: date, quantity: float = 1.0,
) -> None:
    """
    Add a food item to the diary for a specific date and meal.

    Uses the modern MFP add flow (the legacy /food/diary/{user}/add endpoint
    this used to target was retired by MyFitnessPal and now 404s -- every
    write silently no-op'd):
      1. Visit /food/add_to_diary?meal=X to get the page CSRF
      2. POST /food/search to find the food and capture its `data-original-id`
         + `data-weight-ids` + the page's csrf-token meta
      3. POST /food/add with food_entry[food_id]=original_id (NOT mfp_id),
         food_entry[meal_id]=index, food_entry[weight_id]=first weight id

    The food's default weight_id (first one MFP exposes for the food) is
    always used. The quantity is in units of that default serving.

    Raises RuntimeError if no search result exactly matches the requested
    mfp_id -- we do NOT silently substitute another food, because adding the
    wrong item to a diary is materially worse than failing the call.

    Args:
        client: Authenticated myfitnesspal.Client instance
        mfp_id: MyFitnessPal external food ID (from search results)
        meal: Meal name (Breakfast, Lunch, Dinner, Snacks)
        target_date: Date to add the food entry
        quantity: Number of default servings (default 1.0)
    """
    import re

    meal_map = {"breakfast": "0", "lunch": "1", "dinner": "2",
                "snacks": "3", "snack": "3"}
    meal_index = meal_map.get(meal.lower(), "0")
    date_str = target_date.strftime("%Y-%m-%d")

    try:
        # Step 1: Visit the diary page so Rails session cookies are present.
        client._get_document_for_url(
            f"{client.BASE_URL_SECURE}food/diary"
        )

        # Step 2: Get the add_to_diary page (needed for CSRF + warm form session)
        add_page_url = (
            f"{client.BASE_URL_SECURE}food/add_to_diary?meal={meal_index}"
        )
        add_page_doc = client._get_document_for_url(add_page_url)
        page_auth = add_page_doc.xpath(
            "(//input[@name='authenticity_token']/@value)[1]"
        )
        if not page_auth:
            raise RuntimeError("Could not find authenticity token on add_to_diary page")
        page_auth = page_auth[0]

        # Step 3: Get the food's name so we can search for it.
        # MFP's search box doesn't accept mfp_ids directly -- only names.
        try:
            food_item = client.get_food_item_details(mfp_id)
            brand = getattr(food_item, "brand", "") or ""
            name = getattr(food_item, "name", "") or ""
            search_query = f"{brand} {name}".strip() or str(mfp_id)
        except Exception as details_err:
            # If we can't resolve the food's name, the id may simply be
            # invalid. Continue with the id as the query so the search step
            # gives a clean "no results" error, which is more actionable
            # than the lxml/HTTP failure here.
            logger.warning(
                f"Could not fetch details for food {mfp_id}: {details_err}"
            )
            search_query = str(mfp_id)

        # Trim to a reasonable length for the search box
        if len(search_query) > 60:
            search_query = search_query[:60]

        search_url = f"{client.BASE_URL_SECURE}food/search"
        search_resp = client.session.post(search_url, data={
            "authenticity_token": page_auth,
            "meal_name": meal,
            "search": search_query,
            "date": date_str,
            "page": "1",
        })
        search_html = search_resp.text

        # Find the link whose data-external-id matches mfp_id exactly.
        # We deliberately do NOT fall back to "first result" if the exact
        # match isn't there -- silently adding the wrong food to a diary
        # is a far worse failure mode than raising. The caller can use
        # mfp_search_food to pick a more specific id and retry.
        link_match = re.search(
            r'<a[^>]+class="search"[^>]+data-external-id="' + re.escape(str(mfp_id)) + r'"[^>]+data-original-id="(\d+)"[^>]+data-weight-ids="([^"]+)"',
            search_html,
        )
        if not link_match:
            # See if ANY results came back, to give the caller a hint about
            # whether the issue is "wrong id" vs "search returned nothing".
            has_any_results = bool(re.search(
                r'<a[^>]+class="search"[^>]+data-external-id=',
                search_html,
            ))
            if has_any_results:
                raise RuntimeError(
                    f"Food {mfp_id} (search query '{search_query}') was not "
                    "in the first page of search results. The mfp_id may be "
                    "stale or the food may be hard to surface from its name. "
                    "Try mfp_search_food with a more specific query, pick a "
                    "result whose mfp_id appears in the returned list, then "
                    "retry mfp_add_food_to_diary with that id."
                )
            raise RuntimeError(
                f"No search results returned for food {mfp_id} "
                f"(query '{search_query}'). Try mfp_search_food directly "
                "to find a valid id, then retry."
            )
        original_id = link_match.group(1)
        weight_ids = link_match.group(2).split(",")

        # CSRF tokens from the search results page
        page_csrf_match = re.search(
            r'<meta[^>]+name=["\']csrf-token["\'][^>]+content=["\']([^"\']+)["\']',
            search_html,
        )
        page_csrf = page_csrf_match.group(1) if page_csrf_match else None

        results_auth_matches = re.findall(
            r'authenticity_token["\'][^>]*value=["\']([^"\']+)["\']',
            search_html,
        )
        results_auth = results_auth_matches[0] if results_auth_matches else page_auth

        # Step 4: POST /food/add with the modern field names
        add_url = f"{client.BASE_URL_SECURE}food/add"
        payload = {
            "authenticity_token": results_auth,
            "food_entry[food_id]": original_id,
            "food_entry[date]": date_str,
            "food_entry[quantity]": str(quantity),
            "food_entry[weight_id]": weight_ids[0],
            "food_entry[meal_id]": meal_index,
        }
        headers = {
            "Referer": search_url,
            "Origin": "https://www.myfitnesspal.com",
        }
        if page_csrf:
            headers["X-CSRF-Token"] = page_csrf

        response = client.session.post(
            add_url, data=payload, headers=headers, allow_redirects=False
        )

        # Success = 302 redirect to /food/diary/* . Failure = 200 with form,
        # or 302 to /account/login, or 4xx.
        loc = response.headers.get("Location", "")
        if response.status_code in (302, 303) and "/food/diary" in loc:
            logger.info(
                f"Successfully added food {mfp_id} -> original_id={original_id} "
                f"to {meal} for {target_date}"
            )
            return
        if response.status_code in (302, 303) and "/account/login" in loc:
            raise RuntimeError(
                "Add failed: session not authenticated for write. "
                "Refresh the session cookie."
            )
        raise RuntimeError(
            f"Add failed: HTTP {response.status_code} -> {loc or '(no redirect)'}"
        )

    except RuntimeError:
        raise
    except Exception as e:
        raise RuntimeError(f"Failed to add food to diary: {e}")


def set_water_intake(client, target_date: date, cups: float) -> None:
    """
    Set water intake for a specific date.

    Args:
        client: Authenticated myfitnesspal.Client instance
        target_date: Date to set water intake
        cups: Number of cups of water

    Raises:
        RuntimeError: If the operation fails
    """
    from urllib import parse

    try:
        # Get the diary page for the target date to extract CSRF token
        date_str = target_date.strftime("%Y-%m-%d")
        diary_url = parse.urljoin(
            client.BASE_URL_SECURE,
            f"food/diary/{client.effective_username}?date={date_str}"
        )

        # Use the library's method to get the document
        document = client._get_document_for_url(diary_url)

        # Extract authenticity token
        authenticity_token = document.xpath(
            "(//input[@name='authenticity_token']/@value)[1]"
        )
        if not authenticity_token:
            raise RuntimeError("Could not find authenticity token on diary page")
        authenticity_token = authenticity_token[0]

        # Build the URL for setting water
        # MyFitnessPal uses /food/diary/{username}/water endpoint
        water_url = parse.urljoin(
            client.BASE_URL_SECURE,
            f"food/diary/{client.effective_username}/water"
        )

        # Prepare the data for the POST request
        post_data = {
            "authenticity_token": authenticity_token,
            "date": date_str,
            "water": str(cups),
        }

        # Set water intake
        headers = {
            "Referer": diary_url,
            "Content-Type": "application/x-www-form-urlencoded",
            "X-Requested-With": "XMLHttpRequest",
        }

        response = client.session.post(water_url, data=post_data, headers=headers)
        response.raise_for_status()

        if response.status_code != 200:
            raise RuntimeError(f"Failed to set water: HTTP {response.status_code}")

        logger.info(f"Successfully set water intake to {cups} cups for {target_date}")

    except Exception as e:
        # Don't expose internal error details to avoid leaking sensitive information
        error_msg = str(e)
        # Only include safe error information
        if "HTTP" in error_msg or "status" in error_msg.lower():
            raise RuntimeError(f"Failed to set water intake: {error_msg}")
        else:
            raise RuntimeError("Failed to set water intake. Please check your authentication and try again.")


# ============================================================================
# MCP Tools
# ============================================================================


@mcp.tool(
    name="mfp_get_diary",
    annotations={
        "title": "Get Food Diary",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def mfp_get_diary(params: GetDiaryInput) -> str:
    """
    Get the food diary for a specific date including all meals and their nutritional information.

    Returns meals (Breakfast, Lunch, Dinner, Snacks) with each food entry's name,
    quantity, and complete nutrition breakdown (calories, protein, carbs, fat, etc.).
    Also includes daily totals and goals.

    Args:
        params: GetDiaryInput containing:
            - date (str, optional): Date in YYYY-MM-DD format, defaults to today
            - response_format (str): 'markdown' or 'json'

    Returns:
        str: Formatted diary data with meals, entries, nutrition, and goals
    """
    try:
        client = get_mfp_client()
        target_date = parse_date(params.date)
        day = client.get_date(target_date)

        # Build response data
        data = {
            "date": str(target_date),
            "meals": {},
            "daily_totals": {},
            "daily_goals": {},
            "water": day.water,
            "notes": day.notes or "",
        }

        # Process meals
        for meal in day.meals:
            meal_data = {
                "entries": [format_meal_entry(entry) for entry in meal.entries],
                "totals": format_nutrition_dict(meal.totals),
            }
            data["meals"][meal.name] = meal_data

        # Get daily totals and goals
        totals = {}
        for entry in day.entries:
            for key, value in entry.totals.items():
                val = float(value.magnitude) if hasattr(value, "magnitude") else value
                totals[key] = totals.get(key, 0) + val
        data["daily_totals"] = totals
        data["daily_goals"] = day.goals

        return format_response(
            data, params.response_format, f"Food Diary for {target_date}"
        )

    except Exception as e:
        return f"Error retrieving diary: {str(e)}"


@mcp.tool(
    name="mfp_search_food",
    annotations={
        "title": "Search Food Database",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def mfp_search_food(params: SearchFoodInput) -> str:
    """
    Search the MyFitnessPal food database for food items.

    Returns a list of matching foods with their name, brand, serving size,
    calories, and MFP ID (which can be used with mfp_get_food_details).

    Args:
        params: SearchFoodInput containing:
            - query (str): Search query (e.g., 'chicken breast')
            - limit (int): Maximum results to return (default 10)
            - response_format (str): 'markdown' or 'json'

    Returns:
        str: List of matching food items with basic nutrition info
    """
    try:
        client = get_mfp_client()
        results = client.get_food_search_results(params.query)

        # Limit results
        results = results[: params.limit]

        data = {"query": params.query, "count": len(results), "results": []}

        for item in results:
            data["results"].append(
                {
                    "name": item.name,
                    "brand": item.brand,
                    "serving": item.serving,
                    "calories": item.calories,
                    "mfp_id": item.mfp_id,
                }
            )

        return format_response(
            data, params.response_format, f"Food Search Results for '{params.query}'"
        )

    except Exception as e:
        return f"Error searching foods: {str(e)}"


@mcp.tool(
    name="mfp_get_food_details",
    annotations={
        "title": "Get Food Item Details",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def mfp_get_food_details(params: GetFoodDetailsInput) -> str:
    """
    Get detailed nutritional information for a specific food item by its MFP ID.

    Returns complete nutrition breakdown including calories, macros (protein, carbs, fat),
    fiber, sugar, sodium, cholesterol, vitamins, minerals, and available serving sizes.

    Args:
        params: GetFoodDetailsInput containing:
            - mfp_id (str): MyFitnessPal food item ID from search results
            - response_format (str): 'markdown' or 'json'

    Returns:
        str: Complete nutritional information for the food item
    """
    try:
        client = get_mfp_client()
        item = client.get_food_item_details(params.mfp_id)

        data = {
            "mfp_id": params.mfp_id,
            "description": getattr(item, "description", "N/A"),
            "brand_name": getattr(item, "brand_name", None),
            "verified": getattr(item, "verified", False),
            "calories": getattr(item, "calories", None),
            "nutrition": {
                "protein": getattr(item, "protein", None),
                "carbohydrates": getattr(item, "carbohydrates", None),
                "fat": getattr(item, "fat", None),
                "fiber": getattr(item, "fiber", None),
                "sugar": getattr(item, "sugar", None),
                "sodium": getattr(item, "sodium", None),
                "cholesterol": getattr(item, "cholesterol", None),
                "saturated_fat": getattr(item, "saturated_fat", None),
                "polyunsaturated_fat": getattr(item, "polyunsaturated_fat", None),
                "monounsaturated_fat": getattr(item, "monounsaturated_fat", None),
                "trans_fat": getattr(item, "trans_fat", None),
                "potassium": getattr(item, "potassium", None),
                "vitamin_a": getattr(item, "vitamin_a", None),
                "vitamin_c": getattr(item, "vitamin_c", None),
                "calcium": getattr(item, "calcium", None),
                "iron": getattr(item, "iron", None),
            },
            "servings": [],
        }

        # Get serving sizes if available
        if hasattr(item, "servings"):
            for serving in item.servings:
                data["servings"].append(str(serving))

        return format_response(data, params.response_format, "Food Item Details")

    except Exception as e:
        return f"Error getting food details: {str(e)}"


@mcp.tool(
    name="mfp_get_measurements",
    annotations={
        "title": "Get Body Measurements",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def mfp_get_measurements(params: GetMeasurementsInput) -> str:
    """
    Get body measurements (weight, body fat, etc.) over a date range.

    Returns historical measurement data with dates and values. Useful for
    tracking weight loss progress and body composition changes.

    Args:
        params: GetMeasurementsInput containing:
            - measurement (str): Type of measurement (default 'Weight')
            - start_date (str, optional): Start date, defaults to 30 days ago
            - end_date (str, optional): End date, defaults to today
            - response_format (str): 'markdown' or 'json'

    Returns:
        str: Measurement history with dates and values
    """
    try:
        client = get_mfp_client()

        end = parse_date(params.end_date)
        if params.start_date:
            start = parse_date(params.start_date)
        else:
            start = end - timedelta(days=30)

        measurements = client.get_measurements(params.measurement, start, end)

        data = {
            "measurement_type": params.measurement,
            "start_date": str(start),
            "end_date": str(end),
            "count": len(measurements),
            "values": ordered_dict_to_dict(measurements),
        }

        # Calculate summary stats if we have data
        if measurements:
            values = list(measurements.values())
            data["summary"] = {
                "latest": values[-1] if values else None,
                "earliest": values[0] if values else None,
                "change": round(values[-1] - values[0], 2) if len(values) >= 2 else 0,
                "min": min(values),
                "max": max(values),
                "average": round(sum(values) / len(values), 2),
            }

        return format_response(
            data, params.response_format, f"{params.measurement} History"
        )

    except Exception as e:
        return f"Error getting measurements: {str(e)}"


@mcp.tool(
    name="mfp_set_measurement",
    annotations={
        "title": "Log Body Measurement",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": True,
    },
)
async def mfp_set_measurement(params: SetMeasurementInput) -> str:
    """
    Log a new body measurement (weight, body fat, etc.) for today.

    Records the measurement value in MyFitnessPal for tracking progress.

    Args:
        params: SetMeasurementInput containing:
            - measurement (str): Type of measurement (default 'Weight')
            - value (float): Measurement value (e.g., 185.5)

    Returns:
        str: Confirmation message with the logged value
    """
    try:
        client = get_mfp_client()
        client.set_measurements(params.measurement, params.value)

        return json.dumps(
            {
                "success": True,
                "message": f"Successfully logged {params.measurement}: {params.value}",
                "measurement": params.measurement,
                "value": params.value,
                "date": str(date.today()),
            },
            indent=2,
        )

    except Exception as e:
        return f"Error setting measurement: {str(e)}"


@mcp.tool(
    name="mfp_get_exercises",
    annotations={
        "title": "Get Exercise Log",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def mfp_get_exercises(params: GetExercisesInput) -> str:
    """
    Get logged exercises for a specific date.

    Returns both cardiovascular and strength training exercises with their
    details (duration, calories burned, sets, reps, weight, etc.).

    Args:
        params: GetExercisesInput containing:
            - date (str, optional): Date in YYYY-MM-DD format, defaults to today
            - response_format (str): 'markdown' or 'json'

    Returns:
        str: List of exercises with details and calories burned
    """
    try:
        client = get_mfp_client()
        target_date = parse_date(params.date)
        day = client.get_date(target_date)

        data = {"date": str(target_date), "exercises": []}

        for exercise in day.exercises:
            data["exercises"].append(format_exercise(exercise))

        # Calculate total calories burned
        total_burned = 0
        for ex in data["exercises"]:
            for entry in ex.get("entries", []):
                if "nutrition_information" in entry:
                    total_burned += entry["nutrition_information"].get(
                        "calories burned", 0
                    )

        data["total_calories_burned"] = total_burned

        return format_response(
            data, params.response_format, f"Exercise Log for {target_date}"
        )

    except Exception as e:
        return f"Error getting exercises: {str(e)}"


@mcp.tool(
    name="mfp_get_goals",
    annotations={
        "title": "Get Nutrition Goals",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def mfp_get_goals(params: GetGoalsInput) -> str:
    """
    Get the user's daily nutrition goals (calories, protein, carbs, fat, etc.).

    Returns the configured daily targets for all tracked nutrients.

    Args:
        params: GetGoalsInput containing:
            - date (str, optional): Date in YYYY-MM-DD format, defaults to today
            - response_format (str): 'markdown' or 'json'

    Returns:
        str: Daily nutrition goals and targets
    """
    try:
        client = get_mfp_client()
        target_date = parse_date(params.date)
        day = client.get_date(target_date)

        data = {"date": str(target_date), "goals": day.goals}

        return format_response(data, params.response_format, "Daily Nutrition Goals")

    except Exception as e:
        return f"Error getting goals: {str(e)}"


@mcp.tool(
    name="mfp_set_goals",
    annotations={
        "title": "Update Nutrition Goals",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def mfp_set_goals(params: SetGoalsInput) -> str:
    """
    Update daily nutrition goals (calories, protein, carbs, fat).

    Sets new daily targets for the specified nutrients. Only updates the
    values that are provided; others remain unchanged.

    Args:
        params: SetGoalsInput containing:
            - calories (int, optional): Daily calorie goal
            - protein (int, optional): Daily protein goal in grams
            - carbohydrates (int, optional): Daily carb goal in grams
            - fat (int, optional): Daily fat goal in grams

    Returns:
        str: Confirmation message with updated goals
    """
    try:
        # Check that at least one goal is provided
        if not any(
            [params.calories, params.protein, params.carbohydrates, params.fat]
        ):
            return "Error: Please provide at least one goal to update (calories, protein, carbohydrates, or fat)"

        client = get_mfp_client()

        # Build kwargs for set_new_goal
        kwargs = {}
        if params.calories:
            kwargs["energy"] = params.calories
        if params.protein:
            kwargs["protein"] = params.protein
        if params.carbohydrates:
            kwargs["carbohydrates"] = params.carbohydrates
        if params.fat:
            kwargs["fat"] = params.fat

        client.set_new_goal(**kwargs)

        return json.dumps(
            {
                "success": True,
                "message": "Successfully updated nutrition goals",
                "updated_goals": {
                    "calories": params.calories,
                    "protein": params.protein,
                    "carbohydrates": params.carbohydrates,
                    "fat": params.fat,
                },
            },
            indent=2,
        )

    except Exception as e:
        return f"Error setting goals: {str(e)}"


@mcp.tool(
    name="mfp_get_water",
    annotations={
        "title": "Get Water Intake",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def mfp_get_water(params: GetWaterInput) -> str:
    """
    Get water intake for a specific date.

    Returns the number of cups/glasses of water logged for the day.

    Args:
        params: GetWaterInput containing:
            - date (str, optional): Date in YYYY-MM-DD format, defaults to today

    Returns:
        str: Water intake amount for the specified date
    """
    try:
        client = get_mfp_client()
        target_date = parse_date(params.date)
        day = client.get_date(target_date)

        data = {
            "date": str(target_date),
            "water_cups": day.water,
            "water_ml": day.water * 236.588,  # Convert cups to ml
        }

        return json.dumps(data, indent=2)

    except Exception as e:
        return f"Error getting water intake: {str(e)}"


@mcp.tool(
    name="mfp_add_food_to_diary",
    annotations={
        "title": "Add Food to Diary",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": True,
    },
)
async def mfp_add_food_to_diary(params: AddFoodToDiaryInput) -> str:
    """
    Add a food item to your MyFitnessPal food diary for a specific date and meal.

    This tool adds a food entry to your diary. You can search for foods using
    mfp_search_food to find the food ID (mfp_id) needed for this tool.

    Args:
        params: AddFoodToDiaryInput containing:
            - mfp_id (str): MyFitnessPal food item ID (from mfp_search_food)
            - meal (str): Meal name - 'Breakfast', 'Lunch', 'Dinner', or 'Snacks' (default: 'Breakfast')
            - date (str, optional): Date in YYYY-MM-DD format, defaults to today
            - quantity (float): Number of default servings for this food (default: 1.0)

    Returns:
        str: Confirmation message with details of the added food entry
    """
    try:
        client = get_mfp_client()
        target_date = parse_date(params.date)

        # Normalize meal name (capitalize first letter)
        meal = params.meal.strip().capitalize()
        if meal.lower() == "snack":
            meal = "Snacks"

        # Add food to diary
        add_food_to_diary(
            client=client,
            mfp_id=params.mfp_id,
            meal=meal,
            target_date=target_date,
            quantity=params.quantity,
        )

        # Get food details for confirmation
        try:
            food_item = client.get_food_item_details(params.mfp_id)
            food_name = getattr(food_item, "description", "Unknown Food")
        except Exception:
            food_name = "Food item"

        return json.dumps(
            {
                "success": True,
                "message": f"Successfully added {food_name} to {meal}",
                "date": str(target_date),
                "meal": meal,
                "food_id": params.mfp_id,
                "food_name": food_name,
                "quantity": params.quantity,
            },
            indent=2,
        )

    except Exception as e:
        return f"Error adding food to diary: {str(e)}"


@mcp.tool(
    name="mfp_set_water",
    annotations={
        "title": "Log Water Intake",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": True,
    },
)
async def mfp_set_water(params: SetWaterInput) -> str:
    """
    Log water intake for a specific date.

    Sets the number of cups of water consumed for the day. MyFitnessPal uses
    cups as the unit (1 cup = ~237ml).

    Args:
        params: SetWaterInput containing:
            - cups (float): Number of cups of water (e.g., 2.5 for 2.5 cups)
            - date (str, optional): Date in YYYY-MM-DD format, defaults to today

    Returns:
        str: Confirmation message with the logged water amount
    """
    try:
        client = get_mfp_client()
        target_date = parse_date(params.date)

        # Set water intake
        set_water_intake(client=client, target_date=target_date, cups=params.cups)

        return json.dumps(
            {
                "success": True,
                "message": f"Successfully logged {params.cups} cups of water",
                "date": str(target_date),
                "cups": params.cups,
                "milliliters": round(params.cups * 236.588, 2),
            },
            indent=2,
        )

    except Exception as e:
        return f"Error setting water intake: {str(e)}"


@mcp.tool(
    name="mfp_get_report",
    annotations={
        "title": "Get Nutrition Report",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def mfp_get_report(params: GetReportInput) -> str:
    """
    Get a nutrition report over a date range.

    Returns daily values for the specified nutrient/metric over the date range.
    Useful for analyzing trends and patterns in nutrition intake.

    Args:
        params: GetReportInput containing:
            - report_name (str): Report type (e.g., 'Net Calories', 'Protein')
            - start_date (str, optional): Start date, defaults to 7 days ago
            - end_date (str, optional): End date, defaults to today
            - response_format (str): 'markdown' or 'json'

    Returns:
        str: Daily values and summary statistics for the report period
    """
    try:
        client = get_mfp_client()

        end = parse_date(params.end_date)
        if params.start_date:
            start = parse_date(params.start_date)
        else:
            start = end - timedelta(days=7)

        report = client.get_report(
            report_name=params.report_name,
            report_category="Nutrition",
            lower_bound=start,
            upper_bound=end,
        )

        data = {
            "report_name": params.report_name,
            "start_date": str(start),
            "end_date": str(end),
            "values": (
                ordered_dict_to_dict(report) if isinstance(report, OrderedDict) else report
            ),
        }

        # Calculate summary stats
        if report:
            values = list(report.values())
            numeric_values = [v for v in values if isinstance(v, (int, float))]
            if numeric_values:
                data["summary"] = {
                    "total": sum(numeric_values),
                    "average": round(sum(numeric_values) / len(numeric_values), 2),
                    "min": min(numeric_values),
                    "max": max(numeric_values),
                }

        return format_response(
            data, params.response_format, f"{params.report_name} Report"
        )

    except Exception as e:
        return f"Error getting report: {str(e)}"


# ============================================================================
# Main Entry Point
# ============================================================================


def main():
    """Run the MCP server.

    Supports two transport modes controlled by MCP_TRANSPORT environment variable:
    - "stdio" (default): Standard input/output for local MCP clients
    - "streamable-http": HTTP server for remote/Docker deployments

    For HTTP mode, also supports:
    - MCP_HOST: Host to bind to (default: "127.0.0.1" for stdio, "0.0.0.0" for http)
    - MCP_PORT: Port to listen on (default: 8000)
    - MCP_ALLOWED_HOSTS: Comma-separated list of allowed Host headers for reverse proxy
      (e.g., "mfp.example.com,mfp.example.com:443")
      If not set, DNS rebinding protection is disabled for HTTP mode.
    """
    transport = os.getenv("MCP_TRANSPORT", "stdio")

    if transport == "streamable-http":
        mcp.run(transport="streamable-http")
    else:
        mcp.run()


if __name__ == "__main__":
    main()

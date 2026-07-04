"""Load MyFitnessPal session cookies for the MCP server.

MyFitnessPal's login page is protected by a captcha, so password login from
a headless server is effectively dead. Instead, the operator logs into
myfitnesspal.com once in a real Firefox profile and mounts that profile
(read-only) into the container; this module reads the session cookies
straight out of it.

Two sources, checked in order:

1. ``MFP_FIREFOX_PROFILE_DIR`` - path to a Firefox profile directory (or a
   directory containing one, e.g. a mounted ``~/.mozilla/firefox``). The
   ``cookies.sqlite`` database is COPIED to a temp file before reading:
   Firefox holds locks on the live file, and with SQLite in WAL mode the
   newest rows live in ``cookies.sqlite-wal``, which is copied alongside so
   the read sees a consistent, current snapshot.

2. ``MFP_COOKIES_FILE`` - JSON file of session cookies. Accepts both the
   ``{"cookies": {name: value}, "saved_at": ...}`` format used by AdamWalt's
   original myfitnesspal-mcp-python (``~/.mfp_mcp/cookies.json``) and a plain
   ``{name: value}`` dict.

``get_cookiejar()`` caches the built jar and only re-reads a source when its
file mtime/size changes, so each MCP tool call doesn't re-copy the sqlite
database. The same jar OBJECT is returned while the source is unchanged,
which lets callers cache derived state (e.g. a myfitnesspal.Client) keyed on
jar identity.
"""

import json
import logging
import os
import shutil
import sqlite3
import tempfile
import threading
import time
from http.cookiejar import Cookie, CookieJar
from pathlib import Path

logger = logging.getLogger(__name__)

MFP_DOMAIN_SUFFIX = "myfitnesspal.com"

_cache_lock = threading.Lock()
# (source_kind, source_path) -> (stat_signature, CookieJar)
_cache: dict[tuple[str, str], tuple[tuple, CookieJar]] = {}


def _make_cookie(
    name: str,
    value: str,
    domain: str = f".{MFP_DOMAIN_SUFFIX}",
    path: str = "/",
    secure: bool = True,
    expires: int | None = None,
) -> Cookie:
    """Build an http.cookiejar.Cookie (cookie-dict construction ported from
    AdamWalt's myfitnesspal-mcp-python)."""
    if expires is None:
        expires = int(time.time()) + 86400 * 30  # 30 days from now
    return Cookie(
        version=0,
        name=name,
        value=value,
        port=None,
        port_specified=False,
        domain=domain,
        domain_specified=True,
        domain_initial_dot=domain.startswith("."),
        path=path,
        path_specified=True,
        secure=secure,
        expires=expires,
        discard=False,
        comment=None,
        comment_url=None,
        rest={"HttpOnly": None},
        rfc2109=False,
    )


# ---------------------------------------------------------------------------
# Source 1: Firefox profile (cookies.sqlite)
# ---------------------------------------------------------------------------


def _find_cookies_sqlite(profile_dir: Path) -> Path | None:
    """Locate cookies.sqlite in profile_dir, or one level down.

    Handles both a profile directory being mounted directly and a whole
    ~/.mozilla/firefox directory (profiles are subdirectories like
    ``abcd1234.default-release``) being mounted.
    """
    direct = profile_dir / "cookies.sqlite"
    if direct.is_file():
        return direct
    candidates = sorted(
        profile_dir.glob("*/cookies.sqlite"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    return candidates[0] if candidates else None


def _firefox_stat_signature(db_path: Path) -> tuple:
    """Change-detection signature: mtime+size of the db and its WAL."""
    parts = []
    for p in (db_path, db_path.with_name(db_path.name + "-wal")):
        try:
            st = p.stat()
            parts.append((str(p), st.st_mtime_ns, st.st_size))
        except FileNotFoundError:
            parts.append((str(p), None, None))
    return tuple(parts)


def _load_firefox_cookiejar(db_path: Path) -> CookieJar:
    """Read MyFitnessPal cookies out of a (copied) Firefox cookies.sqlite."""
    tmpdir = tempfile.mkdtemp(prefix="mfp-cookies-")
    try:
        # Copy the database out first: Firefox keeps the live file locked,
        # and sqlite refuses to read a locked db over some mounts. Copy the
        # WAL (and -shm, if readable) too so uncheckpointed rows are seen.
        tmp_db = Path(tmpdir) / "cookies.sqlite"
        shutil.copy2(db_path, tmp_db)
        for suffix in ("-wal", "-shm"):
            side = db_path.with_name(db_path.name + suffix)
            if side.is_file():
                try:
                    shutil.copy2(side, tmp_db.with_name(tmp_db.name + suffix))
                except OSError as e:
                    logger.warning("Could not copy %s: %s", side, e)

        jar = CookieJar()
        conn = sqlite3.connect(tmp_db)
        try:
            rows = conn.execute(
                "SELECT host, path, isSecure, expiry, name, value "
                "FROM moz_cookies WHERE host LIKE ?",
                (f"%{MFP_DOMAIN_SUFFIX}",),
            ).fetchall()
        finally:
            conn.close()

        now = time.time()
        for host, path, is_secure, expiry, name, value in rows:
            if expiry and expiry < now:
                continue  # skip already-expired cookies
            jar.set_cookie(
                _make_cookie(
                    name=name,
                    value=value,
                    domain=host,
                    path=path or "/",
                    secure=bool(is_secure),
                    expires=int(expiry) if expiry else None,
                )
            )
        if len(jar) == 0:
            raise RuntimeError(
                f"No {MFP_DOMAIN_SUFFIX} cookies found in {db_path}. "
                "Log into myfitnesspal.com in this Firefox profile first."
            )
        logger.info("Loaded %d MyFitnessPal cookies from %s", len(jar), db_path)
        return jar
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Source 2: JSON cookies file (AdamWalt's ~/.mfp_mcp/cookies.json format)
# ---------------------------------------------------------------------------


def _json_stat_signature(path: Path) -> tuple:
    st = path.stat()
    return ((str(path), st.st_mtime_ns, st.st_size),)


def _load_json_cookiejar(path: Path) -> CookieJar:
    """Build a CookieJar from a JSON cookies file."""
    with open(path) as f:
        data = json.load(f)
    cookies = data.get("cookies", data) if isinstance(data, dict) else None
    if not isinstance(cookies, dict) or not cookies:
        raise RuntimeError(
            f"{path} does not contain a cookie dict "
            '(expected {"cookies": {name: value}} or {name: value})'
        )
    jar = CookieJar()
    for name, value in cookies.items():
        jar.set_cookie(_make_cookie(name=name, value=str(value)))
    logger.info("Loaded %d MyFitnessPal cookies from %s", len(jar), path)
    return jar


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def get_cookiejar() -> CookieJar:
    """Return a CookieJar of MyFitnessPal session cookies.

    Checks MFP_FIREFOX_PROFILE_DIR first, then MFP_COOKIES_FILE. Cached with
    mtime-based invalidation: while the underlying file is unchanged, the
    same CookieJar object is returned without touching the sqlite database.
    """
    profile_dir_env = os.environ.get("MFP_FIREFOX_PROFILE_DIR")
    cookies_file_env = os.environ.get("MFP_COOKIES_FILE")

    if profile_dir_env:
        profile_dir = Path(profile_dir_env)
        db_path = _find_cookies_sqlite(profile_dir) if profile_dir.is_dir() else None
        if db_path is not None:
            return _cached(
                ("firefox", str(db_path)),
                lambda: _firefox_stat_signature(db_path),
                lambda: _load_firefox_cookiejar(db_path),
            )
        # Fall through to MFP_COOKIES_FILE (e.g. default /profile mount left
        # empty in Docker while a JSON cookies file is configured instead).
        if not cookies_file_env:
            raise RuntimeError(
                f"MFP_FIREFOX_PROFILE_DIR={profile_dir_env} does not contain a "
                "cookies.sqlite (looked in the directory and one level down). "
                "Mount a Firefox profile that is logged into myfitnesspal.com, "
                "or set MFP_COOKIES_FILE instead."
            )
        logger.warning(
            "No cookies.sqlite under MFP_FIREFOX_PROFILE_DIR=%s; "
            "falling back to MFP_COOKIES_FILE",
            profile_dir_env,
        )

    if cookies_file_env:
        cookies_file = Path(cookies_file_env)
        if not cookies_file.is_file():
            raise RuntimeError(f"MFP_COOKIES_FILE={cookies_file_env} does not exist")
        return _cached(
            ("json", str(cookies_file)),
            lambda: _json_stat_signature(cookies_file),
            lambda: _load_json_cookiejar(cookies_file),
        )

    raise RuntimeError(
        "No cookie source configured. Set MFP_FIREFOX_PROFILE_DIR to a mounted "
        "Firefox profile directory (logged into myfitnesspal.com), or "
        "MFP_COOKIES_FILE to a JSON cookies file."
    )


def _cached(key: tuple[str, str], signature_fn, loader_fn) -> CookieJar:
    """Return the cached jar for key unless its stat signature changed."""
    signature = signature_fn()
    with _cache_lock:
        cached = _cache.get(key)
        if cached is not None and cached[0] == signature:
            return cached[1]
    jar = loader_fn()
    with _cache_lock:
        _cache[key] = (signature, jar)
    return jar


def clear_cache() -> None:
    """Drop all cached cookie jars (mainly for tests)."""
    with _cache_lock:
        _cache.clear()

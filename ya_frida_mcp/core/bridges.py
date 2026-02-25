"""Download and cache Frida bridge JS files (Java/ObjC/Swift) from GitHub releases."""

import logging
import urllib.request
from pathlib import Path

logger = logging.getLogger(__name__)

_BRIDGE_NAMES = ("java.js", "objc.js", "swift.js")
_CACHE_DIR = Path.home() / ".cache" / "ya-frida-mcp" / "bridges"
_REPO = "1shin-7/ya-frida-mcp"
_RELEASE_TAG = "bridges"
_ASSET_URL = f"https://github.com/{_REPO}/releases/download/{_RELEASE_TAG}"
_VERSION_FILE = "version.txt"


def _cached_version() -> str | None:
    """Read the cached frida-tools version, if any."""
    vf = _CACHE_DIR / _VERSION_FILE
    if vf.is_file():
        return vf.read_text().strip()
    return None


def _remote_version() -> str | None:
    """Fetch version.txt from the GitHub release (lightweight check)."""
    try:
        with urllib.request.urlopen(f"{_ASSET_URL}/{_VERSION_FILE}", timeout=10) as resp:
            return resp.read().decode().strip()
    except Exception:
        return None


def _download_bridges(dest: Path) -> bool:
    """Download bridge JS files + version.txt from the GitHub release."""
    dest.mkdir(parents=True, exist_ok=True)
    for name in (*_BRIDGE_NAMES, _VERSION_FILE):
        url = f"{_ASSET_URL}/{name}"
        logger.info("Downloading %s ...", url)
        try:
            with urllib.request.urlopen(url, timeout=120) as resp:
                (dest / name).write_bytes(resp.read())
        except Exception:
            logger.debug("Failed to download %s", name, exc_info=True)
            return False
    return True


def _cache_complete() -> bool:
    """Return True if all bridge JS files exist in cache."""
    return _CACHE_DIR.is_dir() and all((_CACHE_DIR / n).is_file() for n in _BRIDGE_NAMES)


def ensure_bridges() -> Path | None:
    """Return a directory containing java.js / objc.js / swift.js, or None.

    Checks local cache first; downloads from the GitHub ``bridges`` release
    if missing or stale.  Returns ``None`` on any failure (graceful degradation).
    """
    cached_ver = _cached_version() if _cache_complete() else None

    if cached_ver is not None:
        # Cache exists - check for updates (best-effort)
        remote_ver = _remote_version()
        if remote_ver is None or remote_ver == cached_ver:
            # Offline or up-to-date
            return _CACHE_DIR
        logger.info("Bridge update: %s -> %s", cached_ver, remote_ver)

    # Download (first run or version mismatch)
    try:
        logger.info("Downloading bridges from GitHub release...")
        if _download_bridges(_CACHE_DIR):
            logger.info("Bridges cached at %s", _CACHE_DIR)
            return _CACHE_DIR
        logger.warning("Some bridge JS files could not be downloaded")
    except Exception:
        logger.debug("Failed to fetch bridges", exc_info=True)

    # Fallback: partial cache still usable
    if _cache_complete():
        return _CACHE_DIR
    return None

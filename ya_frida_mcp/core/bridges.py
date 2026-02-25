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


def _download_bridges(dest: Path) -> bool:
    """Download the three bridge JS files from the GitHub release."""
    dest.mkdir(parents=True, exist_ok=True)
    for name in _BRIDGE_NAMES:
        url = f"{_ASSET_URL}/{name}"
        logger.info("Downloading %s ...", url)
        try:
            with urllib.request.urlopen(url, timeout=120) as resp:
                (dest / name).write_bytes(resp.read())
        except Exception:
            logger.debug("Failed to download %s", name, exc_info=True)
            return False
    return True


def ensure_bridges() -> Path | None:
    """Return a directory containing java.js / objc.js / swift.js, or None.

    Checks local cache first; downloads from the GitHub ``bridges`` release
    if missing.  Returns ``None`` on any failure (graceful degradation).
    """
    # 1. Cached and complete → return immediately
    if _CACHE_DIR.is_dir() and all((_CACHE_DIR / n).is_file() for n in _BRIDGE_NAMES):
        return _CACHE_DIR

    # 2. Download from GitHub release
    try:
        logger.info("Bridge JS cache miss - downloading from GitHub release...")
        if _download_bridges(_CACHE_DIR):
            logger.info("Bridges cached at %s", _CACHE_DIR)
            return _CACHE_DIR
        logger.warning("Some bridge JS files could not be downloaded")
    except Exception:
        logger.debug("Failed to fetch bridges", exc_info=True)

    return None

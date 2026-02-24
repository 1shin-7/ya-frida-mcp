"""Shared structured output helpers for MCP tool responses."""

from __future__ import annotations

from typing import Any


def ok(detail: str, **extra: Any) -> dict[str, Any]:
    """Build a success response dict."""
    result: dict[str, Any] = {"ok": True, "detail": detail}
    result.update(extra)
    return result


def err(detail: str, **extra: Any) -> dict[str, Any]:
    """Build an error response dict."""
    result: dict[str, Any] = {"ok": False, "error": detail}
    result.update(extra)
    return result

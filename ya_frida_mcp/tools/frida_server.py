"""Frida-server management MCP tools — registered only when ``adb`` is on PATH."""

from __future__ import annotations

from typing import Any

import frida
from fastmcp import FastMCP
from fastmcp.server.context import Context

from ya_frida_mcp.core.adb import ADBClient, ADBError
from ya_frida_mcp.core.frida_server import (
    download_frida_server,
    get_device_abi,
    get_server_status,
    push_and_start,
    stop_server,
)
from ya_frida_mcp.core.output import err, ok


def register_frida_server_tools(mcp: FastMCP) -> None:
    """Register frida-server lifecycle MCP tools."""

    def _client(ctx: Context, device: str | None = None) -> ADBClient:
        base: ADBClient = ctx.lifespan_context["adb_client"]
        if device and device != base.device_id:
            return ADBClient(device_id=device)
        return base

    @mcp.tool
    async def frida_server_status(
        ctx: Context, device: str | None = None
    ) -> dict[str, Any]:
        """Check if frida-server is running on the device and whether its version matches the local Frida client."""
        try:
            return await get_server_status(_client(ctx, device))
        except ADBError as e:
            return err(e.stderr)

    @mcp.tool
    async def frida_server_install(
        ctx: Context,
        device: str | None = None,
        version: str | None = None,
    ) -> dict[str, Any]:
        """Download and push frida-server to the device.

        If *version* is omitted, uses the locally installed Frida client version
        to ensure client/server compatibility.
        """
        adb = _client(ctx, device)
        target_version = version or frida.__version__
        try:
            abi = await get_device_abi(adb)
            local_path = download_frida_server(target_version, abi)
            result = await push_and_start(adb, local_path)
            return ok(result, version=target_version, abi=abi)
        except ADBError as e:
            return err(e.stderr, version=target_version)
        except (ValueError, OSError) as e:
            return err(str(e), version=target_version)

    @mcp.tool
    async def frida_server_start(
        ctx: Context, device: str | None = None
    ) -> dict[str, Any]:
        """Start frida-server on the device (must already be pushed)."""
        adb = _client(ctx, device)
        try:
            await adb.shell(
                "setsid /data/local/tmp/frida-server -D </dev/null >/dev/null 2>&1 &",
            )
            pid_out = await adb.shell("pidof frida-server")
            pid = pid_out.strip()
            if pid:
                return ok(f"frida-server started (pid {pid})")
            return ok("frida-server start command issued (could not confirm pid)")
        except ADBError as e:
            return err(e.stderr)

    @mcp.tool
    async def frida_server_stop(
        ctx: Context, device: str | None = None
    ) -> dict[str, Any]:
        """Stop frida-server on the device."""
        try:
            detail = await stop_server(_client(ctx, device))
            return ok(detail)
        except ADBError as e:
            return err(e.stderr)

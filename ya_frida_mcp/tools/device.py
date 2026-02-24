"""Device discovery and remote connection tools."""

from __future__ import annotations

from fastmcp import FastMCP
from fastmcp.server.context import Context

from ya_frida_mcp.core.device import DeviceManager


def register_device_tools(mcp: FastMCP) -> None:
    """Register all device-related MCP tools."""

    @mcp.tool
    async def frida_ls_devices(ctx: Context) -> list[dict]:
        """List all available Frida devices (local, USB, remote)."""
        dm: DeviceManager = ctx.lifespan_context["device_manager"]
        devices = await dm.enumerate_devices()
        return [
            {"id": d.id, "name": d.name, "type": d.dtype}
            for d in devices
        ]

    @mcp.tool
    async def frida_get_device(
        ctx: Context,
        device_id: str | None = None,
    ) -> dict:
        """Get info for a specific device. Uses default device if ID is omitted."""
        dm: DeviceManager = ctx.lifespan_context["device_manager"]
        device = await dm.get_device(device_id)
        return {"id": device.id, "name": device.name, "type": device.dtype}

    @mcp.tool
    async def frida_add_remote(
        ctx: Context,
        host: str,
        port: int = 27042,
    ) -> dict:
        """Connect to a remote Frida server (frida-server over TCP)."""
        dm: DeviceManager = ctx.lifespan_context["device_manager"]
        device = await dm.add_remote(host, port)
        return {"id": device.id, "name": device.name, "type": device.dtype}

    @mcp.tool
    async def frida_remove_remote(
        ctx: Context,
        host: str,
        port: int = 27042,
    ) -> str:
        """Disconnect from a remote Frida server."""
        dm: DeviceManager = ctx.lifespan_context["device_manager"]
        await dm.remove_remote(host, port)
        return f"Removed remote device at {host}:{port}"

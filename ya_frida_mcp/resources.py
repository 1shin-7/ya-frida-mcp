"""MCP resource registrations for Frida state."""

from __future__ import annotations

from fastmcp import FastMCP
from fastmcp.server.context import Context

from ya_frida_mcp.core.device import DeviceManager
from ya_frida_mcp.core.session import SessionManager


def register_resources(mcp: FastMCP) -> None:
    """Register all MCP resources."""

    @mcp.resource("frida://devices")
    async def devices_resource(ctx: Context) -> list[dict]:
        """Live list of all connected Frida devices."""
        dm: DeviceManager = ctx.lifespan_context["device_manager"]
        devices = await dm.enumerate_devices()
        return [{"id": d.id, "name": d.name, "type": d.dtype} for d in devices]

    @mcp.resource("frida://sessions")
    async def sessions_resource(ctx: Context) -> dict:
        """Current active sessions and scripts."""
        sm: SessionManager = ctx.lifespan_context["session_manager"]
        return {
            "active_sessions": sm.list_sessions(),
            "active_scripts": sm.list_scripts(),
        }

    @mcp.resource("frida://device/{device_id}/processes")
    async def processes_resource(device_id: str, ctx: Context) -> list[dict]:
        """Live process list for a specific device."""
        dm: DeviceManager = ctx.lifespan_context["device_manager"]
        device = await dm.get_device(device_id)
        processes = await device.enumerate_processes()
        return [{"pid": p.pid, "name": p.name} for p in processes]

    @mcp.resource("frida://device/{device_id}/apps")
    async def apps_resource(device_id: str, ctx: Context) -> list[dict]:
        """Installed applications for a specific device."""
        dm: DeviceManager = ctx.lifespan_context["device_manager"]
        device = await dm.get_device(device_id)
        apps = await device.enumerate_applications()
        return [
            {"identifier": a.identifier, "name": a.name, "pid": a.pid}
            for a in apps
        ]

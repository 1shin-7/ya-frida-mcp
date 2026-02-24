"""Application enumeration tools (frida-ls)."""

from fastmcp import FastMCP
from fastmcp.server.context import Context

from ya_frida_mcp.core.device import DeviceManager


def register_app_tools(mcp: FastMCP) -> None:
    """Register all application-related MCP tools."""

    @mcp.tool
    async def frida_ls_apps(
        ctx: Context,
        device_id: str | None = None,
    ) -> list[dict]:
        """List installed applications on a device (frida-ls equivalent).

        Returns identifier, name, and PID (if running).
        """
        dm: DeviceManager = ctx.lifespan_context["device_manager"]
        device = await dm.get_device(device_id)
        apps = await device.enumerate_applications()
        return [
            {"identifier": a.identifier, "name": a.name, "pid": a.pid}
            for a in apps
        ]

    @mcp.tool
    async def frida_ls_apps_running(
        ctx: Context,
        device_id: str | None = None,
    ) -> list[dict]:
        """List only currently running applications."""
        dm: DeviceManager = ctx.lifespan_context["device_manager"]
        device = await dm.get_device(device_id)
        apps = await device.enumerate_applications()
        return [
            {"identifier": a.identifier, "name": a.name, "pid": a.pid}
            for a in apps
            if a.pid != 0
        ]

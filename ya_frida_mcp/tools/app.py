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
        scope: str | None = None,
        identifiers: list[str] | None = None,
    ) -> list[dict]:
        """List installed applications on a device (frida-ls equivalent).

        Returns identifier, name, and PID (if running).

        Args:
            device_id: Target device. Uses default if omitted.
            scope: Enumeration scope — "minimal", "metadata", or "full".
                   When "full", includes parameters (version, build, etc.).
            identifiers: Optional list of bundle identifiers to filter by.
        """
        dm: DeviceManager = ctx.lifespan_context["device_manager"]
        device = await dm.get_device(device_id)
        apps = await device.enumerate_applications(identifiers=identifiers, scope=scope)
        result = []
        for a in apps:
            entry: dict = {"identifier": a.identifier, "name": a.name, "pid": a.pid}
            if scope == "full" and hasattr(a, "parameters"):
                params = dict(a.parameters)
                params.pop("icons", None)
                entry["parameters"] = params
            result.append(entry)
        return result

    @mcp.tool
    async def frida_ls_apps_running(
        ctx: Context,
        device_id: str | None = None,
        scope: str | None = None,
        identifiers: list[str] | None = None,
    ) -> list[dict]:
        """List only currently running applications.

        Args:
            device_id: Target device. Uses default if omitted.
            scope: Enumeration scope — "minimal", "metadata", or "full".
            identifiers: Optional list of bundle identifiers to filter by.
        """
        dm: DeviceManager = ctx.lifespan_context["device_manager"]
        device = await dm.get_device(device_id)
        apps = await device.enumerate_applications(identifiers=identifiers, scope=scope)
        result = []
        for a in apps:
            if a.pid == 0:
                continue
            entry: dict = {"identifier": a.identifier, "name": a.name, "pid": a.pid}
            if scope == "full" and hasattr(a, "parameters"):
                params = dict(a.parameters)
                params.pop("icons", None)
                entry["parameters"] = params
            result.append(entry)
        return result

    # --- Phase 1: frontmost application ---

    @mcp.tool
    async def frida_get_frontmost_application(
        ctx: Context,
        device_id: str | None = None,
        scope: str | None = None,
    ) -> dict | None:
        """Get details about the frontmost application.

        Args:
            device_id: Target device. Uses default if omitted.
            scope: Enumeration scope — "minimal", "metadata", or "full".
        """
        dm: DeviceManager = ctx.lifespan_context["device_manager"]
        device = await dm.get_device(device_id)
        app = await device.get_frontmost_application(scope=scope)
        if app is None:
            return None
        entry: dict = {
            "identifier": app.identifier,
            "name": app.name,
            "pid": app.pid,
        }
        if scope == "full" and hasattr(app, "parameters"):
            params = dict(app.parameters)
            params.pop("icons", None)
            entry["parameters"] = params
        return entry

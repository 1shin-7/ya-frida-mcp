"""Device discovery and remote connection tools."""

import base64

from fastmcp import FastMCP
from fastmcp.server.context import Context

from ya_frida_mcp.core.device import DeviceManager
from ya_frida_mcp.core.output import ok


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
    ) -> dict:
        """Disconnect from a remote Frida server."""
        dm: DeviceManager = ctx.lifespan_context["device_manager"]
        await dm.remove_remote(host, port)
        return ok(f"Removed {host}:{port}")

    # --- Phase 1: system info ---

    @mcp.tool
    async def frida_query_system_parameters(
        ctx: Context,
        device_id: str | None = None,
    ) -> dict:
        """Returns a dictionary of information about the host system.

        Args:
            device_id: Target device. Uses default if omitted.
        """
        dm: DeviceManager = ctx.lifespan_context["device_manager"]
        device = await dm.get_device(device_id)
        return await device.query_system_parameters()

    # --- Phase 2: spawn gating ---

    @mcp.tool
    async def frida_enable_spawn_gating(
        ctx: Context,
        device_id: str | None = None,
    ) -> dict:
        """Enable spawn gating on the device.

        When enabled, newly spawned processes are suspended until explicitly resumed.

        Args:
            device_id: Target device. Uses default if omitted.
        """
        dm: DeviceManager = ctx.lifespan_context["device_manager"]
        device = await dm.get_device(device_id)
        await device.enable_spawn_gating()
        return ok("Spawn gating enabled")

    @mcp.tool
    async def frida_disable_spawn_gating(
        ctx: Context,
        device_id: str | None = None,
    ) -> dict:
        """Disable spawn gating on the device.

        Args:
            device_id: Target device. Uses default if omitted.
        """
        dm: DeviceManager = ctx.lifespan_context["device_manager"]
        device = await dm.get_device(device_id)
        await device.disable_spawn_gating()
        return ok("Spawn gating disabled")

    @mcp.tool
    async def frida_enumerate_pending_spawn(
        ctx: Context,
        device_id: str | None = None,
    ) -> list[dict]:
        """List pending spawned processes that are waiting to be resumed.

        Args:
            device_id: Target device. Uses default if omitted.
        """
        dm: DeviceManager = ctx.lifespan_context["device_manager"]
        device = await dm.get_device(device_id)
        pending = await device.enumerate_pending_spawn()
        return [{"pid": s.pid, "identifier": s.identifier} for s in pending]

    @mcp.tool
    async def frida_enumerate_pending_children(
        ctx: Context,
        device_id: str | None = None,
    ) -> list[dict]:
        """List pending child processes that are waiting to be resumed.

        Args:
            device_id: Target device. Uses default if omitted.
        """
        dm: DeviceManager = ctx.lifespan_context["device_manager"]
        device = await dm.get_device(device_id)
        children = await device.enumerate_pending_children()
        return [
            {"pid": c.pid, "parent_pid": c.parent_pid, "origin": c.origin,
             "identifier": c.identifier, "path": c.path, "argv": c.argv, "envp": c.envp}
            for c in children
        ]

    # --- Phase 4: native library injection ---

    @mcp.tool
    async def frida_inject_library_file(
        ctx: Context,
        pid: int,
        path: str,
        entrypoint: str,
        data: str,
        device_id: str | None = None,
    ) -> dict:
        """Inject a native library file (.so/.dylib) into a process.

        Args:
            pid: Target process PID.
            path: Absolute path to the library on the device.
            entrypoint: Name of the entry function in the library.
            data: String argument passed to the entrypoint.
            device_id: Target device. Uses default if omitted.
        """
        dm: DeviceManager = ctx.lifespan_context["device_manager"]
        device = await dm.get_device(device_id)
        inject_id = await device.inject_library_file(pid, path, entrypoint, data)
        return {"inject_id": inject_id, "pid": pid, "path": path}

    @mcp.tool
    async def frida_inject_library_blob(
        ctx: Context,
        pid: int,
        blob_base64: str,
        entrypoint: str,
        data: str,
        device_id: str | None = None,
    ) -> dict:
        """Inject a native library from memory (base64-encoded binary) into a process.

        Args:
            pid: Target process PID.
            blob_base64: Base64-encoded library binary.
            entrypoint: Name of the entry function in the library.
            data: String argument passed to the entrypoint.
            device_id: Target device. Uses default if omitted.
        """
        dm: DeviceManager = ctx.lifespan_context["device_manager"]
        device = await dm.get_device(device_id)
        blob = base64.b64decode(blob_base64)
        inject_id = await device.inject_library_blob(pid, blob, entrypoint, data)
        return {"inject_id": inject_id, "pid": pid}

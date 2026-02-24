"""Process enumeration and management tools (frida-ps)."""

from fastmcp import FastMCP
from fastmcp.server.context import Context

from ya_frida_mcp.core.device import DeviceManager
from ya_frida_mcp.core.output import ok
from ya_frida_mcp.core.session import SessionManager


def register_process_tools(mcp: FastMCP) -> None:
    """Register all process-related MCP tools."""

    @mcp.tool
    async def frida_ps(
        ctx: Context,
        device_id: str | None = None,
    ) -> list[dict]:
        """List running processes on a device (frida-ps equivalent).

        Returns PID and name for each process.
        """
        dm: DeviceManager = ctx.lifespan_context["device_manager"]
        device = await dm.get_device(device_id)
        processes = await device.enumerate_processes()
        return [
            {"pid": p.pid, "name": p.name}
            for p in processes
        ]

    @mcp.tool
    async def frida_spawn(
        ctx: Context,
        program: str,
        device_id: str | None = None,
        auto_resume: bool = True,
    ) -> dict:
        """Spawn a new process and optionally attach to it.

        Args:
            program: Path or bundle identifier to spawn.
            device_id: Target device. Uses default if omitted.
            auto_resume: Whether to resume the process after attaching.
        """
        dm: DeviceManager = ctx.lifespan_context["device_manager"]
        sm: SessionManager = ctx.lifespan_context["session_manager"]
        device = await dm.get_device(device_id)
        pid, _session = await sm.spawn_and_attach(device, program, auto_resume=auto_resume)
        return {"pid": pid, "program": program, "resumed": auto_resume}

    @mcp.tool
    async def frida_attach(
        ctx: Context,
        target: int | str,
        device_id: str | None = None,
    ) -> dict:
        """Attach to a running process by PID or name.

        Args:
            target: Process PID (int) or name (str).
            device_id: Target device. Uses default if omitted.
        """
        dm: DeviceManager = ctx.lifespan_context["device_manager"]
        sm: SessionManager = ctx.lifespan_context["session_manager"]
        device = await dm.get_device(device_id)
        session = await sm.attach(device, target)
        return {"pid": session.pid, "target": str(target)}

    @mcp.tool
    async def frida_detach(ctx: Context, pid: int) -> dict:
        """Detach from a process session."""
        sm: SessionManager = ctx.lifespan_context["session_manager"]
        await sm.detach(pid)
        return ok(f"Detached from PID {pid}", pid=pid)

    @mcp.tool
    async def frida_kill(
        ctx: Context,
        pid: int,
        device_id: str | None = None,
    ) -> dict:
        """Kill a process by PID."""
        dm: DeviceManager = ctx.lifespan_context["device_manager"]
        device = await dm.get_device(device_id)
        await device.kill(pid)
        return ok(f"Killed PID {pid}", pid=pid)

    @mcp.tool
    async def frida_resume(
        ctx: Context,
        pid: int,
        device_id: str | None = None,
    ) -> dict:
        """Resume a suspended process."""
        dm: DeviceManager = ctx.lifespan_context["device_manager"]
        device = await dm.get_device(device_id)
        await device.resume(pid)
        return ok(f"Resumed PID {pid}", pid=pid)

    @mcp.tool
    async def frida_list_sessions(ctx: Context) -> list[int]:
        """List all active session PIDs."""
        sm: SessionManager = ctx.lifespan_context["session_manager"]
        return sm.list_sessions()

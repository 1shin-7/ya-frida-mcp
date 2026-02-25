"""Process enumeration and management tools (frida-ps)."""

from fastmcp import FastMCP
from fastmcp.server.context import Context

from ya_frida_mcp.core.device import DeviceManager
from ya_frida_mcp.core.options import SessionRealm, TargetSpec
from ya_frida_mcp.core.output import ok
from ya_frida_mcp.core.session import SessionManager


def register_process_tools(mcp: FastMCP) -> None:
    """Register all process-related MCP tools."""

    @mcp.tool
    async def frida_ps(
        ctx: Context,
        device_id: str | None = None,
        scope: str | None = None,
        pids: list[int] | None = None,
    ) -> list[dict]:
        """List running processes on a device (frida-ps equivalent).

        Returns PID and name for each process.

        Args:
            device_id: Target device. Uses default if omitted.
            scope: Enumeration scope — "minimal", "metadata", or "full".
                   When "full", includes parameters (path, user, ppid, started).
            pids: Optional list of PIDs to filter by.
        """
        dm: DeviceManager = ctx.lifespan_context["device_manager"]
        device = await dm.get_device(device_id)
        processes = await device.enumerate_processes(pids=pids, scope=scope)
        result = []
        for p in processes:
            entry: dict = {"pid": p.pid, "name": p.name}
            if scope == "full" and hasattr(p, "parameters"):
                params = dict(p.parameters)
                params.pop("icons", None)
                entry["parameters"] = params
            result.append(entry)
        return result

    @mcp.tool
    async def frida_spawn(
        ctx: Context,
        program: str,
        device_id: str | None = None,
        auto_resume: bool = True,
        argv: list[str] | None = None,
        env: dict[str, str] | None = None,
        cwd: str | None = None,
        stdio: str | None = None,
    ) -> dict:
        """Spawn a new process and optionally attach to it.

        Args:
            program: Path or bundle identifier to spawn.
            device_id: Target device. Uses default if omitted.
            auto_resume: Whether to resume the process after attaching.
            argv: Command-line arguments for the spawned process.
            env: Environment variables as key-value pairs.
            cwd: Working directory for the spawned process.
            stdio: Standard I/O mode — "inherit", "pipe", or "redirect".

        Note:
            If spawn times out on Android, call ``frida_fix_usap`` to disable
            the USAP pool and detect root-hiding modules that may interfere
            with Frida's spawn interception.
        """
        dm: DeviceManager = ctx.lifespan_context["device_manager"]
        sm: SessionManager = ctx.lifespan_context["session_manager"]
        device = await dm.get_device(device_id)
        pid, _session = await sm.spawn_and_attach(
            device, program, auto_resume=auto_resume,
            argv=argv, env=env, cwd=cwd, stdio=stdio,
        )
        return {"pid": pid, "program": program, "resumed": auto_resume}

    @mcp.tool
    async def frida_attach(
        ctx: Context,
        pid: int | None = None,
        name: str | None = None,
        identifier: str | None = None,
        frontmost: bool = False,
        device_id: str | None = None,
        realm: SessionRealm | None = None,
    ) -> dict:
        """Attach to a running process by PID or name.

        Args:
            pid: Process PID (int).
            name: Process name (str).
            identifier: Application bundle identifier (str).
            frontmost: Attach to the frontmost application.
            device_id: Target device. Uses default if omitted.
            realm: Session realm — "native" or "emulated".
        """
        dm: DeviceManager = ctx.lifespan_context["device_manager"]
        sm: SessionManager = ctx.lifespan_context["session_manager"]
        device = await dm.get_device(device_id)
        target = TargetSpec(pid=pid, name=name, identifier=identifier, frontmost=frontmost)
        resolved_pid, _session = await sm.attach(device, target, realm=realm)
        return {"pid": resolved_pid, "target": target.label}

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

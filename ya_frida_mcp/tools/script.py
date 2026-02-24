"""Script injection and RPC tools."""

from __future__ import annotations

from typing import Any

from fastmcp import FastMCP
from fastmcp.server.context import Context

from ya_frida_mcp.core.output import ok
from ya_frida_mcp.core.session import SessionManager


def register_script_tools(mcp: FastMCP) -> None:
    """Register all script-related MCP tools."""

    @mcp.tool
    async def frida_inject(
        ctx: Context,
        pid: int,
        source: str,
    ) -> dict:
        """Inject a JavaScript snippet into a process.

        The process must already have an active session (use frida_attach first).

        Args:
            pid: Target process PID.
            source: JavaScript source code to inject.

        Returns:
            script_id for subsequent RPC calls or unloading.
        """
        sm: SessionManager = ctx.lifespan_context["session_manager"]
        script_id = await sm.inject_script(pid, source)
        return {"script_id": script_id, "pid": pid}

    @mcp.tool
    async def frida_rpc_call(
        ctx: Context,
        script_id: str,
        method: str,
        args: list[Any] | None = None,
    ) -> Any:
        """Call an RPC export on an injected script.

        The script must expose methods via `rpc.exports`.

        Args:
            script_id: ID returned by frida_inject.
            method: Export method name (snake_case in Python, camelCase in JS).
            args: Positional arguments to pass.
        """
        sm: SessionManager = ctx.lifespan_context["session_manager"]
        call_args = args or []
        return await sm.call_rpc(script_id, method, *call_args)

    @mcp.tool
    async def frida_unload_script(ctx: Context, script_id: str) -> dict:
        """Unload a previously injected script."""
        sm: SessionManager = ctx.lifespan_context["session_manager"]
        await sm.unload_script(script_id)
        return ok(f"Unloaded {script_id}", script_id=script_id)

    @mcp.tool
    async def frida_get_messages(ctx: Context, script_id: str) -> list[dict]:
        """Retrieve and drain pending messages from an injected script.

        Messages are produced by `send()` calls in the injected JS.
        """
        sm: SessionManager = ctx.lifespan_context["session_manager"]
        return await sm.get_messages(script_id)

    @mcp.tool
    async def frida_list_scripts(ctx: Context) -> list[str]:
        """List all active script IDs."""
        sm: SessionManager = ctx.lifespan_context["session_manager"]
        return sm.list_scripts()

    @mcp.tool
    async def frida_enumerate_modules(
        ctx: Context,
        pid: int,
    ) -> list[dict]:
        """Enumerate loaded modules in a process.

        Injects a helper script to call Process.enumerateModules().
        Requires an active session for the given PID.
        """
        sm: SessionManager = ctx.lifespan_context["session_manager"]
        source = """
        rpc.exports.enumerateModules = () => {
            return Process.enumerateModules();
        };
        """
        script_id = await sm.inject_script(pid, source)
        try:
            modules = await sm.call_rpc(script_id, "enumerate_modules")
            return [{"name": m["name"], "base": m["base"], "size": m["size"], "path": m["path"]} for m in modules]
        finally:
            await sm.unload_script(script_id)

    @mcp.tool
    async def frida_enumerate_exports(
        ctx: Context,
        pid: int,
        module_name: str,
    ) -> list[dict]:
        """Enumerate exports of a specific module.

        Args:
            pid: Target process PID (must have active session).
            module_name: Name of the module to inspect.
        """
        sm: SessionManager = ctx.lifespan_context["session_manager"]
        source = f"""
        rpc.exports.enumerateExports = () => {{
            return Module.enumerateExports("{module_name}");
        }};
        """
        script_id = await sm.inject_script(pid, source)
        try:
            exports = await sm.call_rpc(script_id, "enumerate_exports")
            return [{"type": e["type"], "name": e["name"], "address": e["address"]} for e in exports]
        finally:
            await sm.unload_script(script_id)

"""Script injection and RPC tools."""

import base64
from typing import Any

from fastmcp import FastMCP
from fastmcp.server.context import Context

from ya_frida_mcp.core.options import ScriptRuntime
from ya_frida_mcp.core.output import ok
from ya_frida_mcp.core.session import SessionManager


def register_script_tools(mcp: FastMCP) -> None:
    """Register all script-related MCP tools."""

    @mcp.tool
    async def frida_inject(
        ctx: Context,
        pid: int,
        source: str,
        runtime: ScriptRuntime | None = None,
    ) -> dict:
        """Inject a JavaScript snippet into a process.

        The process must already have an active session (use frida_attach first).

        IMPORTANT: The default runtime is QJS (QuickJS), which is lightweight but does
        NOT include the Java/ObjC bridges. If your script uses Java.perform(),
        Java.use(), ObjC.classes, or any Java/Objective-C APIs, you MUST set
        runtime="v8". Always use runtime="v8" for Android Java hooking.

        Args:
            pid: Target process PID.
            source: JavaScript source code to inject.
            runtime: Script runtime — "qjs" (default, no Java/ObjC bridge) or
                     "v8" (full runtime with Java/ObjC bridge support).

        Returns:
            script_id for subsequent RPC calls or unloading.
        """
        sm: SessionManager = ctx.lifespan_context["session_manager"]
        script_id = await sm.inject_script(pid, source, runtime=runtime)
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
        name_filter: str | None = None,
    ) -> list[dict]:
        """Enumerate loaded modules in a process.

        Injects a helper script to call Process.enumerateModules().
        Requires an active session for the given PID.

        Args:
            pid: Target process PID (must have active session).
            name_filter: Optional substring filter on module name (case-insensitive).
                         Use this to avoid returning hundreds of modules at once.
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
            result = [
                {"name": m["name"], "base": m["base"], "size": m["size"], "path": m["path"]}
                for m in modules
            ]
            if name_filter:
                flt = name_filter.lower()
                result = list(filter(lambda m: flt in m["name"].lower(), result))
            return result
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

    # --- Phase 1: script exports & messaging ---

    @mcp.tool
    async def frida_list_exports(
        ctx: Context,
        script_id: str,
    ) -> list[str]:
        """List RPC exports available on an injected script.

        Args:
            script_id: ID returned by frida_inject.
        """
        sm: SessionManager = ctx.lifespan_context["session_manager"]
        return await sm.list_script_exports(script_id)

    @mcp.tool
    async def frida_post_message(
        ctx: Context,
        script_id: str,
        message: Any,
        data: str | None = None,
    ) -> dict:
        """Post a message to an injected script.

        Args:
            script_id: ID returned by frida_inject.
            message: JSON-serializable message to send.
            data: Optional base64-encoded binary data.
        """
        sm: SessionManager = ctx.lifespan_context["session_manager"]
        raw_data = base64.b64decode(data) if data else None
        await sm.post_message(script_id, message, raw_data)
        return ok("Message posted", script_id=script_id)

    # --- Phase 3: child gating ---

    @mcp.tool
    async def frida_enable_child_gating(
        ctx: Context,
        pid: int,
    ) -> dict:
        """Enable child gating on a session.

        When enabled, child processes created by the target are suspended
        until explicitly resumed.

        Args:
            pid: Target process PID (must have active session).
        """
        sm: SessionManager = ctx.lifespan_context["session_manager"]
        await sm.enable_child_gating(pid)
        return ok("Child gating enabled", pid=pid)

    @mcp.tool
    async def frida_disable_child_gating(
        ctx: Context,
        pid: int,
    ) -> dict:
        """Disable child gating on a session.

        Args:
            pid: Target process PID (must have active session).
        """
        sm: SessionManager = ctx.lifespan_context["session_manager"]
        await sm.disable_child_gating(pid)
        return ok("Child gating disabled", pid=pid)

    # --- Phase 3: compile / snapshot / eternalize ---

    @mcp.tool
    async def frida_compile_script(
        ctx: Context,
        pid: int,
        source: str,
        runtime: ScriptRuntime | None = None,
    ) -> dict:
        """Compile a script to bytecode without loading it.

        Args:
            pid: Target process PID (must have active session).
            source: JavaScript source code to compile.
            runtime: Script runtime — "qjs" (default, no Java/ObjC) or
                     "v8" (full runtime with Java/ObjC bridge).

        Returns:
            Base64-encoded bytecode.
        """
        sm: SessionManager = ctx.lifespan_context["session_manager"]
        bytecode = await sm.compile_script(pid, source, runtime=runtime)
        return {"bytecode_base64": base64.b64encode(bytecode).decode()}

    @mcp.tool
    async def frida_snapshot_script(
        ctx: Context,
        pid: int,
        embed_script: str,
        warmup_script: str | None = None,
        runtime: ScriptRuntime | None = None,
    ) -> dict:
        """Create a snapshot of a script for fast future loading.

        Args:
            pid: Target process PID (must have active session).
            embed_script: JavaScript source to embed in the snapshot.
            warmup_script: Optional script to run during snapshot creation.
            runtime: Script runtime — "qjs" (default, no Java/ObjC) or
                     "v8" (full runtime with Java/ObjC bridge).

        Returns:
            Base64-encoded snapshot data.
        """
        sm: SessionManager = ctx.lifespan_context["session_manager"]
        snapshot = await sm.snapshot_script(
            pid, embed_script, warmup_script=warmup_script, runtime=runtime,
        )
        return {"snapshot_base64": base64.b64encode(snapshot).decode()}

    @mcp.tool
    async def frida_eternalize_script(
        ctx: Context,
        script_id: str,
    ) -> dict:
        """Eternalize a script so it persists after detaching from the session.

        Args:
            script_id: ID returned by frida_inject.
        """
        sm: SessionManager = ctx.lifespan_context["session_manager"]
        await sm.eternalize_script(script_id)
        return ok("Script eternalized", script_id=script_id)

"""Memory read/write/scan tools."""

from typing import Literal

from fastmcp import FastMCP
from fastmcp.server.context import Context

from ya_frida_mcp.core.output import ok
from ya_frida_mcp.core.session import SessionManager


def register_memory_tools(mcp: FastMCP) -> None:
    """Register all memory-related MCP tools."""

    @mcp.tool
    async def frida_memory_read(
        ctx: Context,
        pid: int,
        address: str,
        size: int,
    ) -> dict:
        """Read bytes from process memory.

        Args:
            pid: Target process PID (must have active session).
            address: Hex address string (e.g. "0x7fff12340000").
            size: Number of bytes to read.
        """
        sm: SessionManager = ctx.lifespan_context["session_manager"]
        source = f"""
        rpc.exports.readMemory = () => {{
            const buf = ptr("{address}").readByteArray({size});
            return buf ? Array.from(new Uint8Array(buf)) : [];
        }};
        """
        script_id = await sm.inject_script(pid, source)
        try:
            data = await sm.call_rpc(script_id, "read_memory")
            hex_str = bytes(data).hex()
            return {"address": address, "size": size, "hex": hex_str}
        finally:
            await sm.unload_script(script_id)

    @mcp.tool
    async def frida_memory_write(
        ctx: Context,
        pid: int,
        address: str,
        hex_data: str,
    ) -> dict:
        """Write bytes to process memory.

        Args:
            pid: Target process PID (must have active session).
            address: Hex address string (e.g. "0x7fff12340000").
            hex_data: Hex-encoded bytes to write (e.g. "deadbeef").
        """
        sm: SessionManager = ctx.lifespan_context["session_manager"]
        byte_array = list(bytes.fromhex(hex_data))
        source = f"""
        rpc.exports.writeMemory = () => {{
            const bytes = {byte_array};
            const buf = new Uint8Array(bytes).buffer;
            ptr("{address}").writeByteArray(buf);
            return bytes.length;
        }};
        """
        script_id = await sm.inject_script(pid, source)
        try:
            written = await sm.call_rpc(script_id, "write_memory")
            return ok(f"Wrote {written} bytes", address=address, bytes_written=written)
        finally:
            await sm.unload_script(script_id)

    @mcp.tool
    async def frida_memory_scan(
        ctx: Context,
        pid: int,
        address: str,
        size: int,
        pattern: str,
    ) -> list[dict]:
        """Scan process memory for a byte pattern.

        Args:
            pid: Target process PID (must have active session).
            address: Start address (hex string).
            size: Number of bytes to scan.
            pattern: Frida-style pattern (e.g. "48 8b ?? 00").
        """
        sm: SessionManager = ctx.lifespan_context["session_manager"]
        source = f"""
        rpc.exports.scanMemory = () => {{
            const matches = [];
            Memory.scan(ptr("{address}"), {size}, "{pattern}", {{
                onMatch(addr, size) {{
                    matches.push({{ address: addr.toString(), size }});
                }},
                onComplete() {{}}
            }});
            return matches;
        }};
        """
        script_id = await sm.inject_script(pid, source)
        try:
            return await sm.call_rpc(script_id, "scan_memory")
        finally:
            await sm.unload_script(script_id)

    @mcp.tool
    async def frida_memory_protect(
        ctx: Context,
        pid: int,
        address: str,
        size: int,
        protection: Literal["---", "r--", "rw-", "rwx", "r-x", "-w-", "-wx", "--x"] = "rwx",
    ) -> dict:
        """Change memory protection flags."""
        sm: SessionManager = ctx.lifespan_context["session_manager"]
        source = f"""
        rpc.exports.protect = () => {{
            Memory.protect(ptr("{address}"), {size}, "{protection}");
            return true;
        }};
        """
        script_id = await sm.inject_script(pid, source)
        try:
            await sm.call_rpc(script_id, "protect")
            return ok(f"Protection set to '{protection}'", address=address, size=size, protection=protection)
        finally:
            await sm.unload_script(script_id)

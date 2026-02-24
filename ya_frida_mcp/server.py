"""FastMCP server factory with Frida lifespan management."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastmcp import FastMCP

from ya_frida_mcp.config import AppConfig
from ya_frida_mcp.core.adb import ADBClient
from ya_frida_mcp.core.device import DeviceManager
from ya_frida_mcp.core.session import SessionManager


def _make_lifespan(config: AppConfig):
    """Create a lifespan context manager bound to the given config."""

    @asynccontextmanager
    async def lifespan(server: FastMCP) -> AsyncIterator[dict]:
        dm = DeviceManager(config)
        sm = SessionManager()
        await dm.initialize()
        await sm.initialize()
        try:
            ctx: dict = {
                "device_manager": dm,
                "session_manager": sm,
                "config": config,
            }
            if ADBClient.available():
                ctx["adb_client"] = ADBClient()
            yield ctx
        finally:
            await sm.cleanup()
            await dm.cleanup()

    return lifespan


def create_server(config: AppConfig | None = None) -> FastMCP:
    """Build and return a fully configured FastMCP server instance."""
    if config is None:
        config = AppConfig()

    mcp = FastMCP(
        config.server.name,
        lifespan=_make_lifespan(config),
    )

    # Register all tool groups
    from ya_frida_mcp.tools.app import register_app_tools
    from ya_frida_mcp.tools.device import register_device_tools
    from ya_frida_mcp.tools.memory import register_memory_tools
    from ya_frida_mcp.tools.process import register_process_tools
    from ya_frida_mcp.tools.script import register_script_tools

    register_device_tools(mcp)
    register_process_tools(mcp)
    register_app_tools(mcp)
    register_script_tools(mcp)
    register_memory_tools(mcp)

    # Optional: ADB tools (only when adb is on PATH)
    if ADBClient.available():
        from ya_frida_mcp.tools.adb import register_adb_tools
        from ya_frida_mcp.tools.frida_server import register_frida_server_tools

        register_adb_tools(mcp)
        register_frida_server_tools(mcp)

    # Register resources and prompts
    from ya_frida_mcp.prompts import register_prompts
    from ya_frida_mcp.resources import register_resources

    register_resources(mcp)
    register_prompts(mcp)

    return mcp

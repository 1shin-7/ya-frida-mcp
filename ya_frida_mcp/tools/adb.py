"""ADB CLI MCP tools — optional, registered only when ``adb`` is on PATH."""

from __future__ import annotations

from fastmcp import FastMCP
from fastmcp.server.context import Context

from ya_frida_mcp.core.adb import ADBClient


def register_adb_tools(mcp: FastMCP) -> None:
    """Register all ADB-related MCP tools."""

    def _client(ctx: Context, device: str | None = None) -> ADBClient:
        base: ADBClient = ctx.lifespan_context["adb_client"]
        if device and device != base.device_id:
            return ADBClient(device_id=device)
        return base

    # ------------------------------------------------------------------
    # Device management
    # ------------------------------------------------------------------

    @mcp.tool
    async def adb_devices(ctx: Context) -> list[dict[str, str]]:
        """List all ADB-connected devices with their state and properties."""
        return await _client(ctx).devices()

    @mcp.tool
    async def adb_connect(ctx: Context, addr: str) -> str:
        """Connect to a device over TCP/IP (e.g. '192.168.1.100:5555')."""
        return await _client(ctx).connect(addr)

    @mcp.tool
    async def adb_disconnect(ctx: Context, addr: str) -> str:
        """Disconnect a TCP/IP device."""
        return await _client(ctx).disconnect(addr)

    # ------------------------------------------------------------------
    # Shell & file transfer
    # ------------------------------------------------------------------

    @mcp.tool
    async def adb_shell(ctx: Context, command: str, device: str | None = None, timeout: float = 30.0) -> str:
        """Run a shell command on the device and return its output."""
        return await _client(ctx, device).shell(command, timeout=timeout)

    @mcp.tool
    async def adb_push(ctx: Context, local: str, remote: str, device: str | None = None) -> str:
        """Push a local file or directory to the device."""
        return await _client(ctx, device).push(local, remote)

    @mcp.tool
    async def adb_pull(ctx: Context, remote: str, local: str, device: str | None = None) -> str:
        """Pull a file or directory from the device to local machine."""
        return await _client(ctx, device).pull(remote, local)

    # ------------------------------------------------------------------
    # App management
    # ------------------------------------------------------------------

    @mcp.tool
    async def adb_install(
        ctx: Context, apk_path: str, device: str | None = None, flags: list[str] | None = None
    ) -> str:
        """Install an APK on the device. Common flags: -r (replace), -d (downgrade), -g (grant perms)."""
        return await _client(ctx, device).install(apk_path, flags=flags)

    @mcp.tool
    async def adb_uninstall(ctx: Context, package: str, device: str | None = None, keep_data: bool = False) -> str:
        """Uninstall a package. Set keep_data=True to preserve app data."""
        return await _client(ctx, device).uninstall(package, keep_data=keep_data)

    # ------------------------------------------------------------------
    # Port forwarding
    # ------------------------------------------------------------------

    @mcp.tool
    async def adb_forward(ctx: Context, local: str, remote: str, device: str | None = None) -> str:
        """Set up port forwarding (e.g. local='tcp:27042' remote='tcp:27042')."""
        return await _client(ctx, device).forward(local, remote)

    @mcp.tool
    async def adb_forward_remove(ctx: Context, local: str, device: str | None = None) -> str:
        """Remove a port forwarding rule."""
        return await _client(ctx, device).forward_remove(local)

    @mcp.tool
    async def adb_reverse(ctx: Context, remote: str, local: str, device: str | None = None) -> str:
        """Set up reverse port forwarding (device→host)."""
        return await _client(ctx, device).reverse(remote, local)

    @mcp.tool
    async def adb_reverse_remove(ctx: Context, remote: str, device: str | None = None) -> str:
        """Remove a reverse port forwarding rule."""
        return await _client(ctx, device).reverse_remove(remote)

    # ------------------------------------------------------------------
    # Logcat
    # ------------------------------------------------------------------

    @mcp.tool
    async def adb_logcat(
        ctx: Context,
        device: str | None = None,
        filters: str | None = None,
        lines: int = 200,
        timeout: float = 15.0,
    ) -> str:
        """Capture logcat output (dump mode). Use filters like 'ActivityManager:I *:S'."""
        return await _client(ctx, device).logcat(filters=filters, lines=lines, timeout=timeout)

    # ------------------------------------------------------------------
    # Misc
    # ------------------------------------------------------------------

    @mcp.tool
    async def adb_reboot(ctx: Context, device: str | None = None, mode: str | None = None) -> str:
        """Reboot the device. Optional mode: 'bootloader', 'recovery', 'sideload'."""
        return await _client(ctx, device).reboot(mode)

    @mcp.tool
    async def adb_getprop(ctx: Context, prop: str, device: str | None = None) -> str:
        """Read a system property (e.g. 'ro.build.version.sdk')."""
        return await _client(ctx, device).getprop(prop)

    @mcp.tool
    async def adb_root(ctx: Context, device: str | None = None) -> str:
        """Restart adbd with root permissions."""
        return await _client(ctx, device).root()

    @mcp.tool
    async def adb_unroot(ctx: Context, device: str | None = None) -> str:
        """Restart adbd without root permissions."""
        return await _client(ctx, device).unroot()

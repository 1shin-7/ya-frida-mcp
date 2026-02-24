"""ADB CLI MCP tools — optional, registered only when ``adb`` is on PATH."""

from __future__ import annotations

from typing import Any, Literal

from fastmcp import FastMCP
from fastmcp.server.context import Context

from ya_frida_mcp.core.adb import ADBClient, ADBError
from ya_frida_mcp.core.output import err, ok


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
    async def adb_connect(ctx: Context, addr: str) -> dict[str, Any]:
        """Connect to a device over TCP/IP (e.g. '192.168.1.100:5555')."""
        try:
            raw = await _client(ctx).connect(addr)
            return ok(raw, addr=addr)
        except ADBError as e:
            return err(e.stderr, addr=addr)

    @mcp.tool
    async def adb_disconnect(ctx: Context, addr: str) -> dict[str, Any]:
        """Disconnect a TCP/IP device."""
        try:
            raw = await _client(ctx).disconnect(addr)
            return ok(raw, addr=addr)
        except ADBError as e:
            return err(e.stderr, addr=addr)

    # ------------------------------------------------------------------
    # Shell & file transfer
    # ------------------------------------------------------------------

    @mcp.tool
    async def adb_shell(ctx: Context, command: str, device: str | None = None, timeout: float = 30.0) -> dict[str, Any]:
        """Run a shell command on the device and return its output."""
        try:
            raw = await _client(ctx, device).shell(command, timeout=timeout)
            return ok(raw)
        except ADBError as e:
            return err(e.stderr, command=command)

    @mcp.tool
    async def adb_push(ctx: Context, local: str, remote: str, device: str | None = None) -> dict[str, Any]:
        """Push a local file or directory to the device."""
        try:
            raw = await _client(ctx, device).push(local, remote)
            return ok(raw, local=local, remote=remote)
        except ADBError as e:
            return err(e.stderr, local=local, remote=remote)

    @mcp.tool
    async def adb_pull(ctx: Context, remote: str, local: str, device: str | None = None) -> dict[str, Any]:
        """Pull a file or directory from the device to local machine."""
        try:
            raw = await _client(ctx, device).pull(remote, local)
            return ok(raw, remote=remote, local=local)
        except ADBError as e:
            return err(e.stderr, remote=remote, local=local)

    # ------------------------------------------------------------------
    # App management
    # ------------------------------------------------------------------

    @mcp.tool
    async def adb_install(
        ctx: Context,
        apk_path: str,
        device: str | None = None,
        flags: list[Literal["-r", "-d", "-g", "-t", "-s"]] | None = None,
    ) -> dict[str, Any]:
        """Install an APK on the device."""
        try:
            raw = await _client(ctx, device).install(apk_path, flags=flags)
            return ok(raw, apk=apk_path)
        except ADBError as e:
            return err(e.stderr, apk=apk_path)

    @mcp.tool
    async def adb_uninstall(
        ctx: Context, package: str, device: str | None = None, keep_data: bool = False
    ) -> dict[str, Any]:
        """Uninstall a package. Set keep_data=True to preserve app data."""
        try:
            raw = await _client(ctx, device).uninstall(package, keep_data=keep_data)
            return ok(raw, package=package)
        except ADBError as e:
            return err(e.stderr, package=package)

    # ------------------------------------------------------------------
    # Port forwarding
    # ------------------------------------------------------------------

    @mcp.tool
    async def adb_forward(ctx: Context, local: str, remote: str, device: str | None = None) -> dict[str, Any]:
        """Set up port forwarding (e.g. local='tcp:27042' remote='tcp:27042')."""
        try:
            raw = await _client(ctx, device).forward(local, remote)
            return ok(raw or "Forward set", local=local, remote=remote)
        except ADBError as e:
            return err(e.stderr, local=local, remote=remote)

    @mcp.tool
    async def adb_forward_remove(ctx: Context, local: str, device: str | None = None) -> dict[str, Any]:
        """Remove a port forwarding rule."""
        try:
            raw = await _client(ctx, device).forward_remove(local)
            return ok(raw or "Forward removed", local=local)
        except ADBError as e:
            return err(e.stderr, local=local)

    @mcp.tool
    async def adb_reverse(ctx: Context, remote: str, local: str, device: str | None = None) -> dict[str, Any]:
        """Set up reverse port forwarding (device to host)."""
        try:
            raw = await _client(ctx, device).reverse(remote, local)
            return ok(raw or "Reverse set", remote=remote, local=local)
        except ADBError as e:
            return err(e.stderr, remote=remote, local=local)

    @mcp.tool
    async def adb_reverse_remove(ctx: Context, remote: str, device: str | None = None) -> dict[str, Any]:
        """Remove a reverse port forwarding rule."""
        try:
            raw = await _client(ctx, device).reverse_remove(remote)
            return ok(raw or "Reverse removed", remote=remote)
        except ADBError as e:
            return err(e.stderr, remote=remote)

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
    ) -> dict[str, Any]:
        """Capture logcat output (dump mode). Use filters like 'ActivityManager:I *:S'."""
        try:
            raw = await _client(ctx, device).logcat(filters=filters, lines=lines, timeout=timeout)
            return ok(raw)
        except ADBError as e:
            return err(e.stderr)

    # ------------------------------------------------------------------
    # Misc
    # ------------------------------------------------------------------

    @mcp.tool
    async def adb_reboot(
        ctx: Context, device: str | None = None, mode: Literal["bootloader", "recovery", "sideload"] | None = None
    ) -> dict[str, Any]:
        """Reboot the device."""
        try:
            raw = await _client(ctx, device).reboot(mode)
            return ok(raw or "Rebooting", mode=mode)
        except ADBError as e:
            return err(e.stderr)

    @mcp.tool
    async def adb_getprop(ctx: Context, prop: str, device: str | None = None) -> dict[str, Any]:
        """Read a system property (e.g. 'ro.build.version.sdk')."""
        try:
            value = await _client(ctx, device).getprop(prop)
            return {"prop": prop, "value": value}
        except ADBError as e:
            return err(e.stderr, prop=prop)

    @mcp.tool
    async def adb_root(ctx: Context, device: str | None = None) -> dict[str, Any]:
        """Restart adbd with root permissions."""
        try:
            raw = await _client(ctx, device).root()
            return ok(raw)
        except ADBError as e:
            return err(e.stderr)

    @mcp.tool
    async def adb_unroot(ctx: Context, device: str | None = None) -> dict[str, Any]:
        """Restart adbd without root permissions."""
        try:
            raw = await _client(ctx, device).unroot()
            return ok(raw)
        except ADBError as e:
            return err(e.stderr)

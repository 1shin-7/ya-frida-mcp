"""Frida-server management MCP tools — registered only when ``adb`` is on PATH."""

import contextlib
from typing import Any

import frida
from fastmcp import FastMCP
from fastmcp.server.context import Context

from ya_frida_mcp.core.adb import ADBClient, ADBError
from ya_frida_mcp.core.frida_server import (
    download_frida_server,
    get_device_abi,
    get_server_status,
    push_and_start,
    stop_server,
)
from ya_frida_mcp.core.output import err, ok

_USAP_PROPS = [
    "persist.sys.usap_pool_enabled",
    "persist.sys.dynamic_usap_enabled",
    "dalvik.vm.usap_pool_enabled",
]

# Known root-hiding processes that interfere with Frida spawn (proc name → module)
_ROOT_HIDER_PROCS: dict[str, str] = {
    "shamiko": "Shamiko",
    "zn-nsdaemon-zygote": "ZygiskSU",
    "zygiskd": "Zygisk (KernelSU)",
    "zygisk_companion": "Zygisk (Magisk)",
}


def register_frida_server_tools(mcp: FastMCP) -> None:
    """Register frida-server lifecycle MCP tools."""

    def _client(ctx: Context, device: str | None = None) -> ADBClient:
        base: ADBClient = ctx.lifespan_context["adb_client"]
        if device and device != base.device_id:
            return ADBClient(device_id=device)
        return base

    @mcp.tool
    async def frida_server_status(
        ctx: Context, device: str | None = None
    ) -> dict[str, Any]:
        """Check if frida-server is running on the device and whether its version matches the local Frida client."""
        try:
            return await get_server_status(_client(ctx, device))
        except ADBError as e:
            return err(e.stderr)

    @mcp.tool
    async def frida_server_install(
        ctx: Context,
        device: str | None = None,
        version: str | None = None,
    ) -> dict[str, Any]:
        """Download and push frida-server to the device.

        If *version* is omitted, uses the locally installed Frida client version
        to ensure client/server compatibility.
        """
        adb = _client(ctx, device)
        target_version = version or frida.__version__
        try:
            abi = await get_device_abi(adb)
            local_path = download_frida_server(target_version, abi)
            result = await push_and_start(adb, local_path)
            return ok(result, version=target_version, abi=abi)
        except ADBError as e:
            return err(e.stderr, version=target_version)
        except (ValueError, OSError) as e:
            return err(str(e), version=target_version)

    @mcp.tool
    async def frida_server_start(
        ctx: Context, device: str | None = None
    ) -> dict[str, Any]:
        """Start frida-server on the device (must already be pushed)."""
        adb = _client(ctx, device)
        try:
            await adb.shell(
                "setsid /data/local/tmp/frida-server -D </dev/null >/dev/null 2>&1 &",
            )
            pid_out = await adb.shell("pidof frida-server")
            pid = pid_out.strip()
            if pid:
                return ok(f"frida-server started (pid {pid})")
            return ok("frida-server start command issued (could not confirm pid)")
        except ADBError as e:
            return err(e.stderr)

    @mcp.tool
    async def frida_fix_usap(
        ctx: Context,
        device: str | None = None,
    ) -> dict[str, Any]:
        """Disable Android USAP pool and detect root-hiding modules that
        interfere with Frida spawn.

        Call this when frida_spawn times out or returns "unable to find
        executable". The tool:
        1. Disables USAP-related system properties (requires root/su)
        2. Kills lingering usap32/usap64 processes
        3. Detects active root-hiding modules (Shamiko, ZygiskSU, etc.)

        If spawn still fails after this fix, check the returned
        ``root_hiders`` list — those modules may need to be disabled
        manually in their respective manager apps.

        Args:
            device: Target device serial. Uses default if omitted.
        """
        adb = _client(ctx, device)

        # 1. Read current USAP property state
        before: dict[str, str] = {}
        for prop in _USAP_PROPS:
            try:
                val = (await adb.shell(f"getprop {prop}")).strip()
                before[prop] = val or "(empty)"
            except ADBError:
                before[prop] = "(unreadable)"

        # 2. Short-circuit: already disabled + no lingering processes
        already_off = all(before[p] == "false" for p in _USAP_PROPS)
        usap_alive = False
        with contextlib.suppress(ADBError):
            usap_alive = bool(
                (await adb.shell("pidof usap32 usap64")).strip()
            )

        # 3. Detect root-hiding modules
        root_hiders: list[str] = []
        try:
            ps_out = await adb.shell("ps -A -o NAME")
            proc_names = {line.strip() for line in ps_out.splitlines()}
            for proc, module in _ROOT_HIDER_PROCS.items():
                if proc in proc_names:
                    root_hiders.append(module)
        except ADBError:
            pass

        if already_off and not usap_alive:
            return ok(
                "USAP pool already disabled",
                state=before,
                root_hiders=root_hiders,
            )

        # 4. Disable via su -c setprop
        errors: list[str] = []
        for prop in _USAP_PROPS:
            try:
                await adb.shell(f"su -c 'setprop {prop} false'")
            except ADBError as e:
                errors.append(f"setprop {prop}: {e.stderr}")

        # 5. Kill lingering usap processes
        for proc in ("usap32", "usap64"):
            with contextlib.suppress(ADBError):
                await adb.shell(f"su -c 'pkill -9 {proc}'")

        # 6. Verify
        after: dict[str, str] = {}
        for prop in _USAP_PROPS:
            try:
                val = (await adb.shell(f"getprop {prop}")).strip()
                after[prop] = val or "(empty)"
            except ADBError:
                after[prop] = "(unreadable)"

        if errors:
            return err(
                f"Partial failure: {'; '.join(errors)}",
                hint="Device may lack root (su).",
                before=before,
                after=after,
                root_hiders=root_hiders,
            )
        return ok(
            "USAP pool disabled",
            before=before,
            after=after,
            root_hiders=root_hiders,
        )

    @mcp.tool
    async def frida_server_stop(
        ctx: Context, device: str | None = None
    ) -> dict[str, Any]:
        """Stop frida-server on the device."""
        try:
            detail = await stop_server(_client(ctx, device))
            return ok(detail)
        except ADBError as e:
            return err(e.stderr)

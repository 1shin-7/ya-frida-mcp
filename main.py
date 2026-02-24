"""CLI entry point using Click."""

from __future__ import annotations

from pathlib import Path

import click

from ya_frida_mcp.config import AppConfig


@click.group()
@click.option(
    "--config", "-c",
    type=click.Path(exists=False, path_type=Path),
    default=None,
    help="Path to config.toml file.",
)
@click.pass_context
def cli(ctx: click.Context, config: Path | None) -> None:
    """Ya-Frida-MCP: Full-featured MCP server for Frida instrumentation."""
    ctx.ensure_object(dict)
    ctx.obj["config"] = AppConfig.load(config)


# ---------------------------------------------------------------------------
# serve
# ---------------------------------------------------------------------------


@cli.command()
@click.option("--transport", "-t", type=click.Choice(["stdio", "sse"]), default=None, help="Transport mode.")
@click.option("--host", "-H", default=None, help="Host for SSE transport.")
@click.option("--port", "-p", type=int, default=None, help="Port for SSE transport.")
@click.pass_context
def serve(ctx: click.Context, transport: str | None, host: str | None, port: int | None) -> None:
    """Start the MCP server."""
    from ya_frida_mcp.server import create_server

    cfg: AppConfig = ctx.obj["config"]
    if transport:
        cfg.server.transport = transport
    if host:
        cfg.server.host = host
    if port:
        cfg.server.port = port

    server = create_server(cfg)
    if cfg.server.transport == "sse":
        server.run(transport="sse", host=cfg.server.host, port=cfg.server.port)
    else:
        server.run(transport="stdio")


# ---------------------------------------------------------------------------
# install / uninstall
# ---------------------------------------------------------------------------

_CLIENT_KEYS = ["claude-desktop", "claude-code", "cursor", "windsurf", "vscode"]


@cli.command()
@click.argument("client", type=click.Choice([*_CLIENT_KEYS, "all"]))
@click.option("--name", "-n", default="ya-frida-mcp", help="Server name in client config.")
@click.pass_context
def install(ctx: click.Context, client: str, name: str) -> None:
    """Register this MCP server into a client's config.

    CLIENT is one of: claude-desktop, claude-code, cursor, windsurf, vscode, all.
    """
    from ya_frida_mcp.installer import ALL_CLIENTS, build_server_command, get_installer

    command = build_server_command()
    targets = [cls() for cls in ALL_CLIENTS] if client == "all" else [get_installer(client)]

    for inst in targets:
        if inst.install(name, command):
            click.echo(f"  Installed into {inst.name} ({inst.config_path()})")
        else:
            click.echo(f"  {inst.name}: already up-to-date")


@cli.command()
@click.argument("client", type=click.Choice([*_CLIENT_KEYS, "all"]))
@click.option("--name", "-n", default="ya-frida-mcp", help="Server name in client config.")
@click.pass_context
def uninstall(ctx: click.Context, client: str, name: str) -> None:
    """Remove this MCP server from a client's config.

    CLIENT is one of: claude-desktop, claude-code, cursor, windsurf, vscode, all.
    """
    from ya_frida_mcp.installer import ALL_CLIENTS, get_installer

    targets = [cls() for cls in ALL_CLIENTS] if client == "all" else [get_installer(client)]

    for inst in targets:
        if inst.uninstall(name):
            click.echo(f"  Removed from {inst.name} ({inst.config_path()})")
        else:
            click.echo(f"  {inst.name}: not found, skipped")


# ---------------------------------------------------------------------------
# doctor
# ---------------------------------------------------------------------------


@cli.command()
@click.pass_context
def doctor(ctx: click.Context) -> None:
    """Diagnose Frida connectivity and environment."""
    import asyncio

    import frida

    from ya_frida_mcp.core.device import DeviceManager

    cfg: AppConfig = ctx.obj["config"]

    click.echo("Checking environment...")
    click.echo(f"  Python:  {'.'.join(map(str, __import__('sys').version_info[:3]))}")
    click.echo(f"  Frida:   {frida.__version__}")

    async def _check() -> None:
        dm = DeviceManager(cfg)
        await dm.initialize()
        try:
            devices = await dm.enumerate_devices()
            click.echo(f"  Devices: {len(devices)} found")
            for d in devices:
                status = "ok"
                try:
                    procs = await d.enumerate_processes()
                    status = f"ok ({len(procs)} processes)"
                except Exception as exc:
                    status = f"error: {exc}"
                click.echo(f"    [{d.dtype:<8}] {d.name:<20} {status}")
        finally:
            await dm.cleanup()

    asyncio.run(_check())


# ---------------------------------------------------------------------------
# devices / tools
# ---------------------------------------------------------------------------


@cli.command()
@click.pass_context
def devices(ctx: click.Context) -> None:
    """List all connected Frida devices."""
    import asyncio

    from ya_frida_mcp.core.device import DeviceManager

    cfg: AppConfig = ctx.obj["config"]

    async def _run() -> None:
        dm = DeviceManager(cfg)
        await dm.initialize()
        try:
            devs = await dm.enumerate_devices()
            click.echo(f"{'ID':<20}  {'Type':<10}  {'Name'}")
            click.echo("-" * 55)
            for d in devs:
                click.echo(f"{d.id:<20}  {d.dtype:<10}  {d.name}")
        finally:
            await dm.cleanup()

    asyncio.run(_run())


@cli.command()
def tools() -> None:
    """List all registered MCP tools."""
    import asyncio

    from ya_frida_mcp.server import create_server

    server = create_server()

    async def _run() -> None:
        tool_list = await server._local_provider._list_tools()
        for tool in sorted(tool_list, key=lambda t: t.name):
            desc = (tool.description or "").split("\n")[0]
            click.echo(f"  {tool.name:<30}  {desc}")

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# frida-ps / frida-ls shortcuts
# ---------------------------------------------------------------------------


@cli.command(name="ps")
@click.option("--device", "-d", default=None, help="Device ID (default: local).")
@click.pass_context
def frida_ps_cmd(ctx: click.Context, device: str | None) -> None:
    """List running processes (frida-ps shortcut)."""
    import asyncio

    from ya_frida_mcp.core.device import DeviceManager

    cfg = ctx.obj["config"]

    async def _run() -> None:
        dm = DeviceManager(cfg)
        await dm.initialize()
        try:
            dev = await dm.get_device(device)
            processes = await dev.enumerate_processes()
            click.echo(f"{'PID':>8}  {'Name'}")
            click.echo("-" * 40)
            for p in sorted(processes, key=lambda x: x.pid):
                click.echo(f"{p.pid:>8}  {p.name}")
        finally:
            await dm.cleanup()

    asyncio.run(_run())


@cli.command(name="ls")
@click.option("--device", "-d", default=None, help="Device ID (default: local).")
@click.option("--running", "-r", is_flag=True, help="Only show running apps.")
@click.pass_context
def frida_ls_cmd(ctx: click.Context, device: str | None, running: bool) -> None:
    """List installed applications (frida-ls shortcut)."""
    import asyncio

    from ya_frida_mcp.core.device import DeviceManager

    cfg = ctx.obj["config"]

    async def _run() -> None:
        dm = DeviceManager(cfg)
        await dm.initialize()
        try:
            dev = await dm.get_device(device)
            apps = await dev.enumerate_applications()
            if running:
                apps = [a for a in apps if a.pid != 0]
            click.echo(f"{'PID':>8}  {'Identifier':<40}  {'Name'}")
            click.echo("-" * 70)
            for a in sorted(apps, key=lambda x: x.identifier):
                click.echo(f"{a.pid:>8}  {a.identifier:<40}  {a.name}")
        finally:
            await dm.cleanup()

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# config / version
# ---------------------------------------------------------------------------


@cli.command()
@click.pass_context
def init_config(ctx: click.Context) -> None:
    """Generate a default config.toml in the current directory."""
    target = Path.cwd() / "config.toml"
    if target.exists():
        click.confirm(f"{target} already exists. Overwrite?", abort=True)
    cfg = AppConfig()
    cfg.save(target)
    click.echo(f"Config written to {target}")


@cli.command()
@click.pass_context
def show_config(ctx: click.Context) -> None:
    """Display the current resolved configuration."""
    import json

    cfg: AppConfig = ctx.obj["config"]
    data = {
        "server": {
            "name": cfg.server.name,
            "transport": cfg.server.transport,
            "host": cfg.server.host,
            "port": cfg.server.port,
        },
        "frida": {
            "default_device": cfg.frida.default_device,
            "script_timeout": cfg.frida.script_timeout,
            "spawn_timeout": cfg.frida.spawn_timeout,
            "remote_devices": [
                {"host": r.host, "port": r.port}
                for r in cfg.frida.remote_devices
            ],
        },
    }
    click.echo(json.dumps(data, indent=2))


@cli.command()
def version() -> None:
    """Show version information."""
    import frida

    from ya_frida_mcp import __version__

    click.echo(f"ya-frida-mcp  {__version__}")
    click.echo(f"frida         {frida.__version__}")


if __name__ == "__main__":
    cli()

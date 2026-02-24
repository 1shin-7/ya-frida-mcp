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


@cli.command()
@click.option("--transport", "-t", type=click.Choice(["stdio", "sse"]), default=None, help="Transport mode.")
@click.option("--host", "-h", default=None, help="Host for SSE transport.")
@click.option("--port", "-p", type=int, default=None, help="Port for SSE transport.")
@click.pass_context
def run(ctx: click.Context, transport: str | None, host: str | None, port: int | None) -> None:
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
            "remote_devices": [{"host": r.host, "port": r.port} for r in cfg.frida.remote_devices],
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


if __name__ == "__main__":
    cli()

<p align="center">
  <img src="https://socialify.git.ci/1shin-7/ya-frida-mcp/image?description=1&font=Inter&language=1&name=1&owner=1&pattern=Plus&theme=Auto" alt="ya-frida-mcp" width="640" />
</p>

<p align="center">
  <a href="https://github.com/1shin-7/ya-frida-mcp/actions"><img src="https://img.shields.io/github/actions/workflow/status/1shin-7/ya-frida-mcp/ci.yml?style=flat-square" alt="CI" /></a>
  <a href="https://pypi.org/project/ya-frida-mcp/"><img src="https://img.shields.io/pypi/v/ya-frida-mcp?style=flat-square&color=blue" alt="PyPI" /></a>
  <a href="https://pypi.org/project/ya-frida-mcp/"><img src="https://img.shields.io/pypi/pyversions/ya-frida-mcp?style=flat-square" alt="Python" /></a>
  <a href="https://github.com/1shin-7/ya-frida-mcp/blob/main/LICENSE"><img src="https://img.shields.io/github/license/1shin-7/ya-frida-mcp?style=flat-square" alt="License" /></a>
  <a href="https://github.com/1shin-7/ya-frida-mcp/stargazers"><img src="https://img.shields.io/github/stars/1shin-7/ya-frida-mcp?style=flat-square" alt="Stars" /></a>
</p>

<p align="center"><b>Yet Another Frida MCP Server</b> — Full-featured <a href="https://modelcontextprotocol.io">MCP</a> server for <a href="https://frida.re">Frida</a> dynamic instrumentation.</p>

<p align="center">English | <a href="README.zh-CN.md">简体中文</a></p>

---

> Existing Frida MCP servers on the market are either abandoned, poorly maintained, or limited to a handful of basic operations. **ya-frida-mcp** was built from scratch to be a comprehensive, production-ready bridge between AI agents and Frida — covering device management, process control, script injection, memory operations, and even ADB integration out of the box.
>
> The vast majority of this codebase was written with the help of [Claude](https://claude.ai). Huge thanks to Anthropic for making AI-assisted development a reality.

## Features

**44 MCP tools** across 7 categories, all returning structured JSON for minimal token consumption.

| Category | Tools | Highlights |
|----------|-------|------------|
| **Device** | `frida_ls_devices` `frida_get_device` `frida_add_remote` `frida_remove_remote` | Local, USB, and remote device management |
| **Process** | `frida_ps` `frida_spawn` `frida_attach` `frida_detach` `frida_kill` `frida_resume` | Full process lifecycle control |
| **App** | `frida_ls_apps` `frida_ls_apps_running` | Application enumeration |
| **Script** | `frida_inject` `frida_rpc_call` `frida_unload_script` `frida_get_messages` `frida_enumerate_modules` `frida_enumerate_exports` | JS injection, RPC calls, module inspection |
| **Memory** | `frida_memory_read` `frida_memory_write` `frida_memory_scan` `frida_memory_protect` | Read/write/scan/protect with hex I/O |
| **ADB** *(optional)* | `adb_shell` `adb_push` `adb_pull` `adb_install` `adb_logcat` `adb_forward` `adb_root` ... | 17 tools, auto-registered when `adb` is on PATH |
| **Frida Server** *(optional)* | `frida_server_status` `frida_server_install` `frida_server_start` `frida_server_stop` | Auto-download, push, and manage frida-server on Android via ADB |

**Also includes:**

- **MCP Resources** — live device list, session state, process/app enumeration as subscribable resources
- **MCP Prompts** — workflow templates for native hooking, Java/ObjC hooking, Stalker tracing, module dumping
- **TOML Configuration** — customize transport, default device, remote devices, timeouts
- **CLI Utilities** — `doctor`, `devices`, `ps`, `ls`, `tools`, `install`/`uninstall` for MCP clients
- **One-command client setup** — register into Claude Desktop, Claude Code, Cursor, Windsurf, or VS Code
- **Structured output** — all tools return compact JSON with `Literal` type hints for LLM-friendly schemas

## Quickstart

### Install

```bash
# PyPI (recommended)
pip install ya-frida-mcp

# Or via uv
uv tool install ya-frida-mcp
```

### Register into your MCP client

```bash
# Claude Desktop
ya-frida-mcp install claude-desktop

# Claude Code
ya-frida-mcp install claude-code

# Cursor / Windsurf / VS Code
ya-frida-mcp install cursor
ya-frida-mcp install windsurf
ya-frida-mcp install vscode

# All at once
ya-frida-mcp install all
```

### Start the server manually

```bash
# stdio (default, used by MCP clients)
ya-frida-mcp serve

# SSE transport
ya-frida-mcp serve -t sse -H 0.0.0.0 -p 8000
```

### Configuration (optional)

```bash
ya-frida-mcp init-config   # generates config.toml in current directory
ya-frida-mcp show-config    # display resolved config
ya-frida-mcp -c /path/to/config.toml serve
```

```toml
# config.toml
[server]
name = "ya-frida-mcp"
transport = "stdio"       # "stdio" or "sse"
host = "127.0.0.1"
port = 8000

[frida]
default_device = "local"  # "local", "usb", or device ID
script_timeout = 10
spawn_timeout = 15

[[frida.remote_devices]]
host = "192.168.1.100"
port = 27042
```

## CLI Reference

```bash
ya-frida-mcp doctor       # diagnose Frida connectivity
ya-frida-mcp devices      # list Frida devices
ya-frida-mcp ps            # list running processes (frida-ps)
ya-frida-mcp ls            # list installed apps (frida-ls)
ya-frida-mcp tools         # list all registered MCP tools
ya-frida-mcp version       # show version info
```

## Development

```bash
# Clone
git clone https://github.com/1shin-7/ya-frida-mcp.git
cd ya-frida-mcp

# Install dependencies
uv sync

# Run in dev mode
uv run ya-frida-mcp serve

# Lint
uv run ruff check ya_frida_mcp/

# List tools (verify registration)
uv run ya-frida-mcp tools
```

### Project Structure

```
ya_frida_mcp/
├── cli.py              # Click CLI entry point
├── config.py           # TOML configuration management
├── installer.py        # MCP client config installers
├── server.py           # FastMCP server factory + lifespan
├── resources.py        # MCP resources
├── prompts.py          # MCP workflow prompts
├── core/
│   ├── base.py         # ABC base classes + async helpers
│   ├── device.py       # Frida device wrapper + manager
│   ├── session.py      # Session + script lifecycle
│   ├── adb.py          # ADB CLI async wrapper
│   ├── frida_server.py # frida-server download & deploy logic
│   └── output.py       # Structured output helpers
└── tools/
    ├── device.py       # Device discovery tools
    ├── process.py      # Process management tools
    ├── app.py          # App enumeration tools
    ├── script.py       # Script injection + RPC tools
    ├── memory.py       # Memory read/write/scan tools
    ├── adb.py          # ADB CLI tools (optional)
    └── frida_server.py # frida-server management tools (optional)
```

## Credits

- [Frida](https://frida.re) — Dynamic instrumentation toolkit
- [FastMCP](https://github.com/jlowin/fastmcp) — Pythonic MCP server framework
- [Claude](https://claude.ai) — Core collaborator, authored the vast majority of this codebase
- [Click](https://click.palletsprojects.com) — CLI framework

## License

[MIT](LICENSE)


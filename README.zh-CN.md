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

<p align="center"><b>Yet Another Frida MCP Server</b> — 功能完备的 <a href="https://modelcontextprotocol.io">MCP</a> 服务器，用于 <a href="https://frida.re">Frida</a> 动态插桩。</p>

<p align="center"><a href="README.md">English</a> | 简体中文</p>

---

> 市面上现有的 Frida MCP 服务器要么已经停止维护，要么功能有限，仅支持少量基础操作。**ya-frida-mcp** 从零开始构建，旨在成为 AI 智能体与 Frida 之间全面、可用于生产环境的桥梁 —— 开箱即用地涵盖设备管理、进程控制、脚本注入、内存操作，甚至 ADB 集成。

## 功能特性

**59 个 MCP 工具**，横跨 7 大类别，所有工具均返回结构化 JSON 以最小化 Token 消耗。

| 类别 | 工具 | 亮点 |
|------|------|------|
| **设备** | `frida_ls_devices` `frida_get_device` `frida_add_remote` `frida_remove_remote` `frida_query_system_parameters` `frida_enable_spawn_gating` `frida_disable_spawn_gating` `frida_enumerate_pending_spawn` `frida_enumerate_pending_children` `frida_inject_library_file` `frida_inject_library_blob` | 设备管理、系统信息、Spawn 拦截、原生库注入 |
| **进程** | `frida_ps` `frida_spawn` `frida_attach` `frida_detach` `frida_kill` `frida_resume` `frida_list_sessions` | 完整进程生命周期；`frida_ps` 支持 scope/pids，`frida_spawn` 支持 argv/env/cwd/stdio |
| **应用** | `frida_ls_apps` `frida_ls_apps_running` `frida_get_frontmost_application` | 应用枚举，支持 scope/identifiers 过滤 |
| **脚本** | `frida_inject` `frida_rpc_call` `frida_unload_script` `frida_get_messages` `frida_list_scripts` `frida_enumerate_modules` `frida_enumerate_exports` `frida_list_exports` `frida_post_message` `frida_enable_child_gating` `frida_disable_child_gating` `frida_compile_script` `frida_snapshot_script` `frida_eternalize_script` | JS 注入（QJS/V8）、RPC 调用、子进程拦截、字节码编译、脚本快照 |
| **内存** | `frida_memory_read` `frida_memory_write` `frida_memory_scan` `frida_memory_protect` | 以十六进制 I/O 进行读/写/扫描/保护 |
| **ADB** *(可选)* | `adb_shell` `adb_push` `adb_pull` `adb_install` `adb_logcat` `adb_forward` `adb_root` ... | 17 个工具，当 `adb` 在 PATH 中时自动注册 |
| **Frida Server** *(可选)* | `frida_server_status` `frida_server_install` `frida_server_start` `frida_server_stop` | 通过 ADB 自动下载、推送并管理 Android 上的 frida-server |

**还包括：**

- **MCP 资源** — 实时设备列表、会话状态、进程/应用枚举等可订阅资源
- **MCP 提示词** — 用于 Native Hook、Java/ObjC Hook、Stalker 追踪、模块导出的工作流模板
- **TOML 配置** — 自定义传输方式、默认设备、远程设备、超时时间
- **CLI 工具** — `doctor`、`devices`、`ps`、`ls`、`tools`、`install`/`uninstall` 等命令
- **一键客户端配置** — 支持注册到 22+ MCP 客户端，包括 Claude Desktop、Cursor、VS Code、Windsurf、Roo Code、Cline、Kiro 等
- **结构化输出** — 所有工具返回紧凑的 JSON，带有 `Literal` 类型提示，对 LLM 友好

## 快速开始

### 安装

```bash
# PyPI（推荐）
pip install ya-frida-mcp

# 或通过 uv
uv tool install ya-frida-mcp
```

### 注册到 MCP 客户端

```bash
# 选择你的客户端
ya-frida-mcp install claude-desktop
ya-frida-mcp install cursor
ya-frida-mcp install vscode
ya-frida-mcp install windsurf
ya-frida-mcp install roo-code
ya-frida-mcp install cline

# 一次性注册所有支持的客户端
ya-frida-mcp install all
```

<details>
<summary>所有支持的客户端（22 个）</summary>

| Key | 客户端 |
|-----|--------|
| `amazon-q` | Amazon Q Developer CLI |
| `augment-code` | Augment Code |
| `claude-desktop` | Claude Desktop |
| `claude-code` | Claude Code |
| `cline` | Cline |
| `copilot-cli` | Copilot CLI |
| `crush` | Crush |
| `cursor` | Cursor |
| `gemini-cli` | Gemini CLI |
| `kilo-code` | Kilo Code |
| `kiro` | Kiro |
| `lm-studio` | LM Studio |
| `opencode` | Opencode |
| `qodo-gen` | Qodo Gen |
| `qwen-coder` | Qwen Coder |
| `roo-code` | Roo Code |
| `trae` | Trae |
| `vscode` | VS Code |
| `vscode-insiders` | VS Code Insiders |
| `warp` | Warp |
| `windsurf` | Windsurf |
| `zed` | Zed |

</details>

### 手动启动服务器

```bash
# stdio（默认，MCP 客户端使用）
ya-frida-mcp serve

# SSE 传输
ya-frida-mcp serve -t sse -H 0.0.0.0 -p 8000
```

### 配置（可选）

```bash
ya-frida-mcp init-config   # 在当前目录生成 config.toml
ya-frida-mcp show-config    # 显示已解析的配置
ya-frida-mcp -c /path/to/config.toml serve
```

```toml
# config.toml
[server]
name = "ya-frida-mcp"
transport = "stdio"       # "stdio" 或 "sse"
host = "127.0.0.1"
port = 8000

[frida]
default_device = "local"  # "local"、"usb" 或设备 ID
script_timeout = 10
spawn_timeout = 15

[[frida.remote_devices]]
host = "192.168.1.100"
port = 27042
```

## CLI 参考

```bash
ya-frida-mcp doctor       # 诊断 Frida 连接状态
ya-frida-mcp devices      # 列出 Frida 设备
ya-frida-mcp ps            # 列出运行中的进程（frida-ps）
ya-frida-mcp ls            # 列出已安装的应用（frida-ls）
ya-frida-mcp tools         # 列出所有已注册的 MCP 工具
ya-frida-mcp version       # 显示版本信息
```

## 开发

```bash
# 克隆仓库
git clone https://github.com/1shin-7/ya-frida-mcp.git
cd ya-frida-mcp

# 安装依赖
uv sync

# 以开发模式运行
uv run ya-frida-mcp serve

# 代码检查
uv run ruff check ya_frida_mcp/

# 列出工具（验证注册）
uv run ya-frida-mcp tools
```

### 项目结构

```
ya_frida_mcp/
├── cli.py              # Click CLI 入口
├── config.py           # TOML 配置管理
├── installer.py        # MCP 客户端配置安装器
├── server.py           # FastMCP 服务器工厂 + 生命周期
├── resources.py        # MCP 资源
├── prompts.py          # MCP 工作流提示词
├── core/
│   ├── base.py         # ABC 基类 + 异步辅助工具
│   ├── device.py       # Frida 设备封装 + 管理器
│   ├── session.py      # 会话 + 脚本生命周期
│   ├── adb.py          # ADB CLI 异步封装
│   ├── frida_server.py # frida-server 下载与部署逻辑
│   └── output.py       # 结构化输出辅助工具
└── tools/
    ├── device.py       # 设备发现工具
    ├── process.py      # 进程管理工具
    ├── app.py          # 应用枚举工具
    ├── script.py       # 脚本注入 + RPC 工具
    ├── memory.py       # 内存读/写/扫描工具
    ├── adb.py          # ADB CLI 工具（可选）
    └── frida_server.py # frida-server 管理工具（可选）
```

## 致谢

- [Frida](https://frida.re) — 动态插桩工具包
- [FastMCP](https://github.com/jlowin/fastmcp) — Pythonic MCP 服务器框架
- [Click](https://click.palletsprojects.com) — CLI 框架
- [Claude](https://claude.ai) — AI 辅助开发

## 许可证

[MIT](LICENSE)

# WIP: Ya Frida MCP

_Corrección de JsBridge pendiente [#3](https://github.com/1shin-7/ya-frida-mcp/issues/3)_

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

<p align="center"><b>Yet Another Frida MCP Server</b> — Servidor <a href="https://modelcontextprotocol.io">MCP</a> completo para la instrumentación dinámica de <a href="https://frida.re">Frida</a>.</p>

<p align="center">Español | <a href="README.zh-CN.md">简体中文</a> | English</p>

---

> Los servidores Frida MCP existentes en el mercado están abandonados, mal mantenidos o limitados a unas pocas operaciones básicas. **ya-frida-mcp** fue construido desde cero para ser un puente exhaustivo y listo para producción entre agentes de IA y Frida, cubriendo la gestión de dispositivos, control de procesos, inyección de scripts, operaciones de memoria e incluso integración con ADB de forma nativa.

## Características

**59 herramientas MCP** divididas en 7 categorías, todas devolviendo JSON estructurado para un consumo mínimo de tokens.

| Categoría | Herramientas | Aspectos Destacados |
|----------|-------|------------|
| **Dispositivo** | `frida_ls_devices` `frida_get_device` `frida_add_remote` `frida_remove_remote` `frida_query_system_parameters` `frida_enable_spawn_gating` `frida_disable_spawn_gating` `frida_enumerate_pending_spawn` `frida_enumerate_pending_children` `frida_inject_library_file` `frida_inject_library_blob` | Gestión de dispositivos, info del sistema, spawn gating, inyección de librerías nativas |
| **Proceso** | `frida_ps` `frida_spawn` `frida_attach` `frida_detach` `frida_kill` `frida_resume` `frida_list_sessions` | Ciclo de vida completo del proceso; `frida_ps` soporta scope/pids, `frida_spawn` soporta argv/env/cwd/stdio |
| **App** | `frida_ls_apps` `frida_ls_apps_running` `frida_get_frontmost_application` | Enumeración de apps con filtrado por scope/identificadores |
| **Script** | `frida_inject` `frida_rpc_call` `frida_unload_script` `frida_get_messages` `frida_list_scripts` `frida_enumerate_modules` `frida_enumerate_exports` `frida_list_exports` `frida_post_message` `frida_enable_child_gating` `frida_disable_child_gating` `frida_compile_script` `frida_snapshot_script` `frida_eternalize_script` | Inyección de JS (QJS/V8), RPC, child gating, compilación de bytecode, snapshots de scripts |
| **Memoria** | `frida_memory_read` `frida_memory_write` `frida_memory_scan` `frida_memory_protect` | Lectura/escritura/escaneo/protección con E/S hexadecimal |
| **ADB** *(opcional)* | `adb_shell` `adb_push` `adb_pull` `adb_install` `adb_logcat` `adb_forward` `adb_root` ... | 17 herramientas, registradas automáticamente si `adb` está en el PATH |
| **Frida Server** *(opcional)* | `frida_server_status` `frida_server_install` `frida_server_start` `frida_server_stop` | Descarga automática, push y gestión de frida-server en Android vía ADB |

**También incluye:**

- **Recursos MCP** — Lista de dispositivos en vivo, estado de la sesión, enumeración de procesos/apps como recursos suscribibles.
- **Prompts MCP** — Plantillas de flujo de trabajo para hooking nativo, hooking de Java/ObjC, rastreo con Stalker, volcado de módulos.
- **Configuración TOML** — Personaliza el transporte, dispositivo predeterminado, dispositivos remotos y tiempos de espera (timeouts).
- **Utilidades CLI** — `doctor`, `devices`, `ps`, `ls`, `tools`, `install`/`uninstall` para clientes MCP.
- **Configuración de cliente en un solo comando** — Registro en más de 22 clientes MCP, incluyendo Claude Desktop, Cursor, VS Code, Windsurf, Roo Code, Cline, Kiro y más.
- **Salida estructurada** — Todas las herramientas devuelven JSON compacto con sugerencias de tipo `Literal` para esquemas optimizados para LLM.

## Inicio Rápido

### Instalación

```bash
# PyPI (recomendado)
pip install ya-frida-mcp

# O vía uv
uv tool install ya-frida-mcp
```

### Registrar en tu cliente MCP

```bash
# Elige tu cliente
ya-frida-mcp install claude-desktop
ya-frida-mcp install cursor
ya-frida-mcp install vscode
ya-frida-mcp install windsurf
ya-frida-mcp install roo-code
ya-frida-mcp install cline

# Todos los clientes soportados a la vez
ya-frida-mcp install all
```

<details>
<summary>Todos los clientes soportados (22)</summary>

| Clave | Cliente |
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

### Iniciar el servidor manualmente

```bash
# stdio (predeterminado, usado por clientes MCP)
ya-frida-mcp serve

# transporte SSE
ya-frida-mcp serve -t sse -H 0.0.0.0 -p 8000
```

### Configuración (opcional)

```bash
ya-frida-mcp init-config   # genera config.toml en el directorio actual
ya-frida-mcp show-config    # muestra la configuración resuelta
ya-frida-mcp -c /path/to/config.toml serve
```

```toml
# config.toml
[server]
name = "ya-frida-mcp"
transport = "stdio"       # "stdio" o "sse"
host = "127.0.0.1"
port = 8000

[frida]
default_device = "local"  # "local", "usb", o ID del dispositivo
script_timeout = 10
spawn_timeout = 15

[[frida.remote_devices]]
host = "192.168.1.100"
port = 27042
```

## Referencia de la CLI

```bash
ya-frida-mcp doctor       # diagnostica la conectividad de Frida
ya-frida-mcp devices      # lista los dispositivos de Frida
ya-frida-mcp ps            # lista los procesos en ejecución (frida-ps)
ya-frida-mcp ls            # lista las apps instaladas (frida-ls)
ya-frida-mcp tools         # lista todas las herramientas MCP registradas
ya-frida-mcp version       # muestra la información de versión
```

## Desarrollo

```bash
# Clonar
git clone https://github.com/1shin-7/ya-frida-mcp.git
cd ya-frida-mcp

# Instalar dependencias
uv sync

# Ejecutar en modo desarrollo
uv run ya-frida-mcp serve

# Linting
uv run ruff check ya_frida_mcp/

# Listar herramientas (verificar registro)
uv run ya-frida-mcp tools
```

### Estructura del Proyecto

```
ya_frida_mcp/
├── cli.py              # Punto de entrada de la CLI Click
├── config.py           # Gestión de configuración TOML
├── installer.py        # Instaladores de configuración para clientes MCP
├── server.py           # Factory de servidor FastMCP + lifespan
├── resources.py        # Recursos MCP
├── prompts.py          # Prompts de flujo de trabajo MCP
├── core/
│   ├── base.py         # Clases base ABC + ayudantes async
│   ├── device.py       # Wrapper + gestor de dispositivos Frida
│   ├── session.py      # Ciclo de vida de sesión + script
│   ├── adb.py          # Wrapper async de la CLI de ADB
│   ├── frida_server.py # Lógica de descarga y despliegue de frida-server
│   └── output.py       # Ayudantes de salida estructurada
└── tools/
    ├── device.py       # Herramientas de descubrimiento de dispositivos
    ├── process.py      # Herramientas de gestión de procesos
    ├── app.py          # Herramientas de enumeración de apps
    ├── script.py       # Herramientas de inyección de scripts + RPC
    ├── memory.py       # Herramientas de lectura/escritura/escaneo de memoria
    ├── adb.py          # Herramientas de la CLI de ADB (opcional)
    └── frida_server.py # Herramientas de gestión de frida-server (opcional)
```

## Créditos

- [Frida](https://frida.re) — Toolkit de instrumentación dinámica
- [FastMCP](https://github.com/jlowin/fastmcp) — Framework de servidor MCP para Python
- [Click](https://click.palletsprojects.com) — Framework de CLI
- [Claude](https://claude.ai) — Desarrollo asistido por IA

## Licencia

[MIT](LICENSE)

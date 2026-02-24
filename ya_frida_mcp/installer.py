"""MCP client installer — register/unregister server config in various MCP clients."""

from __future__ import annotations

import json
import os
import platform
import shutil
import sys
from abc import ABC, abstractmethod
from pathlib import Path
from typing import ClassVar


class MCPClientInstaller(ABC):
    """Abstract base for MCP client config installers."""

    name: ClassVar[str]
    key: ClassVar[str]

    # Override in subclasses that use a nested JSON structure.
    # Format: (top_level_key, nested_key)
    #   ("mcp", "servers")  -> config["mcp"]["servers"][server_name]
    #   (None, "servers")   -> config["servers"][server_name]
    #   None                -> config["mcpServers"][server_name]  (default)
    _json_structure: ClassVar[tuple[str | None, str] | None] = None

    @abstractmethod
    def config_path(self) -> Path:
        """Return the path to this client's MCP config file."""

    def exists(self) -> bool:
        """Check if the client appears to be installed."""
        return self.config_path().parent.exists()

    # ------------------------------------------------------------------
    # Helpers for navigating the servers dict inside the config
    # ------------------------------------------------------------------

    def _get_servers_dict(self, data: dict, *, create: bool = False) -> dict:
        """Return the dict that holds server entries, respecting _json_structure."""
        struct = self._json_structure
        if struct is None:
            if create:
                return data.setdefault("mcpServers", {})
            return data.get("mcpServers", {})

        top_key, nested_key = struct
        if top_key is None:
            # servers at top level  e.g. config["servers"]
            if create:
                return data.setdefault(nested_key, {})
            return data.get(nested_key, {})

        # nested  e.g. config["mcp"]["servers"]
        if create:
            parent = data.setdefault(top_key, {})
            return parent.setdefault(nested_key, {})
        parent = data.get(top_key, {})
        return parent.get(nested_key, {})

    # ------------------------------------------------------------------

    def install(self, server_name: str, command: list[str]) -> bool:
        """Write server entry into the client's MCP config. Returns True if changed."""
        path = self.config_path()
        data = self._read_config(path)
        servers = self._get_servers_dict(data, create=True)
        entry = {"command": command[0], "args": command[1:]}
        if servers.get(server_name) == entry:
            return False
        servers[server_name] = entry
        self._write_config(path, data)
        return True

    def uninstall(self, server_name: str) -> bool:
        """Remove server entry from the client's MCP config. Returns True if changed."""
        path = self.config_path()
        data = self._read_config(path)
        servers = self._get_servers_dict(data, create=False)
        if server_name not in servers:
            return False
        del servers[server_name]
        self._write_config(path, data)
        return True

    def is_installed(self, server_name: str) -> bool:
        """Check if the server is already registered."""
        path = self.config_path()
        if not path.exists():
            return False
        data = self._read_config(path)
        return server_name in self._get_servers_dict(data)

    @staticmethod
    def _read_config(path: Path) -> dict:
        if not path.exists():
            return {}
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return {}

    @staticmethod
    def _write_config(path: Path, data: dict) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def _home() -> Path:
    return Path.home()


def _appdata() -> Path:
    """Windows %APPDATA%, falls back to ~/.config on other platforms."""
    val = os.environ.get("APPDATA")
    if val:
        return Path(val)
    return _home() / ".config"


def _vscode_global_storage(ext_id: str) -> Path:
    """Return the globalStorage path for a VS Code extension."""
    system = platform.system()
    if system == "Windows":
        base = Path(os.environ.get("APPDATA", "")) / "Code" / "User" / "globalStorage"
    elif system == "Darwin":
        base = _home() / "Library" / "Application Support" / "Code" / "User" / "globalStorage"
    else:
        base = _home() / ".config" / "Code" / "User" / "globalStorage"
    return base / ext_id


def _vscode_user_dir(variant: str = "Code") -> Path:
    """Return the VS Code User settings directory."""
    system = platform.system()
    if system == "Windows":
        return Path(os.environ.get("APPDATA", "")) / variant / "User"
    if system == "Darwin":
        return _home() / "Library" / "Application Support" / variant / "User"
    return _home() / ".config" / variant / "User"


# ===================================================================
# Concrete installers — sorted alphabetically
# ===================================================================


class AmazonQInstaller(MCPClientInstaller):
    name: ClassVar[str] = "Amazon Q"
    key: ClassVar[str] = "amazon-q"

    def config_path(self) -> Path:
        return _home() / ".aws" / "amazonq" / "mcp_config.json"


class AugmentCodeInstaller(MCPClientInstaller):
    """Augment Code stores MCP config inside VS Code's settings.json."""
    name: ClassVar[str] = "Augment Code"
    key: ClassVar[str] = "augment-code"
    _json_structure: ClassVar[tuple[str | None, str] | None] = ("augment", "mcpServers")

    def config_path(self) -> Path:
        return _vscode_user_dir() / "settings.json"


class ClaudeDesktopInstaller(MCPClientInstaller):
    name: ClassVar[str] = "Claude Desktop"
    key: ClassVar[str] = "claude-desktop"

    def config_path(self) -> Path:
        system = platform.system()
        if system == "Darwin":
            return _home() / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"
        if system == "Windows":
            return _appdata() / "Claude" / "claude_desktop_config.json"
        return _home() / ".config" / "claude" / "claude_desktop_config.json"


class ClaudeCodeInstaller(MCPClientInstaller):
    name: ClassVar[str] = "Claude Code"
    key: ClassVar[str] = "claude-code"

    def config_path(self) -> Path:
        return _home() / ".claude.json"


class ClineInstaller(MCPClientInstaller):
    name: ClassVar[str] = "Cline"
    key: ClassVar[str] = "cline"

    def config_path(self) -> Path:
        return _vscode_global_storage("saoudrizwan.claude-dev") / "settings" / "cline_mcp_settings.json"


class CopilotCLIInstaller(MCPClientInstaller):
    name: ClassVar[str] = "Copilot CLI"
    key: ClassVar[str] = "copilot-cli"

    def config_path(self) -> Path:
        return _home() / ".copilot" / "mcp-config.json"


class CrushInstaller(MCPClientInstaller):
    name: ClassVar[str] = "Crush"
    key: ClassVar[str] = "crush"

    def config_path(self) -> Path:
        return _home() / "crush.json"


class CursorInstaller(MCPClientInstaller):
    name: ClassVar[str] = "Cursor"
    key: ClassVar[str] = "cursor"

    def config_path(self) -> Path:
        return _home() / ".cursor" / "mcp.json"


class GeminiCLIInstaller(MCPClientInstaller):
    name: ClassVar[str] = "Gemini CLI"
    key: ClassVar[str] = "gemini-cli"

    def config_path(self) -> Path:
        return _home() / ".gemini" / "settings.json"


class KiloCodeInstaller(MCPClientInstaller):
    name: ClassVar[str] = "Kilo Code"
    key: ClassVar[str] = "kilo-code"

    def config_path(self) -> Path:
        return _vscode_global_storage("kilocode.kilo-code") / "settings" / "mcp_settings.json"


class KiroInstaller(MCPClientInstaller):
    name: ClassVar[str] = "Kiro"
    key: ClassVar[str] = "kiro"

    def config_path(self) -> Path:
        return _home() / ".kiro" / "mcp_config.json"


class LMStudioInstaller(MCPClientInstaller):
    name: ClassVar[str] = "LM Studio"
    key: ClassVar[str] = "lm-studio"

    def config_path(self) -> Path:
        return _home() / ".lmstudio" / "mcp.json"


class OpencodeInstaller(MCPClientInstaller):
    name: ClassVar[str] = "Opencode"
    key: ClassVar[str] = "opencode"

    def config_path(self) -> Path:
        return _home() / ".opencode" / "mcp_config.json"


class QodoGenInstaller(MCPClientInstaller):
    """Qodo Gen stores MCP config inside VS Code's settings.json."""
    name: ClassVar[str] = "Qodo Gen"
    key: ClassVar[str] = "qodo-gen"
    _json_structure: ClassVar[tuple[str | None, str] | None] = ("qodo-gen", "mcpServers")

    def config_path(self) -> Path:
        return _vscode_user_dir() / "settings.json"


class QwenCoderInstaller(MCPClientInstaller):
    name: ClassVar[str] = "Qwen Coder"
    key: ClassVar[str] = "qwen-coder"

    def config_path(self) -> Path:
        return _home() / ".qwen" / "settings.json"


class RooCodeInstaller(MCPClientInstaller):
    name: ClassVar[str] = "Roo Code"
    key: ClassVar[str] = "roo-code"

    def config_path(self) -> Path:
        return _vscode_global_storage("rooveterinaryinc.roo-cline") / "settings" / "mcp_settings.json"


class TraeInstaller(MCPClientInstaller):
    name: ClassVar[str] = "Trae"
    key: ClassVar[str] = "trae"

    def config_path(self) -> Path:
        return _home() / ".trae" / "mcp_config.json"


class VSCodeInstaller(MCPClientInstaller):
    name: ClassVar[str] = "VS Code"
    key: ClassVar[str] = "vscode"
    _json_structure: ClassVar[tuple[str | None, str] | None] = ("mcp", "servers")

    def config_path(self) -> Path:
        return _vscode_user_dir() / "settings.json"


class VSCodeInsidersInstaller(MCPClientInstaller):
    name: ClassVar[str] = "VS Code Insiders"
    key: ClassVar[str] = "vscode-insiders"
    _json_structure: ClassVar[tuple[str | None, str] | None] = ("mcp", "servers")

    def config_path(self) -> Path:
        return _vscode_user_dir("Code - Insiders") / "settings.json"


class WarpInstaller(MCPClientInstaller):
    name: ClassVar[str] = "Warp"
    key: ClassVar[str] = "warp"

    def config_path(self) -> Path:
        return _home() / ".warp" / "mcp_config.json"


class WindsurfInstaller(MCPClientInstaller):
    name: ClassVar[str] = "Windsurf"
    key: ClassVar[str] = "windsurf"

    def config_path(self) -> Path:
        return _home() / ".codeium" / "windsurf" / "mcp_config.json"


class ZedInstaller(MCPClientInstaller):
    name: ClassVar[str] = "Zed"
    key: ClassVar[str] = "zed"

    def config_path(self) -> Path:
        system = platform.system()
        if system == "Darwin":
            return _home() / "Library" / "Application Support" / "Zed" / "settings.json"
        if system == "Windows":
            return _appdata() / "Zed" / "settings.json"
        return _home() / ".config" / "zed" / "settings.json"


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

ALL_CLIENTS: list[type[MCPClientInstaller]] = [
    AmazonQInstaller,
    AugmentCodeInstaller,
    ClaudeDesktopInstaller,
    ClaudeCodeInstaller,
    ClineInstaller,
    CopilotCLIInstaller,
    CrushInstaller,
    CursorInstaller,
    GeminiCLIInstaller,
    KiloCodeInstaller,
    KiroInstaller,
    LMStudioInstaller,
    OpencodeInstaller,
    QodoGenInstaller,
    QwenCoderInstaller,
    RooCodeInstaller,
    TraeInstaller,
    VSCodeInstaller,
    VSCodeInsidersInstaller,
    WarpInstaller,
    WindsurfInstaller,
    ZedInstaller,
]

CLIENT_MAP: dict[str, type[MCPClientInstaller]] = {cls.key: cls for cls in ALL_CLIENTS}


def get_installer(key: str) -> MCPClientInstaller:
    """Instantiate an installer by its short key."""
    cls = CLIENT_MAP.get(key)
    if not cls:
        valid = ", ".join(CLIENT_MAP)
        msg = f"Unknown client '{key}'. Choose from: {valid}"
        raise ValueError(msg)
    return cls()


# ---------------------------------------------------------------------------
# Server launch command
# ---------------------------------------------------------------------------

_ENTRY_POINT = "ya-frida-mcp"


def _resolve_entry_point() -> str:
    """Resolve the absolute path to the ``ya-frida-mcp`` entry point.

    When the package lives inside a virtualenv (poetry, pdm, uv, plain venv),
    the bare name won't be on the system PATH that MCP clients see.  We resolve
    the full path so the registered command always works.

    Lookup order:
    1. ``shutil.which`` — works because *this* process is already running
       inside the correct environment.
    2. Derive from ``sys.executable``'s parent (entry point scripts are
       co-located with the interpreter).
    3. Bare name as last resort.
    """
    found = shutil.which(_ENTRY_POINT)
    if found:
        return str(Path(found).resolve())

    bin_dir = Path(sys.executable).parent
    suffix = ".exe" if sys.platform == "win32" else ""
    candidate = bin_dir / f"{_ENTRY_POINT}{suffix}"
    if candidate.exists():
        return str(candidate.resolve())

    return _ENTRY_POINT


def build_server_command() -> list[str]:
    """Return the argv list to launch the MCP server.

    Resolves the entry point to an absolute path so MCP clients can invoke it
    even when the package is installed inside a virtualenv that isn't on the
    system PATH.
    """
    return [_resolve_entry_point(), "serve"]

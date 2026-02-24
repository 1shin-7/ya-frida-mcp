"""MCP client installer — register/unregister server config in various MCP clients."""

from __future__ import annotations

import json
import os
import platform
import sys
from abc import ABC, abstractmethod
from pathlib import Path
from typing import ClassVar


class MCPClientInstaller(ABC):
    """Abstract base for MCP client config installers."""

    name: ClassVar[str]
    key: ClassVar[str]

    @abstractmethod
    def config_path(self) -> Path:
        """Return the path to this client's MCP config file."""

    def exists(self) -> bool:
        """Check if the client appears to be installed."""
        return self.config_path().parent.exists()

    def install(self, server_name: str, command: list[str]) -> bool:
        """Write server entry into the client's MCP config. Returns True if changed."""
        path = self.config_path()
        data = self._read_config(path)
        servers = data.setdefault("mcpServers", {})
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
        servers = data.get("mcpServers", {})
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
        return server_name in data.get("mcpServers", {})

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


class CursorInstaller(MCPClientInstaller):
    name: ClassVar[str] = "Cursor"
    key: ClassVar[str] = "cursor"

    def config_path(self) -> Path:
        return _home() / ".cursor" / "mcp.json"


class WindsurfInstaller(MCPClientInstaller):
    name: ClassVar[str] = "Windsurf"
    key: ClassVar[str] = "windsurf"

    def config_path(self) -> Path:
        return _home() / ".codeium" / "windsurf" / "mcp_config.json"


class VSCodeInstaller(MCPClientInstaller):
    name: ClassVar[str] = "VS Code"
    key: ClassVar[str] = "vscode"

    def config_path(self) -> Path:
        return Path.cwd() / ".vscode" / "mcp.json"


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

ALL_CLIENTS: list[type[MCPClientInstaller]] = [
    ClaudeDesktopInstaller,
    ClaudeCodeInstaller,
    CursorInstaller,
    WindsurfInstaller,
    VSCodeInstaller,
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


def build_server_command() -> list[str]:
    """Build the command list for launching this MCP server via uv."""
    project_dir = str(Path.cwd().resolve())
    python = sys.executable
    return [python, str(Path(project_dir) / "main.py"), "serve"]

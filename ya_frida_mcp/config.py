"""Configuration management with TOML support."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path

import tomli_w

DEFAULT_CONFIG_NAME = "config.toml"


@dataclass
class RemoteDevice:
    """Remote Frida device connection config."""

    host: str = "127.0.0.1"
    port: int = 27042
    certificate: str | None = None


@dataclass
class ServerConfig:
    """MCP server configuration."""

    name: str = "ya-frida-mcp"
    transport: str = "stdio"
    host: str = "0.0.0.0"
    port: int = 8000


@dataclass
class FridaConfig:
    """Frida-specific configuration."""

    default_device: str = "local"
    remote_devices: list[RemoteDevice] = field(default_factory=list)
    script_timeout: int = 30
    spawn_timeout: int = 30


@dataclass
class AppConfig:
    """Top-level application configuration."""

    server: ServerConfig = field(default_factory=ServerConfig)
    frida: FridaConfig = field(default_factory=FridaConfig)

    @classmethod
    def load(cls, path: Path | None = None) -> AppConfig:
        """Load config from TOML file, falling back to defaults."""
        if path is None:
            path = Path.cwd() / DEFAULT_CONFIG_NAME
        if not path.exists():
            return cls()
        with open(path, "rb") as f:
            raw = tomllib.load(f)
        return cls._from_dict(raw)

    @classmethod
    def _from_dict(cls, data: dict) -> AppConfig:
        server_data = data.get("server", {})
        frida_data = data.get("frida", {})
        remote_list = frida_data.pop("remote_devices", [])
        remotes = [RemoteDevice(**r) for r in remote_list]
        return cls(
            server=ServerConfig(**server_data),
            frida=FridaConfig(**frida_data, remote_devices=remotes),
        )

    def save(self, path: Path) -> None:
        """Persist current config to TOML file."""
        data = {
            "server": {
                "name": self.server.name,
                "transport": self.server.transport,
                "host": self.server.host,
                "port": self.server.port,
            },
            "frida": {
                "default_device": self.frida.default_device,
                "script_timeout": self.frida.script_timeout,
                "spawn_timeout": self.frida.spawn_timeout,
                "remote_devices": [
                    {"host": r.host, "port": r.port, **({"certificate": r.certificate} if r.certificate else {})}
                    for r in self.frida.remote_devices
                ],
            },
        }
        with open(path, "wb") as f:
            tomli_w.dump(data, f)

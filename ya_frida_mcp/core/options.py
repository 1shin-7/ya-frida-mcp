"""Frida process target resolution and option types."""

from dataclasses import dataclass
from typing import Literal

from ya_frida_mcp.core.device import FridaDeviceWrapper


@dataclass(frozen=True, slots=True)
class TargetSpec:
    """Process selection for attach — mirrors frida CLI -p/-n/-N/-F."""

    pid: int | None = None
    name: str | None = None
    identifier: str | None = None
    frontmost: bool = False

    def __post_init__(self) -> None:
        sources = sum([
            self.pid is not None,
            self.name is not None,
            self.identifier is not None,
            self.frontmost,
        ])
        if sources == 0:
            msg = "One of pid, name, identifier, or frontmost must be specified"
            raise ValueError(msg)
        if sources > 1:
            msg = "Only one of pid, name, identifier, or frontmost may be specified"
            raise ValueError(msg)

    @property
    def label(self) -> str:
        if self.pid is not None:
            return str(self.pid)
        if self.name is not None:
            return self.name
        if self.identifier is not None:
            return self.identifier
        return "frontmost"


async def resolve_target(spec: TargetSpec, device: FridaDeviceWrapper) -> int:
    """Resolve a TargetSpec to a concrete PID."""
    if spec.frontmost:
        app = await device.get_frontmost_application()
        if app is None:
            msg = "No frontmost application found"
            raise ValueError(msg)
        return app.pid

    if spec.pid is not None:
        return spec.pid

    if spec.name is not None:
        processes = await device.enumerate_processes()
        match = next((p for p in processes if p.name == spec.name), None)
        if match is None:
            msg = f"Process '{spec.name}' not found"
            raise ValueError(msg)
        return match.pid

    # identifier
    assert spec.identifier is not None
    apps = await device.enumerate_applications()
    app = next((a for a in apps if a.identifier == spec.identifier), None)
    if app is None or app.pid == 0:
        msg = f"Application '{spec.identifier}' not found or not running"
        raise ValueError(msg)
    return app.pid


ScriptRuntime = Literal["qjs", "v8"]
SessionRealm = Literal["native", "emulated"]

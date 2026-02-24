"""Frida device management with remote support."""

from typing import Any

import frida

from ya_frida_mcp.config import AppConfig, RemoteDevice
from ya_frida_mcp.core.base import BaseFridaDevice, BaseFridaManager


class FridaDeviceWrapper(BaseFridaDevice):
    """Async wrapper around a single frida.core.Device."""

    def __init__(self, device: "frida.core.Device") -> None:
        self._device = device

    @property
    def raw(self) -> "frida.core.Device":
        return self._device

    @property
    def id(self) -> str:
        return self._device.id

    @property
    def name(self) -> str:
        return self._device.name

    @property
    def dtype(self) -> str:
        return self._device.type

    async def enumerate_processes(
        self,
        pids: list[int] | None = None,
        scope: str | None = None,
    ) -> "list[frida.core.Process]":
        kwargs: dict[str, object] = {}
        if pids is not None:
            kwargs["pids"] = pids
        if scope is not None:
            kwargs["scope"] = scope
        return await BaseFridaManager.run_sync(self._device.enumerate_processes, **kwargs)

    async def enumerate_applications(
        self,
        identifiers: list[str] | None = None,
        scope: str | None = None,
    ) -> "list[frida.core.Application]":
        kwargs: dict[str, object] = {}
        if identifiers is not None:
            kwargs["identifiers"] = identifiers
        if scope is not None:
            kwargs["scope"] = scope
        return await BaseFridaManager.run_sync(self._device.enumerate_applications, **kwargs)

    async def get_frontmost_application(
        self,
        scope: str | None = None,
    ) -> "frida.core.Application | None":
        kwargs: dict[str, object] = {}
        if scope is not None:
            kwargs["scope"] = scope
        return await BaseFridaManager.run_sync(self._device.get_frontmost_application, **kwargs)

    async def attach(
        self,
        target: int | str,
        realm: str | None = None,
        persist_timeout: int | None = None,
    ) -> "frida.core.Session":
        kwargs: dict[str, object] = {}
        if realm is not None:
            kwargs["realm"] = realm
        if persist_timeout is not None:
            kwargs["persist_timeout"] = persist_timeout
        return await BaseFridaManager.run_sync(self._device.attach, target, **kwargs)

    async def spawn(
        self,
        program: str,
        *,
        argv: list[str] | None = None,
        env: dict[str, str] | None = None,
        cwd: str | None = None,
        stdio: str | None = None,
    ) -> int:
        kwargs: dict[str, object] = {}
        if argv is not None:
            kwargs["argv"] = argv
        if env is not None:
            kwargs["env"] = env
        if cwd is not None:
            kwargs["cwd"] = cwd
        if stdio is not None:
            kwargs["stdio"] = stdio
        return await BaseFridaManager.run_sync(self._device.spawn, program, **kwargs)

    async def resume(self, pid: int) -> None:
        await BaseFridaManager.run_sync(self._device.resume, pid)

    async def kill(self, pid: int) -> None:
        await BaseFridaManager.run_sync(self._device.kill, pid)

    # --- Phase 1: system info ---

    async def query_system_parameters(self) -> dict[str, Any]:
        return await BaseFridaManager.run_sync(self._device.query_system_parameters)

    # --- Phase 2: spawn gating ---

    async def enable_spawn_gating(self) -> None:
        await BaseFridaManager.run_sync(self._device.enable_spawn_gating)

    async def disable_spawn_gating(self) -> None:
        await BaseFridaManager.run_sync(self._device.disable_spawn_gating)

    async def enumerate_pending_spawn(self) -> list:
        return await BaseFridaManager.run_sync(self._device.enumerate_pending_spawn)

    async def enumerate_pending_children(self) -> list:
        return await BaseFridaManager.run_sync(self._device.enumerate_pending_children)

    # --- Phase 4: native library injection ---

    async def inject_library_file(
        self, target: int, path: str, entrypoint: str, data: str,
    ) -> int:
        return await BaseFridaManager.run_sync(
            self._device.inject_library_file, target, path, entrypoint, data,
        )

    async def inject_library_blob(
        self, target: int, blob: bytes, entrypoint: str, data: str,
    ) -> int:
        return await BaseFridaManager.run_sync(
            self._device.inject_library_blob, target, blob, entrypoint, data,
        )


class DeviceManager(BaseFridaManager):
    """Manages Frida device discovery and remote connections."""

    def __init__(self, config: AppConfig) -> None:
        self._config = config
        self._mgr: frida.core.DeviceManager | None = None
        self._devices: dict[str, FridaDeviceWrapper] = {}

    async def initialize(self) -> None:
        self._mgr = frida.get_device_manager()
        for remote in self._config.frida.remote_devices:
            await self._add_remote(remote)

    async def cleanup(self) -> None:
        self._devices.clear()
        self._mgr = None

    async def _add_remote(self, remote: RemoteDevice) -> FridaDeviceWrapper:
        assert self._mgr is not None
        addr = f"{remote.host}:{remote.port}"
        device = await self.run_sync(self._mgr.add_remote_device, addr)
        wrapper = FridaDeviceWrapper(device)
        self._devices[wrapper.id] = wrapper
        return wrapper

    async def add_remote(self, host: str, port: int = 27042) -> FridaDeviceWrapper:
        """Dynamically add a remote device at runtime."""
        assert self._mgr is not None
        addr = f"{host}:{port}"
        device = await self.run_sync(self._mgr.add_remote_device, addr)
        wrapper = FridaDeviceWrapper(device)
        self._devices[wrapper.id] = wrapper
        return wrapper

    async def remove_remote(self, host: str, port: int = 27042) -> None:
        assert self._mgr is not None
        addr = f"{host}:{port}"
        await self.run_sync(self._mgr.remove_remote_device, addr)
        self._devices = {k: v for k, v in self._devices.items() if addr not in k}

    async def enumerate_devices(self) -> list[FridaDeviceWrapper]:
        assert self._mgr is not None
        raw_devices = await self.run_sync(self._mgr.enumerate_devices)
        for d in raw_devices:
            if d.id not in self._devices:
                self._devices[d.id] = FridaDeviceWrapper(d)
        return list(self._devices.values())

    async def get_device(self, device_id: str | None = None) -> FridaDeviceWrapper:
        """Get device by ID, or the default device from config."""
        if not self._devices:
            await self.enumerate_devices()
        target_id = device_id or self._config.frida.default_device
        if target_id == "local":
            device = await self.run_sync(frida.get_local_device)
            wrapper = FridaDeviceWrapper(device)
            self._devices[wrapper.id] = wrapper
            return wrapper
        if target_id == "usb":
            device = await self.run_sync(frida.get_usb_device)
            wrapper = FridaDeviceWrapper(device)
            self._devices[wrapper.id] = wrapper
            return wrapper
        if target_id in self._devices:
            return self._devices[target_id]
        # Attempt a direct lookup via the device manager, which properly
        # establishes the transport connection (unlike cached enumerate refs).
        assert self._mgr is not None
        try:
            device = await self.run_sync(self._mgr.get_device, target_id, 5)
            wrapper = FridaDeviceWrapper(device)
            self._devices[wrapper.id] = wrapper
            return wrapper
        except frida.InvalidArgumentError:
            pass
        msg = f"Device '{target_id}' not found. Available: {list(self._devices.keys())}"
        raise ValueError(msg)

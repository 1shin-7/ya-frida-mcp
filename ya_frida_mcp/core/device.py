"""Frida device management with remote support."""

from __future__ import annotations

from typing import Any

import frida

from ya_frida_mcp.config import AppConfig, RemoteDevice
from ya_frida_mcp.core.base import BaseFridaDevice, BaseFridaManager


class FridaDeviceWrapper(BaseFridaDevice):
    """Async wrapper around a single frida.core.Device."""

    def __init__(self, device: frida.core.Device) -> None:
        self._device = device

    @property
    def raw(self) -> frida.core.Device:
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

    async def enumerate_processes(self) -> list[frida.core.Process]:
        return await BaseFridaManager.run_sync(self._device.enumerate_processes)

    async def enumerate_applications(self) -> list[frida.core.Application]:
        return await BaseFridaManager.run_sync(self._device.enumerate_applications)

    async def attach(self, target: int | str) -> frida.core.Session:
        return await BaseFridaManager.run_sync(self._device.attach, target)

    async def spawn(self, program: str, **kwargs: Any) -> int:
        return await BaseFridaManager.run_sync(self._device.spawn, program, **kwargs)

    async def resume(self, pid: int) -> None:
        await BaseFridaManager.run_sync(self._device.resume, pid)

    async def kill(self, pid: int) -> None:
        await BaseFridaManager.run_sync(self._device.kill, pid)


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
        if self._mgr:
            await self.run_sync(self._mgr.close)
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
        msg = f"Device '{target_id}' not found. Available: {list(self._devices.keys())}"
        raise ValueError(msg)

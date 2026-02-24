"""Frida session and script lifecycle management."""

from __future__ import annotations

import contextlib
from typing import Any

import frida

from ya_frida_mcp.core.base import BaseFridaManager
from ya_frida_mcp.core.device import FridaDeviceWrapper


class ScriptHandle:
    """Wrapper around a loaded Frida script with message handling."""

    def __init__(self, script: frida.core.Script, pid: int) -> None:
        self._script = script
        self.pid = pid
        self.messages: list[dict[str, Any]] = []
        self._script.on("message", self._on_message)

    def _on_message(self, message: dict[str, Any], data: Any) -> None:
        self.messages.append({"message": message, "data": str(data) if data else None})

    async def load(self) -> None:
        await BaseFridaManager.run_sync(self._script.load)

    async def unload(self) -> None:
        await BaseFridaManager.run_sync(self._script.unload)

    async def exports_call(self, method: str, *args: Any) -> Any:
        fn = getattr(self._script.exports_sync, method)
        return await BaseFridaManager.run_sync(fn, *args)

    @property
    def is_destroyed(self) -> bool:
        return self._script.is_destroyed


class SessionManager(BaseFridaManager):
    """Manages Frida attach/spawn sessions and injected scripts."""

    def __init__(self) -> None:
        self._sessions: dict[int, frida.core.Session] = {}
        self._scripts: dict[str, ScriptHandle] = {}
        self._script_counter = 0

    async def initialize(self) -> None:
        pass

    async def cleanup(self) -> None:
        for handle in self._scripts.values():
            if not handle.is_destroyed:
                with contextlib.suppress(frida.InvalidOperationError):
                    await handle.unload()
        self._scripts.clear()
        for session in self._sessions.values():
            with contextlib.suppress(frida.InvalidOperationError):
                await self.run_sync(session.detach)
        self._sessions.clear()

    async def attach(self, device: FridaDeviceWrapper, target: int | str) -> frida.core.Session:
        session = await device.attach(target)
        pid = session.pid
        self._sessions[pid] = session
        return session

    async def spawn_and_attach(
        self, device: FridaDeviceWrapper, program: str, *, auto_resume: bool = True
    ) -> tuple[int, frida.core.Session]:
        pid = await device.spawn(program)
        session = await device.attach(pid)
        self._sessions[pid] = session
        if auto_resume:
            await device.resume(pid)
        return pid, session

    async def detach(self, pid: int) -> None:
        session = self._sessions.pop(pid, None)
        if session:
            await self.run_sync(session.detach)

    async def inject_script(self, pid: int, source: str) -> str:
        session = self._sessions.get(pid)
        if not session:
            msg = f"No active session for PID {pid}. Attach first."
            raise ValueError(msg)
        script = await self.run_sync(session.create_script, source)
        self._script_counter += 1
        script_id = f"script_{self._script_counter}"
        handle = ScriptHandle(script, pid)
        await handle.load()
        self._scripts[script_id] = handle
        return script_id

    async def call_rpc(self, script_id: str, method: str, *args: Any) -> Any:
        handle = self._scripts.get(script_id)
        if not handle:
            msg = f"Script '{script_id}' not found."
            raise ValueError(msg)
        return await handle.exports_call(method, *args)

    async def unload_script(self, script_id: str) -> None:
        handle = self._scripts.pop(script_id, None)
        if handle and not handle.is_destroyed:
            await handle.unload()

    async def get_messages(self, script_id: str) -> list[dict[str, Any]]:
        handle = self._scripts.get(script_id)
        if not handle:
            msg = f"Script '{script_id}' not found."
            raise ValueError(msg)
        msgs = list(handle.messages)
        handle.messages.clear()
        return msgs

    def list_sessions(self) -> list[int]:
        return list(self._sessions.keys())

    def list_scripts(self) -> list[str]:
        return list(self._scripts.keys())

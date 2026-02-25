"""Frida session and script lifecycle management."""

import contextlib
import re
from pathlib import Path
from typing import Any

import frida

from ya_frida_mcp.core.base import BaseFridaManager
from ya_frida_mcp.core.bridges import ensure_bridges
from ya_frida_mcp.core.device import FridaDeviceWrapper
from ya_frida_mcp.core.options import ScriptRuntime, SessionRealm, TargetSpec, resolve_target

_V8_PATTERN = re.compile(
    r"\bJava\s*\.|"
    r"\bObjC\s*\.|"
    r"\bSwift\s*\.",
)

# Bridge JS files (Java/ObjC/Swift) downloaded from GitHub release at runtime.
# We do NOT bundle these files to respect the wxWindows Library Licence (LGPL).
_BRIDGES_DIR: Path | None = ensure_bridges()


def _needs_v8(source: str) -> bool:
    """Return True if the script source uses APIs that require the V8 runtime."""
    return _V8_PATTERN.search(source) is not None


# Bridge loader stub injected before user scripts.
# Defines lazy getters for Java/ObjC/Swift that request bridge code from the host.
_BRIDGE_LOADER = """\
(function(){
  function defineBridge(name){
    Object.defineProperty(globalThis,name,{
      enumerable:true,configurable:true,
      get:function(){
        var b;
        send({type:"frida:load-bridge",name:name});
        recv("frida:bridge-loaded",function(msg){
          b=Script.evaluate("/frida/bridges/"+msg.filename,
            "(function(){"+msg.source+
            ";Object.defineProperty(globalThis,'"+name+"',{value:bridge});return bridge;})();");
        }).wait();
        return b;
      }
    });
  }
  defineBridge("Java");defineBridge("ObjC");defineBridge("Swift");
})();
"""


class ScriptHandle:
    """Wrapper around a loaded Frida script with message handling."""

    def __init__(self, script: "frida.core.Script", pid: int) -> None:
        self._script = script
        self.pid = pid
        self.messages: list[dict[str, Any]] = []
        self._script.on("message", self._on_message)

    def _on_message(self, message: dict[str, Any], data: Any) -> None:
        if self._try_handle_bridge_request(message):
            return
        self.messages.append({"message": message, "data": str(data) if data else None})

    def _try_handle_bridge_request(self, message: dict[str, Any]) -> bool:
        """Handle frida:load-bridge requests from the bridge loader stub."""
        if message.get("type") != "send" or _BRIDGES_DIR is None:
            return False
        payload = message.get("payload")
        if not isinstance(payload, dict) or payload.get("type") != "frida:load-bridge":
            return False
        stem = payload["name"].lower()
        bridge = _BRIDGES_DIR / f"{stem}.js"
        if not bridge.exists():
            return False
        self._script.post({
            "type": "frida:bridge-loaded",
            "filename": bridge.name,
            "source": bridge.read_text(encoding="utf-8"),
        })
        return True

    async def load(self) -> None:
        await BaseFridaManager.run_sync(self._script.load)

    async def unload(self) -> None:
        await BaseFridaManager.run_sync(self._script.unload)

    async def exports_call(self, method: str, *args: Any) -> Any:
        fn = getattr(self._script.exports_sync, method)
        return await BaseFridaManager.run_sync(fn, *args)

    async def list_exports(self) -> list[str]:
        return await BaseFridaManager.run_sync(self._script.list_exports_sync)

    async def post(self, message: Any, data: bytes | None = None) -> None:
        await BaseFridaManager.run_sync(self._script.post, message, data)

    async def eternalize(self) -> None:
        await BaseFridaManager.run_sync(self._script.eternalize)

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

    async def attach(
        self,
        device: FridaDeviceWrapper,
        target: TargetSpec,
        *,
        realm: SessionRealm | None = None,
        persist_timeout: int | None = None,
    ) -> "tuple[int, frida.core.Session]":
        """Attach to a process described by *target*."""
        pid = await resolve_target(target, device)
        session = await device.attach(pid, realm=realm, persist_timeout=persist_timeout)
        self._sessions[pid] = session
        return pid, session

    async def spawn_and_attach(
        self,
        device: FridaDeviceWrapper,
        program: str,
        *,
        auto_resume: bool = True,
        argv: list[str] | None = None,
        env: dict[str, str] | None = None,
        cwd: str | None = None,
        stdio: str | None = None,
    ) -> "tuple[int, frida.core.Session]":
        pid = await device.spawn(program, argv=argv, env=env, cwd=cwd, stdio=stdio)
        session = await device.attach(pid)
        self._sessions[pid] = session
        if auto_resume:
            await device.resume(pid)
        return pid, session

    async def detach(self, pid: int) -> None:
        session = self._sessions.pop(pid, None)
        if session:
            await self.run_sync(session.detach)

    async def inject_script(
        self,
        pid: int,
        source: str,
        *,
        runtime: ScriptRuntime | None = None,
    ) -> str:
        session = self._sessions.get(pid)
        if not session:
            msg = f"No active session for PID {pid}. Attach first."
            raise ValueError(msg)
        # Prepend bridge loader when script uses Java/ObjC/Swift APIs
        if _BRIDGES_DIR is not None and _needs_v8(source):
            source = _BRIDGE_LOADER + source
        kwargs: dict[str, object] = {}
        if runtime is not None:
            kwargs["runtime"] = runtime
        script = await self.run_sync(session.create_script, source, **kwargs)
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

    # --- Phase 1: script exports & messaging ---

    async def list_script_exports(self, script_id: str) -> list[str]:
        handle = self._scripts.get(script_id)
        if not handle:
            msg = f"Script '{script_id}' not found."
            raise ValueError(msg)
        return await handle.list_exports()

    async def post_message(self, script_id: str, message: Any, data: bytes | None = None) -> None:
        handle = self._scripts.get(script_id)
        if not handle:
            msg = f"Script '{script_id}' not found."
            raise ValueError(msg)
        await handle.post(message, data)

    # --- Phase 3: child gating ---

    def _get_session(self, pid: int) -> "frida.core.Session":
        session = self._sessions.get(pid)
        if not session:
            msg = f"No active session for PID {pid}. Attach first."
            raise ValueError(msg)
        return session

    async def enable_child_gating(self, pid: int) -> None:
        session = self._get_session(pid)
        await self.run_sync(session.enable_child_gating)

    async def disable_child_gating(self, pid: int) -> None:
        session = self._get_session(pid)
        await self.run_sync(session.disable_child_gating)

    # --- Phase 3: compile / snapshot / eternalize ---

    async def compile_script(
        self, pid: int, source: str, runtime: ScriptRuntime | None = None,
    ) -> bytes:
        session = self._get_session(pid)
        kwargs: dict[str, object] = {}
        if runtime is not None:
            kwargs["runtime"] = runtime
        return await self.run_sync(session.compile_script, source, **kwargs)

    async def snapshot_script(
        self,
        pid: int,
        embed_script: str,
        warmup_script: str | None = None,
        runtime: ScriptRuntime | None = None,
    ) -> bytes:
        session = self._get_session(pid)
        if runtime is not None:
            return await self.run_sync(
                session.snapshot_script, embed_script, warmup_script or "", runtime=runtime,
            )
        return await self.run_sync(session.snapshot_script, embed_script, warmup_script or "")

    async def eternalize_script(self, script_id: str) -> None:
        handle = self._scripts.get(script_id)
        if not handle:
            msg = f"Script '{script_id}' not found."
            raise ValueError(msg)
        await handle.eternalize()

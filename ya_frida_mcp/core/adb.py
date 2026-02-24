"""Async wrapper around the native ``adb`` CLI."""

from __future__ import annotations

import asyncio
import shutil
from dataclasses import dataclass, field


class ADBError(Exception):
    """Raised when an adb command exits with a non-zero status."""

    def __init__(self, args: list[str], stderr: str, returncode: int) -> None:
        self.args_list = args
        self.stderr = stderr
        self.returncode = returncode
        cmd = " ".join(args)
        super().__init__(f"adb command failed (rc={returncode}): {cmd}\n{stderr}")


@dataclass
class ADBClient:
    """Thin async wrapper around the ``adb`` CLI binary.

    All methods shell out to ``adb`` via :func:`asyncio.create_subprocess_exec`.
    An optional *device_id* is forwarded as ``-s <id>`` to every invocation.
    """

    device_id: str | None = None
    _adb_bin: str = field(init=False, default="adb")

    # ------------------------------------------------------------------
    # Class helpers
    # ------------------------------------------------------------------

    @classmethod
    def available(cls) -> bool:
        """Return *True* if ``adb`` is found on PATH."""
        return shutil.which("adb") is not None

    # ------------------------------------------------------------------
    # Low-level execution
    # ------------------------------------------------------------------

    async def _run(self, *args: str, timeout: float = 30.0) -> tuple[str, str, int]:
        """Execute ``adb [global flags] <args>`` and return *(stdout, stderr, rc)*."""
        cmd = [self._adb_bin]
        if self.device_id:
            cmd.extend(["-s", self.device_id])
        cmd.extend(args)

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return (
            stdout_b.decode(errors="replace").strip(),
            stderr_b.decode(errors="replace").strip(),
            proc.returncode or 0,
        )

    async def _run_checked(self, *args: str, timeout: float = 30.0) -> str:
        """Like :meth:`_run` but raises :class:`ADBError` on failure."""
        stdout, stderr, rc = await self._run(*args, timeout=timeout)
        if rc != 0:
            raise ADBError(list(args), stderr, rc)
        return stdout

    # ------------------------------------------------------------------
    # Device management
    # ------------------------------------------------------------------

    async def devices(self) -> list[dict[str, str]]:
        """List connected devices (``adb devices -l``)."""
        out = await self._run_checked("devices", "-l")
        results: list[dict[str, str]] = []
        for line in out.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 2:
                continue
            info: dict[str, str] = {"serial": parts[0], "state": parts[1]}
            for token in parts[2:]:
                if ":" in token:
                    k, v = token.split(":", 1)
                    info[k] = v
            results.append(info)
        return results

    async def connect(self, addr: str) -> str:
        """Connect to a device over TCP/IP."""
        return await self._run_checked("connect", addr)

    async def disconnect(self, addr: str) -> str:
        """Disconnect a TCP/IP device."""
        return await self._run_checked("disconnect", addr)

    # ------------------------------------------------------------------
    # Shell & file transfer
    # ------------------------------------------------------------------

    async def shell(self, command: str, timeout: float = 30.0) -> str:
        """Run a shell command on the device."""
        return await self._run_checked("shell", command, timeout=timeout)

    async def push(self, local: str, remote: str) -> str:
        """Push a local file/dir to the device."""
        return await self._run_checked("push", local, remote, timeout=120.0)

    async def pull(self, remote: str, local: str) -> str:
        """Pull a file/dir from the device."""
        return await self._run_checked("pull", remote, local, timeout=120.0)

    # ------------------------------------------------------------------
    # App management
    # ------------------------------------------------------------------

    async def install(self, apk_path: str, *, flags: list[str] | None = None) -> str:
        """Install an APK (``adb install [-r -d ...] <path>``)."""
        args = ["install", *(flags or []), apk_path]
        return await self._run_checked(*args, timeout=120.0)

    async def uninstall(self, package: str, *, keep_data: bool = False) -> str:
        """Uninstall a package."""
        args = ["uninstall"]
        if keep_data:
            args.append("-k")
        args.append(package)
        return await self._run_checked(*args, timeout=60.0)

    # ------------------------------------------------------------------
    # Port forwarding
    # ------------------------------------------------------------------

    async def forward(self, local: str, remote: str) -> str:
        """Set up port forwarding (``adb forward <local> <remote>``)."""
        return await self._run_checked("forward", local, remote)

    async def forward_remove(self, local: str) -> str:
        """Remove a port forward rule."""
        return await self._run_checked("forward", "--remove", local)

    async def reverse(self, remote: str, local: str) -> str:
        """Set up reverse port forwarding."""
        return await self._run_checked("reverse", remote, local)

    async def reverse_remove(self, remote: str) -> str:
        """Remove a reverse port forward rule."""
        return await self._run_checked("reverse", "--remove", remote)

    # ------------------------------------------------------------------
    # Logcat
    # ------------------------------------------------------------------

    async def logcat(
        self,
        *,
        filters: str | None = None,
        lines: int = 200,
        dump: bool = True,
        timeout: float = 15.0,
    ) -> str:
        """Capture logcat output.

        Uses ``-d`` (dump) by default to avoid blocking.
        """
        args: list[str] = ["logcat", "-t", str(lines)]
        if dump:
            args.append("-d")
        if filters:
            args.extend(filters.split())
        return await self._run_checked(*args, timeout=timeout)

    # ------------------------------------------------------------------
    # Misc
    # ------------------------------------------------------------------

    async def reboot(self, mode: str | None = None) -> str:
        """Reboot the device (optionally into bootloader/recovery/sideload)."""
        args = ["reboot"]
        if mode:
            args.append(mode)
        return await self._run_checked(*args, timeout=30.0)

    async def getprop(self, prop: str) -> str:
        """Read a system property via ``adb shell getprop``."""
        return await self._run_checked("shell", "getprop", prop)

    async def root(self) -> str:
        """Restart adbd with root permissions."""
        return await self._run_checked("root")

    async def unroot(self) -> str:
        """Restart adbd without root permissions."""
        return await self._run_checked("unroot")

"""Download, deploy, and manage frida-server on Android devices via ADB."""

import lzma
import tempfile
import urllib.request
from pathlib import Path

import frida

from ya_frida_mcp.core.adb import ADBClient, ADBError

ABI_MAP: dict[str, str] = {
    "arm64-v8a": "arm64",
    "armeabi-v7a": "arm",
    "x86": "x86",
    "x86_64": "x86_64",
}

REMOTE_PATH = "/data/local/tmp/frida-server"

RELEASE_URL = (
    "https://github.com/frida/frida/releases/download"
    "/{version}/frida-server-{version}-android-{abi}.xz"
)


async def get_device_abi(adb: ADBClient) -> str:
    """Return the Frida-compatible ABI string for the connected device."""
    raw = await adb.shell("getprop ro.product.cpu.abi")
    abi = raw.strip()
    mapped = ABI_MAP.get(abi)
    if mapped is None:
        msg = f"Unsupported device ABI: {abi}"
        raise ValueError(msg)
    return mapped


async def get_server_status(adb: ADBClient) -> dict[str, object]:
    """Check whether frida-server is running and its version on the device.

    Returns a dict with keys: ``running``, ``device_version``,
    ``client_version``, and ``version_match``.
    """
    client_version: str = frida.__version__

    # Check if process is running
    try:
        pid_out = await adb.shell("pidof frida-server")
        running = bool(pid_out.strip())
    except ADBError:
        running = False

    # Try to get on-device binary version
    device_version: str | None = None
    try:
        ver_out = await adb.shell(f"{REMOTE_PATH} --version")
        ver = ver_out.strip()
        if ver:
            device_version = ver
    except ADBError:
        pass

    return {
        "running": running,
        "device_version": device_version,
        "client_version": client_version,
        "version_match": device_version == client_version,
    }


def download_frida_server(version: str, abi: str) -> Path:
    """Download and decompress a frida-server binary, returning its local path.

    Uses stdlib ``urllib.request`` and ``lzma`` — no extra dependencies.
    """
    url = RELEASE_URL.format(version=version, abi=abi)
    tmp_dir = Path(tempfile.mkdtemp(prefix="frida-server-"))
    xz_path = tmp_dir / f"frida-server-{version}-android-{abi}.xz"
    bin_path = tmp_dir / "frida-server"

    urllib.request.urlretrieve(url, xz_path)

    with lzma.open(xz_path, "rb") as compressed, bin_path.open("wb") as out:
        while chunk := compressed.read(1 << 20):
            out.write(chunk)

    xz_path.unlink()
    return bin_path


async def push_and_start(adb: ADBClient, local_path: Path) -> str:
    """Push frida-server to the device, set permissions, and start it."""
    await adb.push(str(local_path), REMOTE_PATH)
    await adb.shell(f"chmod 755 {REMOTE_PATH}")
    # Start daemonized; nohup + setsid to survive shell exit
    await adb.shell(
        f"setsid {REMOTE_PATH} -D </dev/null >/dev/null 2>&1 &",
    )
    # Brief check that it actually started
    try:
        pid_out = await adb.shell("pidof frida-server")
        if pid_out.strip():
            return f"frida-server started (pid {pid_out.strip()})"
    except ADBError:
        pass
    return "frida-server start command issued (could not confirm pid)"


async def stop_server(adb: ADBClient) -> str:
    """Kill the running frida-server process on the device."""
    try:
        await adb.shell("pkill frida-server")
        return "frida-server stopped"
    except ADBError as e:
        if "No such process" in e.stderr or e.returncode == 1:
            return "frida-server was not running"
        raise

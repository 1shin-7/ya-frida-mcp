"""Abstract base classes for Frida managers."""

import asyncio
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    import frida


class BaseFridaManager(ABC):
    """Abstract base for all Frida resource managers."""

    @abstractmethod
    async def initialize(self) -> None:
        """Initialize the manager's resources."""

    @abstractmethod
    async def cleanup(self) -> None:
        """Release all managed resources."""

    @staticmethod
    async def run_sync(func: Any, *args: Any) -> Any:
        """Run a synchronous Frida call in a thread pool."""
        return await asyncio.to_thread(func, *args)


class BaseFridaDevice(ABC):
    """Abstract interface for Frida device operations."""

    @abstractmethod
    async def enumerate_processes(self, **kwargs) -> "list[frida.core.Process]":
        ...

    @abstractmethod
    async def enumerate_applications(self, **kwargs) -> "list[frida.core.Application]":
        ...

    @abstractmethod
    async def attach(self, target: int | str) -> "frida.core.Session":
        ...

    @abstractmethod
    async def spawn(self, program: str, **kwargs: Any) -> int:
        ...

    @abstractmethod
    async def resume(self, pid: int) -> None:
        ...

    @abstractmethod
    async def kill(self, pid: int) -> None:
        ...

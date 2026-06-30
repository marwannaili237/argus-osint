"""Base notifier abstract class."""
from abc import ABC, abstractmethod


class BaseNotifier(ABC):
    name: str = "base"
    enabled: bool = True

    @abstractmethod
    async def send(self, title: str, message: str, severity: str = "info", **kwargs) -> bool:
        pass

    @abstractmethod
    async def test_connection(self) -> bool:
        pass

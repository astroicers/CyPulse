from __future__ import annotations
from abc import ABC, abstractmethod


class DiscoveryTool(ABC):

    @abstractmethod
    def run(self, domain: str, config: dict) -> list[dict]:
        ...

    @abstractmethod
    def name(self) -> str:
        ...

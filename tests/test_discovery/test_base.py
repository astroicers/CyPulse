import pytest
from cypulse.discovery.base import DiscoveryTool


def test_discovery_tool_is_abstract():
    """DiscoveryTool 是 ABC，不能直接實例化"""
    with pytest.raises(TypeError):
        DiscoveryTool()


def test_discovery_tool_concrete_implementation():
    """具體實作須實作 run() 與 name()"""
    class ConcreteDiscovery(DiscoveryTool):
        def run(self, domain: str, config: dict) -> list[dict]:
            return [{"domain": domain}]

        def name(self) -> str:
            return "concrete"

    tool = ConcreteDiscovery()
    result = tool.run("example.com", {})
    assert result == [{"domain": "example.com"}]
    assert tool.name() == "concrete"


def test_discovery_tool_partial_implementation_fails():
    """只實作部分方法仍應報錯"""
    class PartialDiscovery(DiscoveryTool):
        def run(self, domain: str, config: dict) -> list[dict]:
            return []
        # 故意不實作 name()

    with pytest.raises(TypeError):
        PartialDiscovery()

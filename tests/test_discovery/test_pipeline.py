from unittest.mock import patch, MagicMock
import os
import json
import tempfile
from cypulse.discovery.pipeline import run_discovery, save_assets
from cypulse.models import Assets, Asset


class TestRunDiscovery:
    @patch("cypulse.discovery.pipeline.HttpxTool")
    @patch("cypulse.discovery.pipeline.NaabuTool")
    @patch("cypulse.discovery.pipeline.resolve_subdomains")
    @patch("cypulse.discovery.pipeline.query_web_sources")
    @patch("cypulse.discovery.pipeline.AmassTool")
    @patch("cypulse.discovery.pipeline.SubfinderTool")
    def test_full_pipeline(self, MockSF, MockAmass, mock_web, mock_resolve, MockNaabu, MockHttpx):
        # subfinder returns 2 subdomains
        sf_instance = MockSF.return_value
        sf_instance.run.return_value = [
            {"subdomain": "www.example.com", "source": "subfinder"},
            {"subdomain": "api.example.com", "source": "subfinder"},
        ]

        # amass returns 1 overlapping + 1 new
        am_instance = MockAmass.return_value
        am_instance.run.return_value = [
            {"subdomain": "www.example.com", "source": "amass"},
            {"subdomain": "mail.example.com", "source": "amass"},
        ]

        # web sources return 1 overlapping + 1 new
        mock_web.return_value = [
            {"subdomain": "www.example.com"},
            {"subdomain": "cdn.example.com"},
        ]

        # dnsx resolves
        mock_resolve.return_value = [
            {"subdomain": "example.com", "ip": "93.184.216.34"},
            {"subdomain": "www.example.com", "ip": "93.184.216.34"},
            {"subdomain": "api.example.com", "ip": "93.184.216.35"},
            {"subdomain": "mail.example.com", "ip": "93.184.216.36"},
            {"subdomain": "cdn.example.com", "ip": "93.184.216.37"},
        ]

        # naabu returns ports
        naabu_instance = MockNaabu.return_value
        naabu_instance.run.return_value = [
            {"host": "www.example.com", "port": 80},
            {"host": "www.example.com", "port": 443},
            {"host": "api.example.com", "port": 443},
        ]

        # httpx returns http info
        httpx_instance = MockHttpx.return_value
        httpx_instance.run.return_value = [
            {"subdomain": "www.example.com", "http_status": 200, "http_title": "Example"},
            {"subdomain": "api.example.com", "http_status": 200, "http_title": "API"},
        ]

        config = {"timeout": 300}
        assets = run_discovery("example.com", config)

        assert isinstance(assets, Assets)
        assert assets.domain == "example.com"
        assert assets.total_subdomains == 5  # example.com + www + api + mail + cdn
        assert assets.total_live == 5  # all have IPs
        assert assets.total_http == 2  # www + api

        # Check deduplication
        subs = [a.subdomain for a in assets.subdomains]
        assert len(subs) == len(set(subs))


class TestPortDedup:
    @patch("cypulse.discovery.pipeline.HttpxTool")
    @patch("cypulse.discovery.pipeline.NaabuTool")
    @patch("cypulse.discovery.pipeline.resolve_subdomains")
    @patch("cypulse.discovery.pipeline.query_web_sources")
    @patch("cypulse.discovery.pipeline.AmassTool")
    @patch("cypulse.discovery.pipeline.SubfinderTool")
    def test_ports_deduped(self, MockSF, MockAmass, mock_web, mock_resolve, MockNaabu, MockHttpx):
        sf_instance = MockSF.return_value
        sf_instance.run.return_value = [{"subdomain": "www.example.com"}]
        am_instance = MockAmass.return_value
        am_instance.run.return_value = []
        mock_web.return_value = []
        mock_resolve.return_value = [
            {"subdomain": "example.com", "ip": "1.2.3.4"},
            {"subdomain": "www.example.com", "ip": "1.2.3.4"},
        ]
        naabu_instance = MockNaabu.return_value
        naabu_instance.run.return_value = [
            {"host": "www.example.com", "port": 443},
            {"host": "www.example.com", "port": 443},
            {"host": "www.example.com", "port": 80},
        ]
        httpx_instance = MockHttpx.return_value
        httpx_instance.run.return_value = []
        assets = run_discovery("example.com", {})
        www = next(a for a in assets.subdomains if a.subdomain == "www.example.com")
        assert www.ports == [80, 443]  # deduped and sorted


class TestSaveAssets:
    def test_save_and_read(self):
        assets = Assets(
            domain="example.com",
            timestamp="2026-03-12T020000",
            subdomains=[
                Asset(subdomain="www.example.com", ip="93.184.216.34", ports=[80, 443]),
            ],
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            scan_dir = save_assets(assets, tmpdir)
            assert os.path.isdir(scan_dir)
            path = os.path.join(scan_dir, "assets.json")
            assert os.path.isfile(path)
            with open(path) as f:
                data = json.load(f)
            assert data["domain"] == "example.com"
            assert len(data["subdomains"]) == 1

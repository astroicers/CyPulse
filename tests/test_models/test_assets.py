from cypulse.models import Asset, Assets


class TestAsset:
    def test_create_asset(self, sample_asset):
        assert sample_asset.subdomain == "www.example.com"
        assert sample_asset.ip == "93.184.216.34"
        assert sample_asset.ports == [80, 443]

    def test_asset_defaults(self):
        asset = Asset(subdomain="test.example.com")
        assert asset.ip is None
        assert asset.ports == []
        assert asset.http_status is None
        assert asset.security_headers == {}


class TestAssets:
    def test_create_assets(self, sample_assets):
        assert sample_assets.domain == "example.com"
        assert sample_assets.total_subdomains == 1
        assert sample_assets.total_live == 1
        assert sample_assets.total_http == 1

    def test_empty_assets(self):
        assets = Assets(domain="example.com", timestamp="2026-03-12T020000")
        assert assets.total_subdomains == 0
        assert assets.total_live == 0
        assert assets.total_http == 0

    def test_to_dict(self, sample_assets):
        d = sample_assets.to_dict()
        assert d["domain"] == "example.com"
        assert len(d["subdomains"]) == 1

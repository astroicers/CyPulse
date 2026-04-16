import os
import json
import tempfile
from cypulse.analysis.runner import run_analysis, save_findings
from cypulse.models import Asset, Assets


class TestRunAnalysis:
    def _make_assets(self):
        return Assets(
            domain="example.com",
            timestamp="2026-03-12T020000",
            subdomains=[
                Asset(
                    subdomain="www.example.com",
                    ip="93.184.216.34",
                    ports=[80, 443],
                    http_status=200,
                    security_headers={},
                ),
            ],
        )

    def test_run_all_modules(self):
        assets = self._make_assets()
        findings = run_analysis(assets)
        assert findings.domain == "example.com"
        assert len(findings.modules) == 8
        for m in findings.modules:
            assert m.module_id in ["M1", "M2", "M3", "M4", "M5", "M6", "M7", "M8"]

    def test_run_selected_modules(self):
        assets = self._make_assets()
        findings = run_analysis(assets, module_ids=["M1", "M3"])
        assert len(findings.modules) == 2

    def test_save_findings(self):
        assets = self._make_assets()
        findings = run_analysis(assets, module_ids=["M1"])
        with tempfile.TemporaryDirectory() as tmpdir:
            save_findings(findings, tmpdir)
            assert os.path.isfile(os.path.join(tmpdir, "findings.json"))
            assert os.path.isfile(os.path.join(tmpdir, "module_M1.json"))
            with open(os.path.join(tmpdir, "findings.json")) as f:
                data = json.load(f)
            assert data["domain"] == "example.com"

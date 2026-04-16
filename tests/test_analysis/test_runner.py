import os
import json
import tempfile
from cypulse.analysis.runner import run_analysis, save_findings
from cypulse.models import Asset, Assets
from cypulse.scoring.weights import WEIGHTS


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
        # 模組數必須與 WEIGHTS 定義一致（加 M9 時自動更新）
        assert len(findings.modules) == len(WEIGHTS)
        for m in findings.modules:
            assert m.module_id in WEIGHTS

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

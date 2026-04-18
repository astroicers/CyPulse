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

    def test_on_module_done_callback_invoked(self):
        """每個模組完成時應呼叫 on_module_done callback 一次（用於進度條）。"""
        assets = self._make_assets()
        called_modules = []

        def callback(module_id: str):
            called_modules.append(module_id)

        findings = run_analysis(
            assets,
            module_ids=["M1", "M3", "M7"],
            on_module_done=callback,
        )

        assert len(findings.modules) == 3
        # 每模組剛好觸發一次 callback
        assert sorted(called_modules) == ["M1", "M3", "M7"]

    def test_on_module_done_callback_optional(self):
        """on_module_done=None（預設）時不應拋例外。"""
        assets = self._make_assets()
        findings = run_analysis(assets, module_ids=["M1"], on_module_done=None)
        assert len(findings.modules) == 1

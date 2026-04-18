import os
import json
import tempfile
from cypulse.automation.diff import DiffEngine, save_diff


def _write_scan(tmpdir, scan_name, total, findings_data):
    scan_dir = os.path.join(tmpdir, scan_name)
    os.makedirs(scan_dir, exist_ok=True)
    with open(os.path.join(scan_dir, "score.json"), "w") as f:
        json.dump({"total": total}, f)
    with open(os.path.join(scan_dir, "findings.json"), "w") as f:
        json.dump({"modules": findings_data}, f)
    return scan_dir


class TestDiffEngine:
    def test_score_change(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            old = _write_scan(tmpdir, "old", 80, [])
            new = _write_scan(tmpdir, "new", 75, [])
            engine = DiffEngine()
            report = engine.compare(old, new)
            assert report.score_change == -5

    def test_new_findings(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            old = _write_scan(tmpdir, "old", 80, [
                {"module_id": "M1", "findings": [
                    {"severity": "medium", "title": "Old issue"}
                ]}
            ])
            new = _write_scan(tmpdir, "new", 75, [
                {"module_id": "M1", "findings": [
                    {"severity": "medium", "title": "Old issue"},
                    {"severity": "high", "title": "New CVE"}
                ]}
            ])
            engine = DiffEngine()
            report = engine.compare(old, new)
            assert len(report.new_findings) == 1
            assert report.new_findings[0].description == "New CVE"

    def test_alerts_on_big_drop(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            old = _write_scan(tmpdir, "old", 90, [])
            new = _write_scan(tmpdir, "new", 70, [])
            engine = DiffEngine()
            report = engine.compare(old, new)
            assert len(report.alerts) >= 1
            assert "dropped" in report.alerts[0].lower()

    def test_save_diff(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            old = _write_scan(tmpdir, "old", 80, [])
            new = _write_scan(tmpdir, "new", 80, [])
            engine = DiffEngine()
            report = engine.compare(old, new)
            save_diff(report, new)
            assert os.path.isfile(os.path.join(new, "diff.json"))

    def test_save_diff_atomic_failure_preserves_original(self):
        """save_diff 應使用 atomic write：失敗時原檔保留、無 .tmp 殘留。"""
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as tmpdir:
            old = _write_scan(tmpdir, "old", 80, [])
            new = _write_scan(tmpdir, "new", 80, [])
            engine = DiffEngine()
            report = engine.compare(old, new)

            # 先寫一個有效 diff.json 作為「原檔」
            save_diff(report, new)
            original = open(os.path.join(new, "diff.json")).read()

            # 改動 report 後再寫，但 mock os.replace 拋例外
            report.score_change = -99
            with patch("os.replace", side_effect=OSError("disk full")):
                import pytest
                with pytest.raises(OSError):
                    save_diff(report, new)

            # 原檔應未被破壞
            current = open(os.path.join(new, "diff.json")).read()
            assert current == original, "atomic write 失敗時原檔應保留"
            # 無 .tmp 殘留
            leftovers = [
                f for f in os.listdir(new)
                if f.endswith(".tmp") or f.startswith(".diff.json.")
            ]
            assert leftovers == [], f"tmp 檔殘留: {leftovers}"

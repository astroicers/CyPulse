import os
import tempfile
import yaml
from cypulse.automation.scheduler import load_targets, generate_crontab


class TestLoadTargets:
    def test_load_valid(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump({"targets": [
                {"domain": "example.com", "enabled": True, "schedule": "0 2 * * 0"},
                {"domain": "disabled.com", "enabled": False},
            ]}, f)
            path = f.name
        try:
            targets = load_targets(path)
            assert len(targets) == 1
            assert targets[0]["domain"] == "example.com"
        finally:
            os.unlink(path)

    def test_missing_file(self):
        assert load_targets("/nonexistent/path.yaml") == []


class TestGenerateCrontab:
    def test_generate(self):
        targets = [{"domain": "example.com", "schedule": "0 2 * * 0"}]
        crontab = generate_crontab(targets)
        assert "example.com" in crontab
        assert "0 2 * * 0" in crontab

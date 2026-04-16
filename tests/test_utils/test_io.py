from __future__ import annotations
import json
import threading
from unittest.mock import patch

import pytest

from cypulse.utils.io import safe_write_json, safe_write_text


class TestSafeWriteJson:

    def test_writes_json_file(self, tmp_path):
        path = tmp_path / "out.json"
        safe_write_json(str(path), {"hello": "世界", "n": 42})
        loaded = json.loads(path.read_text(encoding="utf-8"))
        assert loaded == {"hello": "世界", "n": 42}

    def test_creates_missing_parent_dir(self, tmp_path):
        path = tmp_path / "new_dir" / "nested" / "out.json"
        safe_write_json(str(path), {"a": 1})
        assert path.exists()
        assert json.loads(path.read_text()) == {"a": 1}

    def test_no_tmp_file_left_after_success(self, tmp_path):
        path = tmp_path / "out.json"
        safe_write_json(str(path), {"a": 1})
        leftovers = [p.name for p in tmp_path.iterdir() if p.name != "out.json"]
        assert leftovers == []

    def test_failure_preserves_original_file(self, tmp_path):
        path = tmp_path / "out.json"
        safe_write_json(str(path), {"v": "original"})
        with patch("os.replace", side_effect=OSError("disk full")):
            with pytest.raises(OSError):
                safe_write_json(str(path), {"v": "new"})
        assert json.loads(path.read_text()) == {"v": "original"}
        leftovers = [p.name for p in tmp_path.iterdir() if p.name != "out.json"]
        assert leftovers == []

    def test_serialization_error_cleans_tmp(self, tmp_path):
        path = tmp_path / "out.json"

        class Unserializable:
            pass

        with pytest.raises(TypeError):
            safe_write_json(str(path), {"bad": Unserializable()})
        assert not path.exists()
        assert list(tmp_path.iterdir()) == []

    def test_concurrent_writes_no_corruption(self, tmp_path):
        path = tmp_path / "race.json"
        errors: list[Exception] = []

        def worker(n):
            try:
                payload = {"worker": n, "data": list(range(100))}
                safe_write_json(str(path), payload)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == []
        loaded = json.loads(path.read_text(encoding="utf-8"))
        assert "worker" in loaded and isinstance(loaded["worker"], int)
        assert loaded["data"] == list(range(100))
        leftovers = [p.name for p in tmp_path.iterdir() if p.name != "race.json"]
        assert leftovers == []


class TestSafeWriteText:

    def test_writes_text_file(self, tmp_path):
        path = tmp_path / "report.html"
        html = "<html><body>繁體中文</body></html>"
        safe_write_text(str(path), html)
        assert path.read_text(encoding="utf-8") == html

    def test_failure_preserves_original(self, tmp_path):
        path = tmp_path / "report.html"
        safe_write_text(str(path), "<old/>")
        with patch("os.replace", side_effect=OSError("boom")):
            with pytest.raises(OSError):
                safe_write_text(str(path), "<new/>")
        assert path.read_text() == "<old/>"
        leftovers = [p.name for p in tmp_path.iterdir() if p.name != "report.html"]
        assert leftovers == []

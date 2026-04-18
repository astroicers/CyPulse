"""ScanContext 測試（Task O+P）。

涵蓋 lifecycle 管理：abort flag、temp 檔註冊、cleanup。
不直接測 SIGALRM/SIGINT 真的 fire（依賴 OS 信號機制，測試環境難穩定複現），
改測 ScanContext.abort() 的副作用與 cleanup 邏輯。
"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

from cypulse.utils.scan_lifecycle import ScanContext, ScanAborted


class TestScanContext:

    def test_initial_state_not_aborted(self):
        ctx = ScanContext()
        assert ctx.aborted is False

    def test_abort_sets_flag(self):
        ctx = ScanContext()
        ctx.abort(reason="user_interrupt")
        assert ctx.aborted is True
        assert ctx.abort_reason == "user_interrupt"

    def test_check_aborted_raises_when_flag_set(self):
        ctx = ScanContext()
        ctx.abort(reason="timeout")
        with pytest.raises(ScanAborted) as exc_info:
            ctx.check_aborted()
        assert "timeout" in str(exc_info.value)

    def test_check_aborted_silent_when_not_set(self):
        ctx = ScanContext()
        ctx.check_aborted()  # 不應拋例外

    def test_register_temp_file(self):
        ctx = ScanContext()
        with tempfile.NamedTemporaryFile(delete=False) as f:
            tmp_path = f.name
        ctx.register_temp_file(tmp_path)
        assert tmp_path in ctx._temp_files
        # 清理
        os.unlink(tmp_path)

    def test_cleanup_removes_registered_temp_files(self):
        ctx = ScanContext()
        paths = []
        for _ in range(3):
            with tempfile.NamedTemporaryFile(delete=False) as f:
                paths.append(f.name)
                ctx.register_temp_file(f.name)
        for p in paths:
            assert Path(p).exists()
        ctx.cleanup_temp_files()
        for p in paths:
            assert not Path(p).exists(), f"{p} 應被清理"

    def test_cleanup_tolerates_already_deleted_file(self):
        """若 temp 檔已被外部清掉，cleanup 不應拋例外。"""
        ctx = ScanContext()
        with tempfile.NamedTemporaryFile(delete=False) as f:
            path = f.name
        ctx.register_temp_file(path)
        os.unlink(path)  # 提前刪
        ctx.cleanup_temp_files()  # 不應 raise

    def test_deadline_property(self):
        ctx = ScanContext(timeout_seconds=10)
        assert ctx.timeout_seconds == 10
        # deadline = start + timeout
        assert ctx.deadline > ctx.start_time
        assert (ctx.deadline - ctx.start_time) == 10

    def test_no_timeout_when_zero(self):
        ctx = ScanContext(timeout_seconds=0)
        assert ctx.timeout_seconds == 0
        assert ctx.deadline is None

    def test_remaining_seconds(self):
        ctx = ScanContext(timeout_seconds=100)
        # 剛建立應 ≈ 100，誤差 < 1s
        assert 99 <= ctx.remaining_seconds() <= 100

    def test_remaining_seconds_no_timeout(self):
        ctx = ScanContext(timeout_seconds=0)
        assert ctx.remaining_seconds() is None

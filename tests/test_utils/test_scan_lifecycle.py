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


class TestActiveScanContext:
    """Task P：以 module-level 全域引用支援 SIGINT handler 跨層存取。

    SIGINT handler 由 cli.py 註冊在 process 層，但要能 cleanup 由
    web_security/cloud_exposure 註冊到 ScanContext 的 temp 檔，
    需有「目前活躍的 ScanContext」可被存取。
    """

    def test_set_active_scan_context(self):
        from cypulse.utils.scan_lifecycle import (
            set_active_scan_context, get_active_scan_context,
        )
        ctx = ScanContext()
        set_active_scan_context(ctx)
        assert get_active_scan_context() is ctx

    def test_clear_active_scan_context(self):
        from cypulse.utils.scan_lifecycle import (
            set_active_scan_context, get_active_scan_context,
        )
        set_active_scan_context(ScanContext())
        set_active_scan_context(None)
        assert get_active_scan_context() is None

    def test_get_active_returns_none_when_unset(self):
        from cypulse.utils.scan_lifecycle import (
            set_active_scan_context, get_active_scan_context,
        )
        set_active_scan_context(None)  # reset
        assert get_active_scan_context() is None


class TestSigintHandler:
    """Task P：模擬 SIGINT 觸發時的副作用驗證。

    不真的 raise SIGINT（測試環境會殺 pytest），改直接呼叫 handler 函式。
    """

    def test_sigint_handler_aborts_and_cleans(self):
        """install_sigint_handler 安裝後，呼叫 handler 應 abort + cleanup。"""
        from cypulse.utils.scan_lifecycle import install_sigint_handler
        ctx = ScanContext()
        with tempfile.NamedTemporaryFile(delete=False) as f:
            tmp_path = f.name
        ctx.register_temp_file(tmp_path)

        handler = install_sigint_handler(ctx)
        # 模擬 SIGINT 觸發
        handler(2, None)  # signum=SIGINT, frame=None

        assert ctx.aborted is True
        assert "user_interrupt" in (ctx.abort_reason or "")
        assert not os.path.exists(tmp_path), "SIGINT 後 temp 檔應被清理"

    def test_double_sigint_force_exit(self):
        """連按兩次 Ctrl-C 應觸發 force exit（避免 cleanup 卡住）。"""
        from cypulse.utils.scan_lifecycle import install_sigint_handler
        ctx = ScanContext()
        handler = install_sigint_handler(ctx)
        handler(2, None)  # 第一次：cleanup
        # 第二次：直接 raise KeyboardInterrupt 強制退出
        with pytest.raises(KeyboardInterrupt):
            handler(2, None)

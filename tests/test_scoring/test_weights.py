from cypulse.scoring.weights import WEIGHTS, get_grade


def test_weights_sum_to_one():
    total = sum(v["weight"] for v in WEIGHTS.values())
    assert abs(total - 1.0) < 1e-9


def test_weights_max_score_sum():
    total = sum(v["max_score"] for v in WEIGHTS.values())
    assert total == 100


def test_weights_keys():
    # 驗證格式（Mn 數字序列）而非硬寫清單，加 M9 時自動相容
    assert all(k.startswith("M") and k[1:].isdigit() for k in WEIGHTS)
    # 且必須從 M1 開始連續編號
    numbers = sorted(int(k[1:]) for k in WEIGHTS)
    assert numbers == list(range(1, len(WEIGHTS) + 1))


def test_m1_source_defs_sum_to_one():
    """M1 _SOURCE_DEFS 權重總和必須 = 1.0，避免 typo 造成信心分數計算失真。"""
    from cypulse.analysis.web_security import _SOURCE_DEFS
    total = sum(w for _role, w in _SOURCE_DEFS.values())
    assert abs(total - 1.0) < 1e-9, f"M1 _SOURCE_DEFS 權重總和 {total} ≠ 1.0"


def test_m2_source_defs_sum_to_one():
    from cypulse.analysis.ip_reputation import _SOURCE_DEFS
    total = sum(w for _role, w in _SOURCE_DEFS.values())
    assert abs(total - 1.0) < 1e-9, f"M2 _SOURCE_DEFS 權重總和 {total} ≠ 1.0"


def test_m6_source_defs_sum_to_one():
    from cypulse.analysis.darkweb import _SOURCE_DEFS
    total = sum(w for _role, w in _SOURCE_DEFS.values())
    assert abs(total - 1.0) < 1e-9, f"M6 _SOURCE_DEFS 權重總和 {total} ≠ 1.0"


def test_get_grade_a():
    assert get_grade(95) == "A"
    assert get_grade(90) == "A"
    assert get_grade(100) == "A"


def test_get_grade_b():
    assert get_grade(85) == "B"
    assert get_grade(75) == "B"
    assert get_grade(89) == "B"


def test_get_grade_c():
    assert get_grade(60) == "C"
    assert get_grade(67) == "C"
    assert get_grade(74) == "C"


def test_get_grade_d():
    assert get_grade(0) == "D"
    assert get_grade(30) == "D"
    assert get_grade(59) == "D"


def test_get_grade_boundary():
    assert get_grade(90) == "A"
    assert get_grade(89) == "B"
    assert get_grade(75) == "B"
    assert get_grade(74) == "C"
    assert get_grade(60) == "C"
    assert get_grade(59) == "D"
    assert get_grade(0) == "D"

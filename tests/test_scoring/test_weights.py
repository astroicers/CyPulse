import pytest
from cypulse.scoring.weights import WEIGHTS, GRADES, get_grade


def test_weights_sum_to_one():
    total = sum(v["weight"] for v in WEIGHTS.values())
    assert abs(total - 1.0) < 1e-9


def test_weights_max_score_sum():
    total = sum(v["max_score"] for v in WEIGHTS.values())
    assert total == 100


def test_weights_keys():
    assert set(WEIGHTS.keys()) == {"M1", "M2", "M3", "M4", "M5", "M6", "M7"}


def test_get_grade_a():
    assert get_grade(95) == "A"
    assert get_grade(90) == "A"
    assert get_grade(100) == "A"


def test_get_grade_b():
    assert get_grade(85) == "B"
    assert get_grade(80) == "B"
    assert get_grade(89) == "B"


def test_get_grade_c():
    assert get_grade(75) == "C"
    assert get_grade(70) == "C"
    assert get_grade(79) == "C"


def test_get_grade_d():
    assert get_grade(0) == "D"
    assert get_grade(50) == "D"
    assert get_grade(69) == "D"


def test_get_grade_boundary():
    assert get_grade(90) == "A"
    assert get_grade(89) == "B"
    assert get_grade(80) == "B"
    assert get_grade(79) == "C"
    assert get_grade(70) == "C"
    assert get_grade(69) == "D"

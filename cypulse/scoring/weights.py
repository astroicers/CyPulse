WEIGHTS = {
    "M1": {"name": "網站服務安全", "weight": 0.25, "max_score": 25},
    "M2": {"name": "IP 信譽", "weight": 0.15, "max_score": 15},
    "M3": {"name": "網路服務安全", "weight": 0.20, "max_score": 20},
    "M4": {"name": "DNS 安全", "weight": 0.15, "max_score": 15},
    "M5": {"name": "郵件安全", "weight": 0.10, "max_score": 10},
    "M6": {"name": "暗網憑證外洩", "weight": 0.10, "max_score": 10},
    "M7": {"name": "偽冒域名偵測", "weight": 0.05, "max_score": 5},
}

GRADES = {
    "A": (90, 100),
    "B": (75, 89),
    "C": (60, 74),
    "D": (0, 59),
}


def get_grade(total: int) -> str:
    for grade, (low, high) in GRADES.items():
        if low <= total <= high:
            return grade
    return "D"

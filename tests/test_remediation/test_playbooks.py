from __future__ import annotations

import pytest
from cypulse.remediation.playbooks import get_remediation, PLAYBOOKS


def test_get_remediation_known_finding():
    result = get_remediation("No SPF record")
    assert result is not None
    assert result["priority"] in ("P1", "P2", "P3")
    assert "steps" in result
    assert len(result["steps"]) > 0
    assert "timeline" in result
    assert "target_team" in result
    assert "success_criteria" in result


def test_get_remediation_unknown_finding():
    result = get_remediation("Unknown Issue XYZ")
    assert result is None


def test_all_playbooks_have_required_fields():
    for title, playbook in PLAYBOOKS.items():
        assert "priority" in playbook, f"{title} missing priority"
        assert "steps" in playbook, f"{title} missing steps"
        assert "success_criteria" in playbook, f"{title} missing success_criteria"
        assert "target_team" in playbook, f"{title} missing target_team"
        assert "timeline" in playbook, f"{title} missing timeline"


def test_all_playbooks_have_at_least_one_step():
    for title, playbook in PLAYBOOKS.items():
        assert len(playbook["steps"]) >= 1, f"{title} must have at least one step"


def test_playbook_steps_have_required_fields():
    for title, playbook in PLAYBOOKS.items():
        for i, step in enumerate(playbook["steps"]):
            assert "step" in step, f"{title} step {i} missing 'step'"
            assert "action" in step, f"{title} step {i} missing 'action'"


def test_get_remediation_no_dmarc():
    result = get_remediation("No DMARC record")
    assert result is not None
    assert result["priority"] == "P1"


def test_get_remediation_zone_transfer():
    result = get_remediation("Zone Transfer allowed")
    assert result is not None
    assert result["priority"] == "P1"


def test_total_playbook_count():
    assert len(PLAYBOOKS) == 9


def test_all_playbook_titles_match_findings():
    """確認修正後的 key 都能被找到。"""
    known_titles = [
        "Missing strict-transport-security",
        "Missing content-security-policy",
        "Missing x-frame-options",
        "Weak TLS Version",
        "No SPF record",
        "No DMARC record",
        "DMARC policy is none",
        "DNSSEC not enabled",
        "Zone Transfer allowed",
    ]
    for title in known_titles:
        assert get_remediation(title) is not None, f"Missing playbook: {title}"

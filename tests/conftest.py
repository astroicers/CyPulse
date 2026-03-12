import pytest
from cypulse.models import Asset, Assets, Finding, ModuleResult


@pytest.fixture
def sample_asset():
    return Asset(
        subdomain="www.example.com",
        ip="93.184.216.34",
        ports=[80, 443],
        http_status=200,
        http_title="Example Domain",
        tls_version="TLSv1.3",
        security_headers={"HSTS": True, "CSP": False},
    )


@pytest.fixture
def sample_assets(sample_asset):
    return Assets(
        domain="example.com",
        timestamp="2026-03-12T020000",
        subdomains=[sample_asset],
    )


@pytest.fixture
def sample_finding():
    return Finding(
        severity="high",
        title="Missing HSTS Header",
        description="HTTP Strict Transport Security header not set",
        evidence="https://www.example.com",
        score_impact=5,
    )


@pytest.fixture
def sample_module_result(sample_finding):
    return ModuleResult(
        module_id="M1",
        module_name="網站服務安全",
        score=20,
        max_score=25,
        findings=[sample_finding],
        raw_data={},
        execution_time=12.5,
        status="success",
    )

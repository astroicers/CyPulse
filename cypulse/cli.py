from __future__ import annotations
import os
import sys
import json
import click
import structlog
from cypulse import __version__
from cypulse.utils.logging import setup_logging
from cypulse.utils.sanitize import sanitize_domain

logger = structlog.get_logger()

DEFAULT_OUTPUT_DIR = os.environ.get("CYPULSE_OUTPUT_DIR", "./data")
DEFAULT_CONFIG = os.environ.get("CYPULSE_CONFIG", "config/config.yaml")


def _load_config(config_path: str) -> dict:
    if os.path.isfile(config_path):
        import yaml
        with open(config_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    return {}


@click.group()
@click.version_option(version=__version__, prog_name="cypulse")
@click.option("--log-level", default=None, help="Log level: DEBUG/INFO/WARNING/ERROR")
@click.option("--config", "config_path", default=DEFAULT_CONFIG, help="Config file path")
@click.pass_context
def cli(ctx, log_level: str | None, config_path: str):
    """CyPulse — 開源 EASM 資安曝險評級平台"""
    setup_logging(log_level)
    ctx.ensure_object(dict)
    ctx.obj["config"] = _load_config(config_path)
    ctx.obj["config_path"] = config_path


@cli.command()
@click.argument("domain")
@click.option("--modules", "-m", default=None, help="Comma-separated module list (M1-M7)")
@click.option("--output", "-o", default=None, help="Output directory")
@click.pass_context
def scan(ctx, domain: str, modules: str | None, output: str | None):
    """對目標 domain 執行完整掃描"""
    try:
        domain = sanitize_domain(domain)
    except ValueError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

    config = ctx.obj["config"]
    scan_config = config.get("scan", {})
    output_dir = output or DEFAULT_OUTPUT_DIR

    module_ids = None
    if modules:
        module_ids = [m.strip().upper() for m in modules.split(",")]

    click.echo(f"[CyPulse] 開始掃描 {domain}...")

    # Phase 1: Discovery
    click.echo("[CyPulse] Phase 1: 資產探勘...")
    from cypulse.discovery.pipeline import run_discovery, save_assets
    assets = run_discovery(domain, scan_config)
    scan_dir = save_assets(assets, output_dir)
    click.echo(f"[CyPulse]   子網域: {assets.total_subdomains}, 存活: {assets.total_live}, HTTP: {assets.total_http}")

    # Phase 2: Analysis
    click.echo("[CyPulse] Phase 2: 風險分析...")
    from cypulse.analysis.runner import run_analysis, save_findings
    findings = run_analysis(assets, module_ids)
    save_findings(findings, scan_dir)
    click.echo(f"[CyPulse]   完成 {len(findings.modules)} 個模組分析")

    # Phase 3: Scoring
    click.echo("[CyPulse] Phase 3: 評分...")
    from cypulse.scoring.engine import ScoringEngine, save_score
    engine = ScoringEngine()
    score = engine.calculate(findings)
    save_score(score, scan_dir)
    click.echo(f"[CyPulse]   總分: {score.total}/100 ({score.grade})")

    # Phase 4: Report
    click.echo("[CyPulse] Phase 4: 報告產出...")
    from cypulse.report.generator import ReportGenerator
    gen = ReportGenerator()
    html_path = gen.generate_html(score, findings, assets, scan_dir)
    click.echo(f"[CyPulse]   HTML: {html_path}")
    try:
        pdf_path = gen.generate_pdf(html_path, scan_dir)
        click.echo(f"[CyPulse]   PDF: {pdf_path}")
    except Exception as e:
        click.echo(f"[CyPulse]   PDF 產出失敗: {e}", err=True)
    csv_paths = gen.generate_csv(findings, assets, scan_dir)
    click.echo(f"[CyPulse]   CSV: {len(csv_paths)} files")

    # Phase 5: Diff (if previous scan exists)
    prev_dir = _find_previous_scan(output_dir, domain, scan_dir)
    if prev_dir:
        click.echo("[CyPulse] Phase 5: 差異比對...")
        from cypulse.automation.diff import DiffEngine, save_diff
        diff_engine = DiffEngine()
        diff_report = diff_engine.compare(prev_dir, scan_dir)
        save_diff(diff_report, scan_dir)
        if diff_report.score_change != 0:
            direction = "↑" if diff_report.score_change > 0 else "↓"
            click.echo(f"[CyPulse]   分數變化: {direction}{abs(diff_report.score_change)}")
        if diff_report.alerts:
            from cypulse.automation.notifier import send_alerts
            send_alerts(diff_report.alerts, config)
            for alert in diff_report.alerts:
                click.echo(f"[CyPulse]   ⚠️ {alert}")

    # Summary
    total_findings = sum(len(m.findings) for m in findings.modules)
    click.echo("")
    click.echo(f"[SCAN COMPLETE] domain={domain} score={score.total} grade={score.grade} "
               f"duration={score.scan_duration:.0f}s modules={len(findings.modules)}/7 "
               f"findings={total_findings}")
    click.echo(f"[CyPulse] 結果儲存於: {scan_dir}")


@cli.command()
@click.argument("scan_dir")
@click.option("--format", "-f", "fmt", default="html", type=click.Choice(["html", "pdf", "csv", "all"]))
def report(scan_dir: str, fmt: str):
    """以既有掃描結果產出報告"""
    if not os.path.isdir(scan_dir):
        click.echo(f"Error: {scan_dir} not found", err=True)
        sys.exit(1)

    # Load data
    from cypulse.models import Assets, Findings, Score
    import dataclasses

    def _load(path, cls=None):
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)

    assets_data = _load(os.path.join(scan_dir, "assets.json"))
    findings_data = _load(os.path.join(scan_dir, "findings.json"))
    score_data = _load(os.path.join(scan_dir, "score.json"))

    # Reconstruct objects from JSON
    from cypulse.models import Asset, ModuleResult, Finding, ScoreExplanation
    assets = Assets(
        domain=assets_data["domain"],
        timestamp=assets_data["timestamp"],
        subdomains=[Asset(**s) for s in assets_data["subdomains"]],
    )
    modules = []
    for m in findings_data["modules"]:
        modules.append(ModuleResult(
            module_id=m["module_id"],
            module_name=m["module_name"],
            score=m["score"],
            max_score=m["max_score"],
            findings=[Finding(**f) for f in m["findings"]],
            raw_data=m.get("raw_data", {}),
            execution_time=m.get("execution_time", 0),
            status=m.get("status", "success"),
        ))
    findings = Findings(domain=findings_data["domain"], timestamp=findings_data["timestamp"], modules=modules)
    score = Score(
        total=score_data["total"],
        grade=score_data["grade"],
        dimensions=score_data.get("dimensions", {}),
        explanations=[ScoreExplanation(**e) for e in score_data.get("explanations", [])],
        scan_duration=score_data.get("scan_duration", 0),
    )

    from cypulse.report.generator import ReportGenerator
    gen = ReportGenerator()

    if fmt in ("html", "all"):
        path = gen.generate_html(score, findings, assets, scan_dir)
        click.echo(f"HTML report: {path}")
    if fmt in ("pdf", "all"):
        html_path = os.path.join(scan_dir, "report.html")
        if not os.path.isfile(html_path):
            html_path = gen.generate_html(score, findings, assets, scan_dir)
        path = gen.generate_pdf(html_path, scan_dir)
        click.echo(f"PDF report: {path}")
    if fmt in ("csv", "all"):
        paths = gen.generate_csv(findings, assets, scan_dir)
        for p in paths:
            click.echo(f"CSV: {p}")


@cli.command()
@click.argument("dir1")
@click.argument("dir2")
def diff(dir1: str, dir2: str):
    """比較兩次掃描結果差異"""
    from cypulse.automation.diff import DiffEngine
    engine = DiffEngine()
    report = engine.compare(dir1, dir2)
    click.echo(f"Score change: {report.score_change:+d}")
    click.echo(f"New findings: {len(report.new_findings)}")
    click.echo(f"Resolved: {len(report.resolved_findings)}")
    if report.alerts:
        click.echo("Alerts:")
        for alert in report.alerts:
            click.echo(f"  ⚠️ {alert}")


def _find_previous_scan(output_dir: str, domain: str, current_dir: str) -> str | None:
    domain_dir = os.path.join(output_dir, domain)
    if not os.path.isdir(domain_dir):
        return None
    scans = sorted([
        d for d in os.listdir(domain_dir)
        if os.path.isdir(os.path.join(domain_dir, d))
        and os.path.join(domain_dir, d) != current_dir
    ])
    if scans:
        prev = os.path.join(domain_dir, scans[-1])
        if os.path.isfile(os.path.join(prev, "score.json")):
            return prev
    return None


def main():
    cli()


if __name__ == "__main__":
    main()

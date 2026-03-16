from __future__ import annotations
import csv
import os
import structlog
from jinja2 import Environment, FileSystemLoader, select_autoescape
from cypulse.models import Score, Findings, Assets
from cypulse.scoring.weights import WEIGHTS
from cypulse.remediation.playbooks import get_remediation

logger = structlog.get_logger()

TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "templates")


class ReportGenerator:

    def __init__(self):
        self.env = Environment(
            loader=FileSystemLoader(TEMPLATE_DIR),
            autoescape=select_autoescape(["html"]),
        )

    def generate_html(self, score: Score, findings: Findings,
                      assets: Assets, output_dir: str) -> str:
        os.makedirs(output_dir, exist_ok=True)
        template = self.env.get_template("report.html")

        # 建立 finding title → remediation 的查找表
        remediation_map: dict[str, dict] = {}
        for module in findings.modules:
            for finding in module.findings:
                r = get_remediation(finding.title)
                if r is not None:
                    remediation_map[finding.title] = r

        html = template.render(
            domain=assets.domain,
            timestamp=assets.timestamp,
            score=score,
            findings=findings,
            assets=assets,
            weights=WEIGHTS,
            remediation_map=remediation_map,
        )

        path = os.path.join(output_dir, "report.html")
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)

        logger.info("html_report_generated", path=path)
        return path

    def generate_pdf(self, html_path: str, output_dir: str) -> str:
        os.makedirs(output_dir, exist_ok=True)
        pdf_path = os.path.join(output_dir, "report.pdf")

        try:
            from weasyprint import HTML
            HTML(filename=html_path).write_pdf(pdf_path)
            logger.info("pdf_report_generated", path=pdf_path)
        except Exception as e:
            logger.error("pdf_generation_failed", error=str(e))
            raise

        return pdf_path

    def generate_csv(self, findings: Findings,
                     assets: Assets, output_dir: str) -> list[str]:
        os.makedirs(output_dir, exist_ok=True)
        paths = []

        # Assets CSV
        assets_path = os.path.join(output_dir, "assets.csv")
        with open(assets_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["subdomain", "ip", "ports", "http_status", "http_title", "tls_version"])
            for asset in assets.subdomains:
                writer.writerow([
                    asset.subdomain,
                    asset.ip or "",
                    ";".join(str(p) for p in asset.ports),
                    asset.http_status or "",
                    asset.http_title or "",
                    asset.tls_version or "",
                ])
        paths.append(assets_path)

        # Findings CSV
        findings_path = os.path.join(output_dir, "findings.csv")
        with open(findings_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["module_id", "module_name", "severity", "title", "description", "evidence", "score_impact"])
            for module in findings.modules:
                for finding in module.findings:
                    writer.writerow([
                        module.module_id,
                        module.module_name,
                        finding.severity,
                        finding.title,
                        finding.description,
                        finding.evidence or "",
                        finding.score_impact,
                    ])
        paths.append(findings_path)

        logger.info("csv_reports_generated", paths=paths)
        return paths

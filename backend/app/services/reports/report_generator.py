"""Report Generator - Phase 4.

Generates forensic reports in JSON, HTML, and PDF formats.
Reports contain all analysis data with full evidence traceability.

IMPORTANT: Report generation is independent of core forensics.
If PDF generation fails, JSON and HTML remain available.
"""
import hashlib
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from app.services.reports.models import (
    ReportFormat,
    ReportStatus,
    ReportMetadata,
    EvidenceSection,
    SecurityPostureSection,
    FindingSection,
    RecommendationSection,
    CorrelationSection,
    MLSection,
    IntegritySection,
    FullReport,
    GeneratedReportInfo,
)
from app.services.intelligence.models import (
    IntelligenceResult,
    AggregatedFinding,
    CorrelationData,
    RecommendationData,
    SecurityPosture,
)
from app.services.ml.models import MLInsights

logger = logging.getLogger(__name__)


class ReportGenerator:
    """
    Generates forensic reports in multiple formats.

    Supported formats:
    - JSON: Machine-readable, preserves all data
    - HTML: Human-readable, styled presentation
    - PDF: Printable format (requires external library)
    """

    # HTML template for report
    HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
        :root {{
            --primary: #1a365d;
            --secondary: #2d3748;
            --accent: #3182ce;
            --danger: #e53e3e;
            --warning: #dd6b20;
            --success: #38a169;
            --info: #3182ce;
            --bg: #f7fafc;
            --card-bg: #ffffff;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg);
            color: var(--secondary);
            line-height: 1.6;
            margin: 0;
            padding: 20px;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        .header {{
            background: var(--primary);
            color: white;
            padding: 30px;
            border-radius: 8px;
            margin-bottom: 30px;
        }}
        .header h1 {{
            margin: 0 0 10px 0;
            font-size: 2em;
        }}
        .header .subtitle {{
            opacity: 0.9;
            font-size: 1.1em;
        }}
        .card {{
            background: var(--card-bg);
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            padding: 25px;
            margin-bottom: 25px;
        }}
        .card h2 {{
            color: var(--primary);
            margin-top: 0;
            padding-bottom: 15px;
            border-bottom: 2px solid #e2e8f0;
        }}
        .posture-grade {{
            display: inline-flex;
            align-items: center;
            justify-content: center;
            width: 80px;
            height: 80px;
            border-radius: 50%;
            font-size: 2.5em;
            font-weight: bold;
            color: white;
        }}
        .grade-A {{ background: var(--success); }}
        .grade-B {{ background: #68d391; }}
        .grade-C {{ background: var(--warning); }}
        .grade-D {{ background: #ed8936; }}
        .grade-F {{ background: var(--danger); }}
        .severity-critical {{ color: var(--danger); font-weight: bold; }}
        .severity-high {{ color: #c53030; }}
        .severity-medium {{ color: var(--warning); }}
        .severity-low {{ color: #718096; }}
        .severity-info {{ color: var(--info); }}
        .finding {{
            border-left: 4px solid #e2e8f0;
            padding: 15px;
            margin: 15px 0;
            background: #f8fafc;
        }}
        .finding-critical {{ border-color: var(--danger); }}
        .finding-high {{ border-color: #c53030; }}
        .finding-medium {{ border-color: var(--warning); }}
        .finding-low {{ border-color: #718096; }}
        .finding h3 {{
            margin: 0 0 10px 0;
        }}
        .badge {{
            display: inline-block;
            padding: 3px 10px;
            border-radius: 12px;
            font-size: 0.85em;
            font-weight: 500;
        }}
        .badge-critical {{ background: #fed7d7; color: var(--danger); }}
        .badge-high {{ background: #fee2e2; color: #c53030; }}
        .badge-medium {{ background: #feebc8; color: var(--warning); }}
        .badge-low {{ background: #e2e8f0; color: #4a5568; }}
        .dimension {{
            display: flex;
            align-items: center;
            margin: 10px 0;
        }}
        .dimension-label {{
            width: 200px;
            font-weight: 500;
        }}
        .dimension-bar {{
            flex: 1;
            height: 24px;
            background: #e2e8f0;
            border-radius: 12px;
            overflow: hidden;
        }}
        .dimension-fill {{
            height: 100%;
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: flex-end;
            padding-right: 10px;
            color: white;
            font-weight: 500;
            font-size: 0.9em;
        }}
        .recommendation {{
            padding: 15px;
            margin: 15px 0;
            background: #edf2f7;
            border-radius: 8px;
        }}
        .recommendation h3 {{
            margin: 0 0 10px 0;
            color: var(--primary);
        }}
        .steps {{
            padding-left: 20px;
        }}
        .steps li {{
            margin: 5px 0;
        }}
        .integrity-hash {{
            font-family: monospace;
            background: #edf2f7;
            padding: 8px 12px;
            border-radius: 4px;
            font-size: 0.9em;
            word-break: break-all;
        }}
        .meta-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
        }}
        .meta-item {{
            background: #f8fafc;
            padding: 12px;
            border-radius: 6px;
        }}
        .meta-item label {{
            display: block;
            font-size: 0.85em;
            color: #718096;
            margin-bottom: 5px;
        }}
        .meta-item value {{
            display: block;
            font-weight: 500;
        }}
        footer {{
            text-align: center;
            padding: 30px;
            color: #718096;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <div class="container">
        {content}
    </div>
    <footer>
        Generated by SecureMailScope v{version} | {timestamp}
    </footer>
</body>
</html>"""

    def __init__(self, output_dir: Optional[Path] = None):
        """
        Initialize the report generator.

        Args:
            output_dir: Directory for report output files
        """
        self.output_dir = output_dir or Path("./reports")
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_report(
        self,
        intelligence_result: IntelligenceResult,
        evidence_info: dict,
        ml_insights: Optional[MLInsights] = None,
        format: ReportFormat = ReportFormat.JSON,
    ) -> GeneratedReportInfo:
        """
        Generate a report in the specified format.

        Args:
            intelligence_result: Phase 4 intelligence result
            evidence_info: Evidence metadata
            ml_insights: ML insights (optional)
            format: Output format

        Returns:
            Generated report information
        """
        try:
            # Build full report structure
            full_report = self._build_full_report(
                intelligence_result,
                evidence_info,
                ml_insights,
            )

            # Generate based on format
            if format == ReportFormat.JSON:
                return self._generate_json(full_report)
            elif format == ReportFormat.HTML:
                return self._generate_html(full_report)
            elif format == ReportFormat.PDF:
                return self._generate_pdf(full_report)
            else:
                raise ValueError(f"Unsupported format: {format}")

        except Exception as e:
            logger.error(f"Report generation failed: {e}")
            return GeneratedReportInfo(
                report_id=f"rep_error_{datetime.now().strftime('%Y%m%d%H%M%S')}",
                format=format,
                status=ReportStatus.FAILED,
                error_message=str(e),
            )

    def _build_full_report(
        self,
        result: IntelligenceResult,
        evidence_info: dict,
        ml_insights: Optional[MLInsights],
    ) -> FullReport:
        """Build the complete report structure."""
        # Metadata
        metadata = ReportMetadata(
            title=f"Security Analysis Report - {evidence_info.get('original_filename', 'Unknown')}",
            evidence_id=result.evidence_id,
            job_id=result.job_id,
            case_name=evidence_info.get('case_name'),
            format=ReportFormat.JSON,  # Will be updated
        )

        # Evidence section
        evidence = EvidenceSection(
            evidence_id=result.evidence_id,
            original_filename=evidence_info.get('original_filename', 'Unknown'),
            sha256=evidence_info.get('sha256', ''),
            file_size_bytes=evidence_info.get('file_size_bytes', 0),
            upload_timestamp=evidence_info.get('upload_timestamp'),
            packets_analyzed=evidence_info.get('packets_analyzed', 0),
            streams_analyzed=result.streams_analyzed,
            sessions_analyzed=result.sessions_analyzed,
            certificates_analyzed=result.certificates_analyzed,
        )

        # Security posture section
        posture = result.summary.security_posture
        security_posture = SecurityPostureSection(
            overall_score=posture.overall_score,
            grade=posture.grade.value,
            tls_security_score=posture.tls_security.score,
            certificate_security_score=posture.certificate_security.score,
            protocol_security_score=posture.protocol_security.score,
            configuration_security_score=posture.configuration_security.score,
            risk_factors=posture.risk_factors,
            strengths=posture.strengths,
        )

        # Findings by severity
        critical = []
        high = []
        medium = []
        low = []
        info = []

        for agg in result.aggregated_findings:
            section = FindingSection(
                finding_id=agg.finding_id,
                rule_id=agg.rule_id,
                title=agg.title,
                description=agg.description,
                category=agg.category,
                severity=agg.severity,
                confidence=agg.confidence,
                occurrence_count=agg.occurrence_count,
                affected_sessions=len(agg.affected_sessions),
                affected_certificates=len(agg.affected_certificates),
                remediation=agg.remediation,
            )

            if agg.severity == "CRITICAL":
                critical.append(section)
            elif agg.severity == "HIGH":
                high.append(section)
            elif agg.severity == "MEDIUM":
                medium.append(section)
            elif agg.severity == "LOW":
                low.append(section)
            else:
                info.append(section)

        # Recommendations
        recommendations = [
            RecommendationSection(
                recommendation_id=r.recommendation_id,
                priority=r.priority.value,
                category=r.category.value,
                title=r.title,
                description=r.description,
                remediation_steps=r.remediation_steps,
                estimated_effort=r.estimated_effort,
                compliance_references=r.compliance_references,
            )
            for r in result.recommendations
        ]

        # Correlations
        correlations = [
            CorrelationSection(
                correlation_id=c.correlation_id,
                correlation_type=c.correlation_type.value,
                strength=c.strength,
                title=c.title,
                description=c.description,
                linked_findings=len(c.linked_findings),
                linked_sessions=len(c.linked_sessions),
            )
            for c in result.correlations
        ]

        # ML section
        ml_section = None
        if ml_insights and ml_insights.ml_enabled:
            ml_section = MLSection(
                ml_enabled=True,
                model_version=ml_insights.model_version,
                anomalies_detected=ml_insights.anomalies_detected,
                top_anomalies=[
                    a.explanation for a in ml_insights.top_anomalies[:3]
                ],
                confidence=ml_insights.overall_confidence,
                summary=ml_insights.summary,
            )

        # Integrity section
        integrity = IntegritySection(
            evidence_sha256=evidence_info.get('sha256', ''),
            evidence_sha512=evidence_info.get('sha512'),
            analysis_hash=self._compute_analysis_hash(result),
        )

        # Limitations
        limitations = []
        if result.streams_analyzed == 0:
            limitations.append("No TCP streams were reconstructed from the evidence.")
        if result.sessions_analyzed == 0:
            limitations.append("No email sessions were detected in the evidence.")
        if not ml_section or not ml_section.ml_enabled:
            limitations.append("ML-based anomaly detection was not performed.")

        return FullReport(
            metadata=metadata,
            executive_summary=result.summary.executive_summary,
            evidence=evidence,
            security_posture=security_posture,
            critical_findings=critical,
            high_findings=high,
            medium_findings=medium,
            low_findings=low,
            info_findings=info,
            recommendations=recommendations,
            correlations=correlations,
            ml_insights=ml_section,
            integrity=integrity,
            limitations=limitations,
        )

    def _generate_json(self, report: FullReport) -> GeneratedReportInfo:
        """Generate JSON report."""
        report.metadata.format = ReportFormat.JSON

        content = report.model_dump_json(indent=2)
        content_hash = hashlib.sha256(content.encode()).hexdigest()

        filename = f"{report.metadata.report_id}.json"
        filepath = self.output_dir / filename

        with open(filepath, 'w') as f:
            f.write(content)

        return GeneratedReportInfo(
            report_id=report.metadata.report_id,
            format=ReportFormat.JSON,
            status=ReportStatus.COMPLETED,
            filename=filename,
            file_size_bytes=len(content.encode()),
            content_hash=content_hash,
            generated_at=datetime.now(timezone.utc),
        )

    def _generate_html(self, report: FullReport) -> GeneratedReportInfo:
        """Generate HTML report."""
        report.metadata.format = ReportFormat.HTML

        # Build HTML content
        content_parts = []

        # Header
        content_parts.append(f"""
        <div class="header">
            <h1>Security Analysis Report</h1>
            <div class="subtitle">{report.metadata.title}</div>
        </div>
        """)

        # Executive Summary
        content_parts.append(f"""
        <div class="card">
            <h2>Executive Summary</h2>
            <pre style="white-space: pre-wrap;">{report.executive_summary}</pre>
        </div>
        """)

        # Security Posture
        grade_class = f"grade-{report.security_posture.grade}"
        content_parts.append(f"""
        <div class="card">
            <h2>Security Posture</h2>
            <div style="display: flex; align-items: center; gap: 30px; margin-bottom: 20px;">
                <div class="posture-grade {grade_class}">{report.security_posture.grade}</div>
                <div>
                    <div style="font-size: 1.5em; font-weight: bold;">
                        Score: {report.security_posture.overall_score:.0f}/100
                    </div>
                </div>
            </div>
            {self._render_dimensions(report.security_posture)}
        </div>
        """)

        # Findings
        content_parts.append(self._render_findings_section(report))

        # Recommendations
        if report.recommendations:
            content_parts.append(self._render_recommendations(report.recommendations))

        # Evidence Integrity
        content_parts.append(f"""
        <div class="card">
            <h2>Evidence Integrity</h2>
            <p><strong>SHA-256:</strong></p>
            <div class="integrity-hash">{report.integrity.evidence_sha256}</div>
            {f'<p style="margin-top: 15px;"><strong>Analysis Hash:</strong></p><div class="integrity-hash">{report.integrity.analysis_hash}</div>' if report.integrity.analysis_hash else ''}
        </div>
        """)

        # Combine content
        html_content = self.HTML_TEMPLATE.format(
            title=report.metadata.title,
            content="\n".join(content_parts),
            version=report.metadata.generator_version,
            timestamp=report.metadata.generated_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
        )

        content_hash = hashlib.sha256(html_content.encode()).hexdigest()
        filename = f"{report.metadata.report_id}.html"
        filepath = self.output_dir / filename

        with open(filepath, 'w') as f:
            f.write(html_content)

        return GeneratedReportInfo(
            report_id=report.metadata.report_id,
            format=ReportFormat.HTML,
            status=ReportStatus.COMPLETED,
            filename=filename,
            file_size_bytes=len(html_content.encode()),
            content_hash=content_hash,
            generated_at=datetime.now(timezone.utc),
        )

    def _generate_pdf(self, report: FullReport) -> GeneratedReportInfo:
        """Generate PDF report (optional, requires weasyprint)."""
        try:
            from weasyprint import HTML as WeasyHTML
        except ImportError:
            logger.warning("weasyprint not available, PDF generation skipped")
            return GeneratedReportInfo(
                report_id=report.metadata.report_id,
                format=ReportFormat.PDF,
                status=ReportStatus.FAILED,
                error_message="PDF generation requires weasyprint library",
            )

        # First generate HTML
        html_info = self._generate_html(report)

        try:
            html_path = self.output_dir / html_info.filename
            pdf_filename = f"{report.metadata.report_id}.pdf"
            pdf_path = self.output_dir / pdf_filename

            # Convert HTML to PDF
            WeasyHTML(filename=str(html_path)).write_pdf(str(pdf_path))

            with open(pdf_path, 'rb') as f:
                content_hash = hashlib.sha256(f.read()).hexdigest()

            return GeneratedReportInfo(
                report_id=report.metadata.report_id,
                format=ReportFormat.PDF,
                status=ReportStatus.COMPLETED,
                filename=pdf_filename,
                file_size_bytes=pdf_path.stat().st_size,
                content_hash=content_hash,
                generated_at=datetime.now(timezone.utc),
            )

        except Exception as e:
            logger.error(f"PDF generation failed: {e}")
            return GeneratedReportInfo(
                report_id=report.metadata.report_id,
                format=ReportFormat.PDF,
                status=ReportStatus.FAILED,
                error_message=str(e),
            )

    def _render_dimensions(self, posture: SecurityPostureSection) -> str:
        """Render dimension score bars."""
        dimensions = [
            ("TLS Security", posture.tls_security_score),
            ("Certificate Security", posture.certificate_security_score),
            ("Protocol Security", posture.protocol_security_score),
            ("Configuration Security", posture.configuration_security_score),
        ]

        html = []
        for name, score in dimensions:
            color = self._score_to_color(score)
            html.append(f"""
            <div class="dimension">
                <div class="dimension-label">{name}</div>
                <div class="dimension-bar">
                    <div class="dimension-fill" style="width: {score}%; background: {color};">
                        {score:.0f}
                    </div>
                </div>
            </div>
            """)
        return "\n".join(html)

    def _render_findings_section(self, report: FullReport) -> str:
        """Render findings section."""
        html = ['<div class="card"><h2>Security Findings</h2>']

        total = (
            len(report.critical_findings) +
            len(report.high_findings) +
            len(report.medium_findings) +
            len(report.low_findings) +
            len(report.info_findings)
        )

        if total == 0:
            html.append("<p>No security findings were identified.</p>")
        else:
            html.append(f"<p>Total: {total} findings</p>")

            for findings, severity, severity_class in [
                (report.critical_findings, "CRITICAL", "critical"),
                (report.high_findings, "HIGH", "high"),
                (report.medium_findings, "MEDIUM", "medium"),
                (report.low_findings, "LOW", "low"),
                (report.info_findings, "INFO", "info"),
            ]:
                if findings:
                    html.append(f"<h3 class='severity-{severity_class}'>{severity} ({len(findings)})</h3>")
                    for f in findings:
                        html.append(f"""
                        <div class="finding finding-{severity_class}">
                            <h3>{f.title}</h3>
                            <p>{f.description}</p>
                            <p><span class="badge badge-{severity_class}">{f.severity}</span>
                               <span style="margin-left: 10px;">Occurrences: {f.occurrence_count}</span></p>
                            {f'<p><strong>Remediation:</strong> {f.remediation}</p>' if f.remediation else ''}
                        </div>
                        """)

        html.append("</div>")
        return "\n".join(html)

    def _render_recommendations(self, recommendations: list[RecommendationSection]) -> str:
        """Render recommendations section."""
        html = ['<div class="card"><h2>Recommendations</h2>']

        for r in recommendations:
            html.append(f"""
            <div class="recommendation">
                <h3>{r.title}</h3>
                <p><span class="badge badge-{r.priority.lower()}">{r.priority}</span>
                   <span style="margin-left: 10px;">{r.category}</span></p>
                <p>{r.description}</p>
                {self._render_steps(r.remediation_steps)}
            </div>
            """)

        html.append("</div>")
        return "\n".join(html)

    def _render_steps(self, steps: list[str]) -> str:
        """Render remediation steps."""
        if not steps:
            return ""
        items = "\n".join(f"<li>{step}</li>" for step in steps)
        return f"<ul class='steps'>{items}</ul>"

    def _score_to_color(self, score: float) -> str:
        """Convert score to color."""
        if score >= 90:
            return "#38a169"
        elif score >= 80:
            return "#68d391"
        elif score >= 70:
            return "#dd6b20"
        elif score >= 60:
            return "#ed8936"
        else:
            return "#e53e3e"

    def _compute_analysis_hash(self, result: IntelligenceResult) -> str:
        """Compute hash of analysis results for integrity."""
        data = {
            "evidence_id": result.evidence_id,
            "job_id": result.job_id,
            "findings_count": len(result.aggregated_findings),
            "correlations_count": len(result.correlations),
            "recommendations_count": len(result.recommendations),
            "posture_score": result.summary.security_posture.overall_score,
        }
        content = json.dumps(data, sort_keys=True)
        return hashlib.sha256(content.encode()).hexdigest()

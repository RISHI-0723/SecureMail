"""Intelligence Aggregator - Phase 4.

Aggregates all Phase 3 findings into a unified intelligence view.
Computes security posture scores across multiple dimensions.

IMPORTANT: This service enhances Phase 3 findings but does NOT
modify or replace them. All deterministic findings remain intact.
"""
import logging
from typing import Optional
from datetime import datetime, timezone

from app.services.findings.models import SecurityFinding, FindingsResult
from app.services.risk.models import RiskAssessment, RiskLevel
from app.services.crypto.rules import Severity, RuleCategory
from app.services.intelligence.models import (
    AggregatedFinding,
    SecurityPosture,
    SecurityPostureGrade,
    DimensionScore,
    IntelligenceSummary,
)

logger = logging.getLogger(__name__)


class IntelligenceAggregator:
    """
    Aggregates Phase 3 findings into intelligence insights.

    Responsibilities:
    1. Aggregate findings by rule/type
    2. Calculate security posture scores
    3. Identify top risks
    4. Generate executive summary
    """

    # Dimension weights for overall score
    DIMENSION_WEIGHTS = {
        "tls_security": 0.30,
        "certificate_security": 0.30,
        "protocol_security": 0.25,
        "configuration_security": 0.15,
    }

    # Severity impact on dimension scores
    SEVERITY_PENALTIES = {
        Severity.CRITICAL: 30,
        Severity.HIGH: 20,
        Severity.MEDIUM: 10,
        Severity.LOW: 5,
        Severity.INFO: 0,
    }

    def __init__(self):
        """Initialize the intelligence aggregator."""
        self._aggregated_findings: list[AggregatedFinding] = []
        self._dimension_scores: dict[str, DimensionScore] = {}

    def aggregate_findings(
        self,
        findings_result: FindingsResult,
        risk_assessment: Optional[RiskAssessment] = None,
    ) -> tuple[list[AggregatedFinding], SecurityPosture, IntelligenceSummary]:
        """
        Aggregate findings and compute security posture.

        Args:
            findings_result: Phase 3 findings result
            risk_assessment: Phase 3 risk assessment (optional)

        Returns:
            Tuple of (aggregated_findings, security_posture, summary)
        """
        # Reset state
        self._aggregated_findings = []
        self._dimension_scores = {}

        # Aggregate findings by rule_id
        aggregated = self._aggregate_by_rule(findings_result.findings)

        # Calculate dimension scores
        dimension_scores = self._calculate_dimension_scores(
            findings_result.findings,
            risk_assessment
        )

        # Calculate overall posture
        posture = self._calculate_security_posture(dimension_scores, findings_result)

        # Generate summary
        summary = self._generate_summary(
            findings_result,
            posture,
            aggregated,
            risk_assessment
        )

        return aggregated, posture, summary

    def _aggregate_by_rule(
        self,
        findings: list[SecurityFinding]
    ) -> list[AggregatedFinding]:
        """Aggregate findings by rule_id."""
        aggregation_map: dict[str, AggregatedFinding] = {}

        for finding in findings:
            rule_id = finding.rule_id

            if rule_id in aggregation_map:
                # Update existing aggregation
                agg = aggregation_map[rule_id]
                agg.occurrence_count += finding.occurrence_count

                # Extend affected entities
                if finding.stream_id:
                    agg.affected_streams.append(finding.stream_id)
                if finding.session_id:
                    agg.affected_sessions.append(finding.session_id)
                if finding.certificate_id:
                    agg.affected_certificates.append(finding.certificate_id)

                # Track timing
                if agg.last_seen is None:
                    agg.last_seen = datetime.now(timezone.utc)
            else:
                # Create new aggregation
                agg = AggregatedFinding(
                    finding_id=finding.finding_id,
                    rule_id=rule_id,
                    title=finding.title,
                    description=finding.description,
                    category=finding.category.value if hasattr(finding.category, 'value') else str(finding.category),
                    severity=finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity),
                    occurrence_count=finding.occurrence_count,
                    affected_streams=finding.affected_streams.copy() if finding.affected_streams else [],
                    affected_sessions=[finding.session_id] if finding.session_id else [],
                    affected_certificates=[finding.certificate_id] if finding.certificate_id else [],
                    first_seen=datetime.now(timezone.utc),
                    remediation=finding.remediation,
                    confidence=finding.confidence,
                )
                aggregation_map[rule_id] = agg

        # Deduplicate lists
        for agg in aggregation_map.values():
            agg.affected_streams = list(set(agg.affected_streams))
            agg.affected_sessions = list(set(agg.affected_sessions))
            agg.affected_certificates = list(set(agg.affected_certificates))

        self._aggregated_findings = list(aggregation_map.values())
        return self._aggregated_findings

    def _calculate_dimension_scores(
        self,
        findings: list[SecurityFinding],
        risk_assessment: Optional[RiskAssessment]
    ) -> dict[str, DimensionScore]:
        """Calculate security scores for each dimension."""
        # Initialize dimension trackers
        dimensions = {
            "tls_security": {"score": 100.0, "findings": 0, "critical": 0},
            "certificate_security": {"score": 100.0, "findings": 0, "critical": 0},
            "protocol_security": {"score": 100.0, "findings": 0, "critical": 0},
            "configuration_security": {"score": 100.0, "findings": 0, "critical": 0},
        }

        # Map categories to dimensions
        category_to_dimension = {
            RuleCategory.TLS_VERSION: "tls_security",
            RuleCategory.TLS_CIPHER: "tls_security",
            RuleCategory.KEY_EXCHANGE: "tls_security",
            RuleCategory.FORWARD_SECRECY: "tls_security",
            RuleCategory.CERTIFICATE_VALIDITY: "certificate_security",
            RuleCategory.CERTIFICATE_KEY: "certificate_security",
            RuleCategory.CERTIFICATE_SIGNATURE: "certificate_security",
            RuleCategory.CERTIFICATE_CHAIN: "certificate_security",
            RuleCategory.PROTOCOL_SECURITY: "protocol_security",
            RuleCategory.STARTTLS_SECURITY: "protocol_security",
            RuleCategory.HANDSHAKE: "tls_security",
            RuleCategory.STREAM_INTEGRITY: "configuration_security",
        }

        # Apply penalties based on findings
        for finding in findings:
            category = finding.category
            dimension = category_to_dimension.get(category, "configuration_security")

            severity = finding.severity
            penalty = self.SEVERITY_PENALTIES.get(severity, 0)

            # Apply penalty with diminishing returns
            current = dimensions[dimension]
            current["score"] = max(0, current["score"] - penalty)
            current["findings"] += 1

            if severity in [Severity.CRITICAL, Severity.HIGH]:
                current["critical"] += 1

        # Create DimensionScore objects
        scores = {}
        for dim_name, dim_data in dimensions.items():
            scores[dim_name] = DimensionScore(
                dimension=dim_name,
                score=dim_data["score"],
                weight=self.DIMENSION_WEIGHTS.get(dim_name, 0.25),
                findings_count=dim_data["findings"],
                critical_issues=dim_data["critical"],
            )

        self._dimension_scores = scores
        return scores

    def _calculate_security_posture(
        self,
        dimension_scores: dict[str, DimensionScore],
        findings_result: FindingsResult
    ) -> SecurityPosture:
        """Calculate overall security posture from dimension scores."""
        # Calculate weighted average
        total_weight = sum(d.weight for d in dimension_scores.values())
        if total_weight == 0:
            total_weight = 1.0

        weighted_score = sum(
            d.score * d.weight for d in dimension_scores.values()
        ) / total_weight

        # Determine grade
        grade = self._score_to_grade(weighted_score)

        # Identify risk factors and strengths
        risk_factors = []
        strengths = []

        for dim_name, dim_score in dimension_scores.items():
            if dim_score.score < 70:
                risk_factors.append(f"{dim_name.replace('_', ' ').title()}: Score {dim_score.score:.0f}/100")
            elif dim_score.score >= 90:
                strengths.append(f"{dim_name.replace('_', ' ').title()}: Score {dim_score.score:.0f}/100")

        # Add finding-based risk factors
        if findings_result.summary.critical_count > 0:
            risk_factors.append(
                f"{findings_result.summary.critical_count} critical security findings"
            )
        if findings_result.summary.high_count > 0:
            risk_factors.append(
                f"{findings_result.summary.high_count} high severity findings"
            )

        return SecurityPosture(
            overall_score=weighted_score,
            grade=grade,
            tls_security=dimension_scores["tls_security"],
            certificate_security=dimension_scores["certificate_security"],
            protocol_security=dimension_scores["protocol_security"],
            configuration_security=dimension_scores["configuration_security"],
            risk_factors=risk_factors,
            strengths=strengths if strengths else ["No significant vulnerabilities detected"],
            confidence="HIGH" if findings_result.summary.total_findings > 0 else "LOW",
        )

    def _score_to_grade(self, score: float) -> SecurityPostureGrade:
        """Convert numeric score to letter grade."""
        if score >= 90:
            return SecurityPostureGrade.A
        elif score >= 80:
            return SecurityPostureGrade.B
        elif score >= 70:
            return SecurityPostureGrade.C
        elif score >= 60:
            return SecurityPostureGrade.D
        else:
            return SecurityPostureGrade.F

    def _generate_summary(
        self,
        findings_result: FindingsResult,
        posture: SecurityPosture,
        aggregated: list[AggregatedFinding],
        risk_assessment: Optional[RiskAssessment]
    ) -> IntelligenceSummary:
        """Generate executive summary and intelligence summary."""
        # Build executive summary text
        exec_summary = self._build_executive_summary(
            findings_result, posture, aggregated
        )

        # Build category breakdown
        category_counts: dict[str, int] = {}
        for agg in aggregated:
            cat = agg.category
            category_counts[cat] = category_counts.get(cat, 0) + agg.occurrence_count

        return IntelligenceSummary(
            evidence_id=findings_result.evidence_id,
            job_id=findings_result.job_id,
            security_posture=posture,
            total_findings=findings_result.summary.total_findings,
            total_correlations=0,  # Set by correlation engine
            total_recommendations=0,  # Set by recommendation engine
            critical_count=findings_result.summary.critical_count,
            high_count=findings_result.summary.high_count,
            medium_count=findings_result.summary.medium_count,
            low_count=findings_result.summary.low_count,
            info_count=findings_result.summary.info_count,
            findings_by_category=category_counts,
            executive_summary=exec_summary,
            ml_enabled=False,
            anomalies_detected=0,
        )

    def _build_executive_summary(
        self,
        findings_result: FindingsResult,
        posture: SecurityPosture,
        aggregated: list[AggregatedFinding]
    ) -> str:
        """Build executive summary text."""
        lines = []

        # Overall assessment
        lines.append(
            f"Security Posture: Grade {posture.grade.value} "
            f"(Score: {posture.overall_score:.0f}/100)"
        )

        # Finding summary
        total = findings_result.summary.total_findings
        if total == 0:
            lines.append("No security findings were identified in the analyzed evidence.")
        else:
            lines.append(f"Analysis identified {total} security finding(s):")
            if findings_result.summary.critical_count > 0:
                lines.append(f"  - {findings_result.summary.critical_count} CRITICAL")
            if findings_result.summary.high_count > 0:
                lines.append(f"  - {findings_result.summary.high_count} HIGH")
            if findings_result.summary.medium_count > 0:
                lines.append(f"  - {findings_result.summary.medium_count} MEDIUM")
            if findings_result.summary.low_count > 0:
                lines.append(f"  - {findings_result.summary.low_count} LOW")

        # Key risk factors
        if posture.risk_factors:
            lines.append("\nKey Risk Factors:")
            for rf in posture.risk_factors[:5]:  # Top 5
                lines.append(f"  - {rf}")

        # Coverage info
        lines.append(f"\nAnalysis Coverage:")
        lines.append(f"  - Streams analyzed: {findings_result.streams_analyzed}")
        lines.append(f"  - Sessions analyzed: {findings_result.sessions_analyzed}")
        lines.append(f"  - Certificates analyzed: {findings_result.certificates_analyzed}")

        return "\n".join(lines)

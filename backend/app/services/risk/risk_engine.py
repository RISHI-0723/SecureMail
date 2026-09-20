"""Risk assessment engine.

Phase 3: Deterministic risk calculation.

This engine calculates security posture based on:
1. Finding severity distribution
2. Security dimension analysis
3. Coverage and confidence

The algorithm is deterministic and explainable.
No ML is used - pure rule-based calculation.

SCORING FORMULA:
================
Overall Score = 100 - total_penalty

Where total_penalty = sum of:
- CRITICAL findings: 25 points each
- HIGH findings: 15 points each
- MEDIUM findings: 5 points each
- LOW findings: 1 point each
- INFO findings: 0 points

Score is clamped to [0, 100].

RISK LEVEL MAPPING:
==================
- CRITICAL: score < 25
- HIGH: score < 50
- MEDIUM: score < 75
- LOW: score < 90
- MINIMAL: score >= 90
"""

import logging
from typing import Optional

from app.services.crypto.policy import CryptoPolicy, get_default_policy
from app.services.crypto.rules import Severity, RuleCategory
from app.services.findings.models import (
    SecurityFinding,
    FindingsResult,
    FindingSummary,
)
from app.services.risk.models import (
    RiskLevel,
    SecurityDimension,
    DimensionScore,
    SecurityPosture,
    RiskAssessment,
)

logger = logging.getLogger(__name__)


# Severity penalty weights
SEVERITY_WEIGHTS = {
    Severity.CRITICAL: 25,
    Severity.HIGH: 15,
    Severity.MEDIUM: 5,
    Severity.LOW: 1,
    Severity.INFO: 0,
}

# Category to dimension mapping
CATEGORY_DIMENSION_MAP = {
    RuleCategory.TLS_VERSION: SecurityDimension.TLS_SECURITY,
    RuleCategory.TLS_CIPHER: SecurityDimension.TLS_SECURITY,
    RuleCategory.KEY_EXCHANGE: SecurityDimension.TLS_SECURITY,
    RuleCategory.FORWARD_SECRECY: SecurityDimension.TLS_SECURITY,
    RuleCategory.HANDSHAKE: SecurityDimension.TLS_SECURITY,
    RuleCategory.CERTIFICATE_VALIDITY: SecurityDimension.CERTIFICATE_SECURITY,
    RuleCategory.CERTIFICATE_KEY: SecurityDimension.CERTIFICATE_SECURITY,
    RuleCategory.CERTIFICATE_SIGNATURE: SecurityDimension.CERTIFICATE_SECURITY,
    RuleCategory.CERTIFICATE_CHAIN: SecurityDimension.CERTIFICATE_SECURITY,
    RuleCategory.PROTOCOL_SECURITY: SecurityDimension.PROTOCOL_SECURITY,
    RuleCategory.STARTTLS_SECURITY: SecurityDimension.PROTOCOL_SECURITY,
    RuleCategory.STREAM_INTEGRITY: SecurityDimension.CONFIGURATION_SECURITY,
}


class RiskEngine:
    """
    Deterministic risk assessment engine.

    Calculates security posture from findings.
    All calculations are explainable and reproducible.
    """

    ASSESSMENT_VERSION = "1.0.0"

    def __init__(self, policy: Optional[CryptoPolicy] = None):
        """
        Initialize risk engine.

        Args:
            policy: Crypto policy for reference. Defaults to default policy.
        """
        self.policy = policy or get_default_policy()

    def assess_risk(
        self,
        findings_result: FindingsResult,
        total_streams: int = 0,
        total_sessions: int = 0,
        total_certificates: int = 0,
        confidence: str = "HIGH",
        coverage: str = "COMPLETE"
    ) -> RiskAssessment:
        """
        Calculate risk assessment from findings.

        Args:
            findings_result: Findings result from FindingEngine
            total_streams: Number of TCP streams analyzed
            total_sessions: Number of email sessions analyzed
            total_certificates: Number of certificates analyzed
            confidence: Overall analysis confidence
            coverage: Overall analysis coverage

        Returns:
            Complete risk assessment
        """
        findings = findings_result.findings
        summary = findings_result.summary

        # Calculate overall score
        overall_score, score_breakdown = self._calculate_overall_score(summary)

        # Calculate dimension scores
        dimensions = self._calculate_dimension_scores(findings)

        # Determine overall risk level
        overall_risk = self._score_to_risk_level(overall_score)

        # Generate summary and recommendations
        posture_summary = self._generate_summary(
            overall_score, overall_risk, summary, dimensions
        )
        key_findings = self._extract_key_findings(findings)
        recommendations = self._generate_recommendations(findings, dimensions)

        # Adjust confidence based on coverage
        if coverage != "COMPLETE":
            confidence = "MEDIUM" if confidence == "HIGH" else "LOW"

        posture = SecurityPosture(
            overall_score=overall_score,
            overall_risk=overall_risk,
            dimensions=dimensions,
            score_breakdown=score_breakdown,
            confidence=confidence,
            coverage=coverage,
            summary=posture_summary,
            key_findings=key_findings,
            recommendations=recommendations
        )

        return RiskAssessment(
            evidence_id=findings_result.evidence_id,
            job_id=findings_result.job_id,
            posture=posture,
            total_findings=summary.total_findings,
            total_streams=total_streams,
            total_sessions=total_sessions,
            total_certificates=total_certificates,
            assessment_version=self.ASSESSMENT_VERSION,
            policy_version=self.policy.version
        )

    def _calculate_overall_score(
        self,
        summary: FindingSummary
    ) -> tuple[float, dict]:
        """
        Calculate overall security score.

        Returns:
            Tuple of (score, breakdown_dict)
        """
        critical_penalty = summary.critical_count * SEVERITY_WEIGHTS[Severity.CRITICAL]
        high_penalty = summary.high_count * SEVERITY_WEIGHTS[Severity.HIGH]
        medium_penalty = summary.medium_count * SEVERITY_WEIGHTS[Severity.MEDIUM]
        low_penalty = summary.low_count * SEVERITY_WEIGHTS[Severity.LOW]
        info_penalty = summary.info_count * SEVERITY_WEIGHTS[Severity.INFO]

        total_penalty = critical_penalty + high_penalty + medium_penalty + low_penalty + info_penalty
        score = max(0.0, 100.0 - total_penalty)

        breakdown = {
            "base_score": 100,
            "penalties": {
                "critical": {"count": summary.critical_count, "weight": SEVERITY_WEIGHTS[Severity.CRITICAL], "total": critical_penalty},
                "high": {"count": summary.high_count, "weight": SEVERITY_WEIGHTS[Severity.HIGH], "total": high_penalty},
                "medium": {"count": summary.medium_count, "weight": SEVERITY_WEIGHTS[Severity.MEDIUM], "total": medium_penalty},
                "low": {"count": summary.low_count, "weight": SEVERITY_WEIGHTS[Severity.LOW], "total": low_penalty},
                "info": {"count": summary.info_count, "weight": SEVERITY_WEIGHTS[Severity.INFO], "total": info_penalty},
            },
            "total_penalty": total_penalty,
            "final_score": score
        }

        return score, breakdown

    def _calculate_dimension_scores(
        self,
        findings: list[SecurityFinding]
    ) -> list[DimensionScore]:
        """Calculate scores for each security dimension."""
        dimension_findings: dict[SecurityDimension, list[SecurityFinding]] = {
            dim: [] for dim in SecurityDimension
        }

        # Group findings by dimension
        for finding in findings:
            dim = CATEGORY_DIMENSION_MAP.get(
                finding.category,
                SecurityDimension.CONFIGURATION_SECURITY
            )
            dimension_findings[dim].append(finding)

        # Calculate score for each dimension
        scores = []
        for dim, dim_findings in dimension_findings.items():
            score = self._calculate_dimension_score(dim, dim_findings)
            scores.append(score)

        return scores

    def _calculate_dimension_score(
        self,
        dimension: SecurityDimension,
        findings: list[SecurityFinding]
    ) -> DimensionScore:
        """Calculate score for a single dimension."""
        critical = sum(1 for f in findings if f.severity == Severity.CRITICAL)
        high = sum(1 for f in findings if f.severity == Severity.HIGH)
        medium = sum(1 for f in findings if f.severity == Severity.MEDIUM)
        low = sum(1 for f in findings if f.severity == Severity.LOW)

        # Same formula as overall
        penalty = (
            critical * SEVERITY_WEIGHTS[Severity.CRITICAL] +
            high * SEVERITY_WEIGHTS[Severity.HIGH] +
            medium * SEVERITY_WEIGHTS[Severity.MEDIUM] +
            low * SEVERITY_WEIGHTS[Severity.LOW]
        )
        score = max(0.0, 100.0 - penalty)
        risk_level = self._score_to_risk_level(score)

        # Generate description
        if len(findings) == 0:
            description = f"No security issues found in {dimension.value.replace('_', ' ').lower()}"
        else:
            description = f"{len(findings)} finding(s) affecting {dimension.value.replace('_', ' ').lower()}"

        return DimensionScore(
            dimension=dimension,
            score=score,
            risk_level=risk_level,
            findings_count=len(findings),
            critical_count=critical,
            high_count=high,
            medium_count=medium,
            low_count=low,
            description=description
        )

    def _score_to_risk_level(self, score: float) -> RiskLevel:
        """Convert numeric score to risk level."""
        if score < 25:
            return RiskLevel.CRITICAL
        elif score < 50:
            return RiskLevel.HIGH
        elif score < 75:
            return RiskLevel.MEDIUM
        elif score < 90:
            return RiskLevel.LOW
        else:
            return RiskLevel.MINIMAL

    def _generate_summary(
        self,
        score: float,
        risk: RiskLevel,
        summary: FindingSummary,
        dimensions: list[DimensionScore]
    ) -> str:
        """Generate human-readable posture summary."""
        if summary.total_findings == 0:
            return "No security findings detected. Security posture is strong."

        summaries = {
            RiskLevel.CRITICAL: "Critical security issues require immediate attention.",
            RiskLevel.HIGH: "Significant security weaknesses detected that should be addressed promptly.",
            RiskLevel.MEDIUM: "Moderate security concerns identified that warrant review.",
            RiskLevel.LOW: "Minor security issues found. Overall security posture is acceptable.",
            RiskLevel.MINIMAL: "Few or no significant security issues. Security posture is strong.",
        }

        base = summaries.get(risk, "Security assessment complete.")

        # Add dimension context
        worst_dim = min(dimensions, key=lambda d: d.score)
        if worst_dim.findings_count > 0:
            dim_name = worst_dim.dimension.value.replace("_", " ").lower()
            base += f" {dim_name.capitalize()} is the primary concern."

        return base

    def _extract_key_findings(
        self,
        findings: list[SecurityFinding]
    ) -> list[str]:
        """Extract key findings for summary."""
        key = []

        # Prioritize by severity
        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        high = [f for f in findings if f.severity == Severity.HIGH]

        for f in critical[:3]:
            key.append(f"CRITICAL: {f.title}")

        for f in high[:2]:
            key.append(f"HIGH: {f.title}")

        return key[:5]  # Limit to 5 key findings

    def _generate_recommendations(
        self,
        findings: list[SecurityFinding],
        dimensions: list[DimensionScore]
    ) -> list[str]:
        """Generate priority recommendations."""
        recommendations = []

        # Get unique recommendations from findings
        seen_rules = set()
        for finding in sorted(findings, key=lambda f: (
            0 if f.severity == Severity.CRITICAL else
            1 if f.severity == Severity.HIGH else
            2 if f.severity == Severity.MEDIUM else 3
        )):
            if finding.rule_id not in seen_rules and finding.remediation:
                recommendations.append(finding.remediation)
                seen_rules.add(finding.rule_id)

            if len(recommendations) >= 5:
                break

        return recommendations

    def assess_empty(
        self,
        evidence_id: str,
        job_id: str,
        reason: str = "No data to analyze"
    ) -> RiskAssessment:
        """
        Create assessment for case with no findings.

        Args:
            evidence_id: Evidence identifier
            job_id: Job identifier
            reason: Reason for empty assessment

        Returns:
            Risk assessment with UNKNOWN status
        """
        posture = SecurityPosture(
            overall_score=100.0,
            overall_risk=RiskLevel.UNKNOWN,
            dimensions=[],
            score_breakdown={"reason": reason},
            confidence="LOW",
            coverage="UNKNOWN",
            summary=reason,
            key_findings=[],
            recommendations=[]
        )

        return RiskAssessment(
            evidence_id=evidence_id,
            job_id=job_id,
            posture=posture,
            total_findings=0,
            total_streams=0,
            total_sessions=0,
            total_certificates=0,
            assessment_version=self.ASSESSMENT_VERSION,
            policy_version=self.policy.version
        )

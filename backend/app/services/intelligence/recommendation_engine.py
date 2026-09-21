"""Recommendation Engine - Phase 4.

Generates actionable security recommendations based on findings,
correlations, and security posture analysis.

IMPORTANT: Recommendations enhance but do not replace the
deterministic remediation guidance from Phase 3 findings.
"""
import logging
from typing import Optional
from collections import defaultdict

from app.services.findings.models import SecurityFinding
from app.services.crypto.rules import Severity, RuleCategory
from app.services.intelligence.models import (
    RecommendationData,
    RecommendationPriority,
    RecommendationCategory,
    CorrelationData,
    CorrelationType,
    SecurityPosture,
    AggregatedFinding,
)

logger = logging.getLogger(__name__)


# Mapping from finding categories/rules to recommendation categories
CATEGORY_MAPPING = {
    RuleCategory.TLS_VERSION: RecommendationCategory.TLS_UPGRADE,
    RuleCategory.TLS_CIPHER: RecommendationCategory.CIPHER_UPGRADE,
    RuleCategory.CERTIFICATE_VALIDITY: RecommendationCategory.CERTIFICATE_RENEWAL,
    RuleCategory.CERTIFICATE_KEY: RecommendationCategory.KEY_ROTATION,
    RuleCategory.CERTIFICATE_SIGNATURE: RecommendationCategory.CERTIFICATE_RENEWAL,
    RuleCategory.CERTIFICATE_CHAIN: RecommendationCategory.CERTIFICATE_RENEWAL,
    RuleCategory.KEY_EXCHANGE: RecommendationCategory.KEY_ROTATION,
    RuleCategory.FORWARD_SECRECY: RecommendationCategory.KEY_ROTATION,
    RuleCategory.PROTOCOL_SECURITY: RecommendationCategory.CONFIGURATION,
    RuleCategory.STARTTLS_SECURITY: RecommendationCategory.CONFIGURATION,
    RuleCategory.HANDSHAKE: RecommendationCategory.MONITORING,
    RuleCategory.STREAM_INTEGRITY: RecommendationCategory.MONITORING,
}

# Mapping from severity to priority
SEVERITY_TO_PRIORITY = {
    Severity.CRITICAL: RecommendationPriority.CRITICAL,
    Severity.HIGH: RecommendationPriority.HIGH,
    Severity.MEDIUM: RecommendationPriority.MEDIUM,
    Severity.LOW: RecommendationPriority.LOW,
    Severity.INFO: RecommendationPriority.INFO,
}


class RecommendationEngine:
    """
    Generates actionable security recommendations.

    Recommendation sources:
    1. Individual findings (deterministic)
    2. Aggregated findings (patterns)
    3. Correlations (systemic issues)
    4. Security posture (dimension weaknesses)
    """

    def __init__(self):
        """Initialize the recommendation engine."""
        self._recommendations: list[RecommendationData] = []

    def generate_recommendations(
        self,
        aggregated_findings: list[AggregatedFinding],
        correlations: list[CorrelationData],
        posture: SecurityPosture,
        original_findings: Optional[list[SecurityFinding]] = None,
    ) -> list[RecommendationData]:
        """
        Generate all recommendations.

        Args:
            aggregated_findings: Aggregated Phase 3 findings
            correlations: Identified correlations
            posture: Security posture analysis
            original_findings: Original Phase 3 findings (optional)

        Returns:
            List of recommendations
        """
        self._recommendations = []

        # Generate from findings
        self._generate_finding_recommendations(aggregated_findings)

        # Generate from correlations
        self._generate_correlation_recommendations(correlations)

        # Generate from posture weaknesses
        self._generate_posture_recommendations(posture)

        # Deduplicate and prioritize
        self._deduplicate_recommendations()

        # Sort by priority
        self._sort_by_priority()

        logger.info(f"Generated {len(self._recommendations)} recommendations")
        return self._recommendations

    def _generate_finding_recommendations(
        self,
        aggregated_findings: list[AggregatedFinding]
    ) -> None:
        """Generate recommendations from aggregated findings."""
        for agg in aggregated_findings:
            category = self._map_finding_category(agg.category)
            priority = self._map_severity_priority(agg.severity)

            rec = RecommendationData(
                priority=priority,
                category=category,
                title=self._generate_rec_title(agg),
                description=self._generate_rec_description(agg),
                remediation_steps=self._generate_remediation_steps(agg),
                estimated_effort=self._estimate_effort(priority),
                technical_impact=self._get_technical_impact(category),
                business_impact=self._get_business_impact(priority),
                affected_findings=[agg.finding_id],
                affected_sessions=agg.affected_sessions,
                affected_certificates=agg.affected_certificates,
                compliance_references=self._get_compliance_refs(category),
            )
            self._recommendations.append(rec)

    def _generate_correlation_recommendations(
        self,
        correlations: list[CorrelationData]
    ) -> None:
        """Generate recommendations from correlations."""
        for corr in correlations:
            category = self._correlation_to_category(corr.correlation_type)
            priority = self._correlation_to_priority(corr)

            rec = RecommendationData(
                priority=priority,
                category=category,
                title=f"Address systemic issue: {corr.title}",
                description=(
                    f"{corr.description}\n\n"
                    f"This affects {len(corr.linked_streams)} streams and "
                    f"is linked to {len(corr.linked_findings)} findings."
                ),
                remediation_steps=self._correlation_remediation_steps(corr),
                estimated_effort=self._estimate_effort(priority),
                technical_impact=f"Resolving this issue will address {len(corr.linked_findings)} related findings.",
                business_impact=self._get_business_impact(priority),
                affected_findings=corr.linked_findings,
                affected_sessions=corr.linked_sessions,
                affected_certificates=corr.linked_certificates,
                compliance_references=self._get_compliance_refs(category),
            )
            self._recommendations.append(rec)

    def _generate_posture_recommendations(
        self,
        posture: SecurityPosture
    ) -> None:
        """Generate recommendations from security posture weaknesses."""
        # Check each dimension
        dimensions = [
            ("tls_security", posture.tls_security, RecommendationCategory.TLS_UPGRADE),
            ("certificate_security", posture.certificate_security, RecommendationCategory.CERTIFICATE_RENEWAL),
            ("protocol_security", posture.protocol_security, RecommendationCategory.CONFIGURATION),
            ("configuration_security", posture.configuration_security, RecommendationCategory.CONFIGURATION),
        ]

        for dim_name, dim_score, category in dimensions:
            if dim_score.score < 70:  # Weak dimension
                priority = self._score_to_priority(dim_score.score)

                rec = RecommendationData(
                    priority=priority,
                    category=category,
                    title=f"Improve {dim_name.replace('_', ' ').title()}",
                    description=(
                        f"The {dim_name.replace('_', ' ')} dimension scored "
                        f"{dim_score.score:.0f}/100, indicating significant room "
                        f"for improvement. {dim_score.critical_issues} critical issues "
                        f"were identified in this area."
                    ),
                    remediation_steps=self._dimension_remediation_steps(dim_name),
                    estimated_effort="High" if dim_score.score < 50 else "Medium",
                    technical_impact=f"Improving this dimension will enhance overall security posture.",
                    business_impact="Reduced risk of security incidents and compliance violations.",
                    compliance_references=self._get_compliance_refs(category),
                )
                self._recommendations.append(rec)

    def _map_finding_category(self, category_str: str) -> RecommendationCategory:
        """Map finding category string to recommendation category."""
        try:
            category = RuleCategory(category_str)
            return CATEGORY_MAPPING.get(category, RecommendationCategory.CONFIGURATION)
        except (ValueError, KeyError):
            return RecommendationCategory.CONFIGURATION

    def _map_severity_priority(self, severity_str: str) -> RecommendationPriority:
        """Map severity string to recommendation priority."""
        try:
            severity = Severity(severity_str)
            return SEVERITY_TO_PRIORITY.get(severity, RecommendationPriority.MEDIUM)
        except (ValueError, KeyError):
            return RecommendationPriority.MEDIUM

    def _correlation_to_category(
        self,
        corr_type: CorrelationType
    ) -> RecommendationCategory:
        """Map correlation type to recommendation category."""
        mapping = {
            CorrelationType.SAME_CERTIFICATE: RecommendationCategory.CERTIFICATE_RENEWAL,
            CorrelationType.SAME_CIPHER_WEAKNESS: RecommendationCategory.CIPHER_UPGRADE,
            CorrelationType.SAME_TLS_VERSION: RecommendationCategory.TLS_UPGRADE,
            CorrelationType.SAME_KEY_EXCHANGE: RecommendationCategory.KEY_ROTATION,
            CorrelationType.SAME_SERVER: RecommendationCategory.CONFIGURATION,
            CorrelationType.TEMPORAL_PATTERN: RecommendationCategory.MONITORING,
            CorrelationType.RISK_ESCALATION: RecommendationCategory.MONITORING,
        }
        return mapping.get(corr_type, RecommendationCategory.CONFIGURATION)

    def _correlation_to_priority(
        self,
        corr: CorrelationData
    ) -> RecommendationPriority:
        """Determine priority from correlation."""
        if corr.combined_severity:
            return self._map_severity_priority(corr.combined_severity)
        if corr.strength >= 0.8:
            return RecommendationPriority.HIGH
        if corr.strength >= 0.5:
            return RecommendationPriority.MEDIUM
        return RecommendationPriority.LOW

    def _score_to_priority(self, score: float) -> RecommendationPriority:
        """Map dimension score to priority."""
        if score < 40:
            return RecommendationPriority.CRITICAL
        if score < 60:
            return RecommendationPriority.HIGH
        if score < 70:
            return RecommendationPriority.MEDIUM
        return RecommendationPriority.LOW

    def _generate_rec_title(self, agg: AggregatedFinding) -> str:
        """Generate recommendation title from finding."""
        return f"Remediate: {agg.title}"

    def _generate_rec_description(self, agg: AggregatedFinding) -> str:
        """Generate recommendation description from finding."""
        desc = agg.description
        if agg.occurrence_count > 1:
            desc += f"\n\nThis issue was observed {agg.occurrence_count} times."
        if agg.affected_sessions:
            desc += f"\n\nAffects {len(agg.affected_sessions)} session(s)."
        return desc

    def _generate_remediation_steps(
        self,
        agg: AggregatedFinding
    ) -> list[str]:
        """Generate remediation steps from finding."""
        steps = []

        if agg.remediation:
            steps.append(agg.remediation)

        # Add generic steps based on category
        category = agg.category
        if "TLS" in category or "VERSION" in category:
            steps.extend([
                "Upgrade TLS configuration to use TLS 1.3 or TLS 1.2 minimum.",
                "Disable deprecated TLS versions (TLS 1.0, TLS 1.1, SSLv3).",
                "Update server configuration and test with SSL Labs or similar tools.",
            ])
        elif "CIPHER" in category:
            steps.extend([
                "Update cipher suite configuration to use modern, secure ciphers.",
                "Prioritize AEAD ciphers (GCM, ChaCha20-Poly1305).",
                "Remove support for CBC mode ciphers and RC4.",
            ])
        elif "CERTIFICATE" in category:
            steps.extend([
                "Review certificate validity and expiration dates.",
                "Ensure certificates are issued by trusted CAs.",
                "Implement certificate monitoring and automated renewal.",
            ])
        elif "KEY" in category:
            steps.extend([
                "Use ECDHE or DHE key exchange for forward secrecy.",
                "Ensure DH parameters are at least 2048 bits.",
                "Consider ECDHE with P-256 or P-384 curves.",
            ])

        return steps

    def _correlation_remediation_steps(
        self,
        corr: CorrelationData
    ) -> list[str]:
        """Generate remediation steps for correlation."""
        steps = []

        if corr.correlation_type == CorrelationType.SAME_CERTIFICATE:
            steps = [
                "Review certificate deployment across affected systems.",
                "Consider using unique certificates per service where appropriate.",
                "Implement certificate lifecycle management.",
            ]
        elif corr.correlation_type == CorrelationType.SAME_CIPHER_WEAKNESS:
            steps = [
                "Update cipher suite configuration across all affected servers.",
                "Create a standardized TLS configuration template.",
                "Deploy configuration management to ensure consistency.",
            ]
        elif corr.correlation_type == CorrelationType.SAME_TLS_VERSION:
            steps = [
                "Plan TLS upgrade project for all affected services.",
                "Test compatibility with clients before deployment.",
                "Implement monitoring for TLS version usage.",
            ]
        elif corr.correlation_type == CorrelationType.RISK_ESCALATION:
            steps = [
                "Prioritize remediation of high-severity findings.",
                "Implement defense-in-depth measures.",
                "Consider emergency patching if critical vulnerabilities exist.",
            ]
        else:
            steps = [
                "Review affected systems for common configuration issues.",
                "Implement centralized security configuration management.",
                "Conduct regular security assessments.",
            ]

        return steps

    def _dimension_remediation_steps(self, dim_name: str) -> list[str]:
        """Generate remediation steps for dimension weakness."""
        steps_map = {
            "tls_security": [
                "Upgrade all services to TLS 1.3 or TLS 1.2 minimum.",
                "Implement strong cipher suite configurations.",
                "Enable forward secrecy on all TLS connections.",
                "Conduct regular TLS configuration audits.",
            ],
            "certificate_security": [
                "Review all certificates for validity and proper configuration.",
                "Implement automated certificate management and renewal.",
                "Use certificates from trusted Certificate Authorities.",
                "Monitor certificate expiration dates proactively.",
            ],
            "protocol_security": [
                "Enable STARTTLS on all email services where not using implicit TLS.",
                "Configure proper protocol security options.",
                "Monitor for plaintext email communications.",
            ],
            "configuration_security": [
                "Review and harden server configurations.",
                "Implement configuration management and drift detection.",
                "Follow security hardening guides for email servers.",
            ],
        }
        return steps_map.get(dim_name, [
            "Review security configuration for the affected dimension.",
            "Implement security best practices.",
        ])

    def _estimate_effort(self, priority: RecommendationPriority) -> str:
        """Estimate effort based on priority."""
        effort_map = {
            RecommendationPriority.CRITICAL: "High",
            RecommendationPriority.HIGH: "High",
            RecommendationPriority.MEDIUM: "Medium",
            RecommendationPriority.LOW: "Low",
            RecommendationPriority.INFO: "Low",
        }
        return effort_map.get(priority, "Medium")

    def _get_technical_impact(self, category: RecommendationCategory) -> str:
        """Get technical impact description."""
        impact_map = {
            RecommendationCategory.TLS_UPGRADE: "Improved encryption strength and protection against protocol downgrade attacks.",
            RecommendationCategory.CIPHER_UPGRADE: "Enhanced cryptographic security and resistance to known cipher attacks.",
            RecommendationCategory.CERTIFICATE_RENEWAL: "Maintained trust chain integrity and proper identity verification.",
            RecommendationCategory.KEY_ROTATION: "Enhanced forward secrecy and reduced key compromise impact.",
            RecommendationCategory.CONFIGURATION: "Improved overall security posture and reduced attack surface.",
            RecommendationCategory.MONITORING: "Better visibility into security events and faster incident response.",
            RecommendationCategory.COMPLIANCE: "Alignment with industry security standards and regulations.",
        }
        return impact_map.get(category, "Improved security posture.")

    def _get_business_impact(self, priority: RecommendationPriority) -> str:
        """Get business impact description."""
        if priority == RecommendationPriority.CRITICAL:
            return "Urgent action required to prevent potential security breach or data compromise."
        if priority == RecommendationPriority.HIGH:
            return "Important for maintaining security posture and regulatory compliance."
        if priority == RecommendationPriority.MEDIUM:
            return "Recommended for continuous security improvement."
        return "Contributes to overall security best practices."

    def _get_compliance_refs(
        self,
        category: RecommendationCategory
    ) -> dict[str, list[str]]:
        """Get compliance framework references."""
        refs: dict[str, list[str]] = {}

        # NIST references
        nist = []
        if category in [RecommendationCategory.TLS_UPGRADE, RecommendationCategory.CIPHER_UPGRADE]:
            nist.extend(["SC-8", "SC-12", "SC-13"])
        if category == RecommendationCategory.CERTIFICATE_RENEWAL:
            nist.extend(["IA-5", "SC-17"])
        if nist:
            refs["NIST 800-53"] = nist

        # PCI-DSS references
        pci = []
        if category in [RecommendationCategory.TLS_UPGRADE, RecommendationCategory.CIPHER_UPGRADE]:
            pci.extend(["4.1", "2.2.3"])
        if pci:
            refs["PCI-DSS"] = pci

        return refs if refs else None

    def _deduplicate_recommendations(self) -> None:
        """Deduplicate recommendations by title/category."""
        seen = set()
        unique = []

        for rec in self._recommendations:
            key = (rec.category, rec.title)
            if key not in seen:
                seen.add(key)
                unique.append(rec)

        self._recommendations = unique

    def _sort_by_priority(self) -> None:
        """Sort recommendations by priority."""
        priority_order = [
            RecommendationPriority.CRITICAL,
            RecommendationPriority.HIGH,
            RecommendationPriority.MEDIUM,
            RecommendationPriority.LOW,
            RecommendationPriority.INFO,
        ]

        self._recommendations.sort(
            key=lambda r: priority_order.index(r.priority)
        )

    def get_recommendations(self) -> list[RecommendationData]:
        """Get all generated recommendations."""
        return self._recommendations

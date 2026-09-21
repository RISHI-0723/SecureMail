"""Phase 4: Intelligence Aggregation and Reporting

Create Phase 4 tables for:
- Intelligence reports (aggregated analysis)
- Correlations (cross-session/evidence patterns)
- Recommendations (actionable security recommendations)
- ML predictions (ML model results and anomaly detection)
- Generated reports (JSON/HTML/PDF outputs)
- Evidence integrity (hashing and optional blockchain anchoring)

Revision ID: 004_phase4
Revises: 003_phase3
Create Date: 2026-09-21

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = '004_phase4'
down_revision: Union[str, None] = '003_phase3'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create Phase 4 database changes."""

    # Create enums with IF NOT EXISTS pattern
    op.execute("""
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'intelligencestatus') THEN
                CREATE TYPE intelligencestatus AS ENUM (
                    'QUEUED', 'RUNNING', 'COMPLETED', 'FAILED', 'PARTIAL'
                );
            END IF;
        END
        $$;
    """)

    op.execute("""
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'reportformat') THEN
                CREATE TYPE reportformat AS ENUM ('JSON', 'HTML', 'PDF');
            END IF;
        END
        $$;
    """)

    op.execute("""
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'reportstatus') THEN
                CREATE TYPE reportstatus AS ENUM (
                    'QUEUED', 'GENERATING', 'COMPLETED', 'FAILED'
                );
            END IF;
        END
        $$;
    """)

    op.execute("""
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'integritystatus') THEN
                CREATE TYPE integritystatus AS ENUM (
                    'PENDING', 'VERIFIED', 'FAILED', 'ANCHORED'
                );
            END IF;
        END
        $$;
    """)

    op.execute("""
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'correlationtype') THEN
                CREATE TYPE correlationtype AS ENUM (
                    'SAME_CERTIFICATE', 'SAME_CIPHER_WEAKNESS', 'SAME_TLS_VERSION',
                    'SAME_KEY_EXCHANGE', 'SAME_SERVER', 'TEMPORAL_PATTERN', 'RISK_ESCALATION'
                );
            END IF;
        END
        $$;
    """)

    op.execute("""
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'recommendationpriority') THEN
                CREATE TYPE recommendationpriority AS ENUM (
                    'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'
                );
            END IF;
        END
        $$;
    """)

    op.execute("""
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'recommendationcategory') THEN
                CREATE TYPE recommendationcategory AS ENUM (
                    'TLS_UPGRADE', 'CIPHER_UPGRADE', 'CERTIFICATE_RENEWAL',
                    'KEY_ROTATION', 'CONFIGURATION', 'MONITORING', 'COMPLIANCE'
                );
            END IF;
        END
        $$;
    """)

    # Create intelligence_reports table
    op.create_table(
        'intelligence_reports',
        sa.Column('report_id', sa.String(50), primary_key=True),
        sa.Column('evidence_id', sa.String(50),
                  sa.ForeignKey('pcap_evidence.evidence_id', ondelete='CASCADE'),
                  nullable=False),
        sa.Column('security_analysis_id', sa.String(50),
                  sa.ForeignKey('security_analyses.analysis_id', ondelete='CASCADE'),
                  nullable=True),
        sa.Column('job_id', sa.String(50),
                  sa.ForeignKey('analysis_jobs.job_id', ondelete='CASCADE'),
                  nullable=False),

        # Status
        sa.Column('status', postgresql.ENUM('QUEUED', 'RUNNING', 'COMPLETED', 'FAILED', 'PARTIAL',
                                             name='intelligencestatus', create_type=False),
                  nullable=False, server_default='QUEUED'),

        # Timestamps
        sa.Column('created_at', sa.DateTime(timezone=True),
                  nullable=False, server_default=sa.func.now()),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('duration_seconds', sa.Float(), nullable=True),

        # Aggregated metrics
        sa.Column('total_correlations', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('total_recommendations', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('ml_predictions_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('anomalies_detected', sa.Integer(), nullable=False, server_default='0'),

        # Security posture
        sa.Column('security_posture_score', sa.Float(), nullable=True),
        sa.Column('security_posture_grade', sa.String(10), nullable=True),

        # Dimension scores
        sa.Column('tls_security_score', sa.Float(), nullable=True),
        sa.Column('certificate_security_score', sa.Float(), nullable=True),
        sa.Column('protocol_security_score', sa.Float(), nullable=True),
        sa.Column('configuration_security_score', sa.Float(), nullable=True),

        # ML
        sa.Column('ml_enabled', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('ml_model_version', sa.String(50), nullable=True),
        sa.Column('ml_confidence_score', sa.Float(), nullable=True),

        # Summary
        sa.Column('executive_summary', sa.Text(), nullable=True),

        # JSON fields
        sa.Column('aggregated_findings', sa.JSON(), nullable=False, server_default='[]'),
        sa.Column('correlation_summary', sa.JSON(), nullable=False, server_default='{}'),
        sa.Column('recommendation_summary', sa.JSON(), nullable=False, server_default='{}'),
        sa.Column('ml_insights', sa.JSON(), nullable=True),
        sa.Column('anomaly_summary', sa.JSON(), nullable=True),

        # Error handling
        sa.Column('error_code', sa.String(50), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
    )

    # Create correlations table
    op.create_table(
        'correlations',
        sa.Column('correlation_id', sa.String(50), primary_key=True),
        sa.Column('intelligence_report_id', sa.String(50),
                  sa.ForeignKey('intelligence_reports.report_id', ondelete='CASCADE'),
                  nullable=False),

        # Type and strength
        sa.Column('correlation_type', postgresql.ENUM(
            'SAME_CERTIFICATE', 'SAME_CIPHER_WEAKNESS', 'SAME_TLS_VERSION',
            'SAME_KEY_EXCHANGE', 'SAME_SERVER', 'TEMPORAL_PATTERN', 'RISK_ESCALATION',
            name='correlationtype', create_type=False),
            nullable=False),
        sa.Column('strength', sa.Float(), nullable=False, server_default='1.0'),
        sa.Column('confidence', sa.String(20), nullable=False, server_default='MEDIUM'),

        # Description
        sa.Column('title', sa.String(255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),

        # Linked entities
        sa.Column('linked_findings', sa.JSON(), nullable=False, server_default='[]'),
        sa.Column('linked_sessions', sa.JSON(), nullable=False, server_default='[]'),
        sa.Column('linked_certificates', sa.JSON(), nullable=False, server_default='[]'),
        sa.Column('linked_streams', sa.JSON(), nullable=False, server_default='[]'),

        # Common attribute
        sa.Column('common_attribute', sa.String(100), nullable=True),
        sa.Column('common_value', sa.Text(), nullable=True),

        # Impact
        sa.Column('combined_severity', sa.String(20), nullable=True),
        sa.Column('combined_risk_score', sa.Float(), nullable=True),

        # Timestamps
        sa.Column('created_at', sa.DateTime(timezone=True),
                  nullable=False, server_default=sa.func.now()),
    )

    # Create recommendations table
    op.create_table(
        'recommendations',
        sa.Column('recommendation_id', sa.String(50), primary_key=True),
        sa.Column('intelligence_report_id', sa.String(50),
                  sa.ForeignKey('intelligence_reports.report_id', ondelete='CASCADE'),
                  nullable=False),

        # Priority and category
        sa.Column('priority', postgresql.ENUM(
            'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO',
            name='recommendationpriority', create_type=False),
            nullable=False, server_default='MEDIUM'),
        sa.Column('category', postgresql.ENUM(
            'TLS_UPGRADE', 'CIPHER_UPGRADE', 'CERTIFICATE_RENEWAL',
            'KEY_ROTATION', 'CONFIGURATION', 'MONITORING', 'COMPLIANCE',
            name='recommendationcategory', create_type=False),
            nullable=False),

        # Description
        sa.Column('title', sa.String(255), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),

        # Remediation
        sa.Column('remediation_steps', sa.JSON(), nullable=False, server_default='[]'),
        sa.Column('estimated_effort', sa.String(50), nullable=True),
        sa.Column('technical_impact', sa.Text(), nullable=True),
        sa.Column('business_impact', sa.Text(), nullable=True),

        # Affected entities
        sa.Column('affected_findings', sa.JSON(), nullable=False, server_default='[]'),
        sa.Column('affected_sessions', sa.JSON(), nullable=False, server_default='[]'),
        sa.Column('affected_certificates', sa.JSON(), nullable=False, server_default='[]'),

        # Status tracking
        sa.Column('status', sa.String(20), nullable=False, server_default='OPEN'),
        sa.Column('assigned_to', sa.String(100), nullable=True),
        sa.Column('due_date', sa.DateTime(timezone=True), nullable=True),
        sa.Column('resolved_at', sa.DateTime(timezone=True), nullable=True),

        # Compliance
        sa.Column('compliance_references', sa.JSON(), nullable=True),

        # Timestamps
        sa.Column('created_at', sa.DateTime(timezone=True),
                  nullable=False, server_default=sa.func.now()),
    )

    # Create ml_predictions table
    op.create_table(
        'ml_predictions',
        sa.Column('prediction_id', sa.String(50), primary_key=True),
        sa.Column('intelligence_report_id', sa.String(50),
                  sa.ForeignKey('intelligence_reports.report_id', ondelete='CASCADE'),
                  nullable=False),

        # Model info
        sa.Column('model_name', sa.String(100), nullable=False),
        sa.Column('model_version', sa.String(50), nullable=False),
        sa.Column('model_type', sa.String(50), nullable=False),

        # Prediction
        sa.Column('prediction_type', sa.String(50), nullable=False),
        sa.Column('predicted_value', sa.String(50), nullable=True),
        sa.Column('predicted_score', sa.Float(), nullable=True),
        sa.Column('confidence', sa.Float(), nullable=True),

        # Anomaly detection
        sa.Column('is_anomaly', sa.Boolean(), nullable=True),
        sa.Column('anomaly_score', sa.Float(), nullable=True),

        # Features
        sa.Column('feature_vector', sa.JSON(), nullable=True),
        sa.Column('feature_importance', sa.JSON(), nullable=True),

        # Target
        sa.Column('target_type', sa.String(50), nullable=True),
        sa.Column('target_id', sa.String(50), nullable=True),

        # Timestamps
        sa.Column('created_at', sa.DateTime(timezone=True),
                  nullable=False, server_default=sa.func.now()),
    )

    # Create generated_reports table
    op.create_table(
        'generated_reports',
        sa.Column('report_id', sa.String(50), primary_key=True),
        sa.Column('intelligence_report_id', sa.String(50),
                  sa.ForeignKey('intelligence_reports.report_id', ondelete='CASCADE'),
                  nullable=False),
        sa.Column('evidence_id', sa.String(50),
                  sa.ForeignKey('pcap_evidence.evidence_id', ondelete='CASCADE'),
                  nullable=False),

        # Format and status
        sa.Column('format', postgresql.ENUM('JSON', 'HTML', 'PDF', name='reportformat', create_type=False),
                  nullable=False),
        sa.Column('status', postgresql.ENUM('QUEUED', 'GENERATING', 'COMPLETED', 'FAILED',
                                             name='reportstatus', create_type=False),
                  nullable=False, server_default='QUEUED'),

        # File info
        sa.Column('filename', sa.String(255), nullable=True),
        sa.Column('stored_path', sa.String(500), nullable=True),
        sa.Column('file_size_bytes', sa.Integer(), nullable=True),
        sa.Column('content_hash', sa.String(64), nullable=True),

        # Content
        sa.Column('report_content', sa.JSON(), nullable=True),
        sa.Column('html_content', sa.Text(), nullable=True),

        # Timestamps
        sa.Column('created_at', sa.DateTime(timezone=True),
                  nullable=False, server_default=sa.func.now()),
        sa.Column('generated_at', sa.DateTime(timezone=True), nullable=True),

        # Error handling
        sa.Column('error_code', sa.String(50), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
    )

    # Create evidence_integrity table
    op.create_table(
        'evidence_integrity',
        sa.Column('integrity_id', sa.String(50), primary_key=True),
        sa.Column('evidence_id', sa.String(50),
                  sa.ForeignKey('pcap_evidence.evidence_id', ondelete='CASCADE'),
                  nullable=False),
        sa.Column('intelligence_report_id', sa.String(50),
                  sa.ForeignKey('intelligence_reports.report_id', ondelete='CASCADE'),
                  nullable=True),

        # Status
        sa.Column('status', postgresql.ENUM('PENDING', 'VERIFIED', 'FAILED', 'ANCHORED',
                                             name='integritystatus', create_type=False),
                  nullable=False, server_default='PENDING'),

        # Hashes
        sa.Column('evidence_sha256', sa.String(64), nullable=False),
        sa.Column('evidence_sha512', sa.String(128), nullable=True),
        sa.Column('evidence_md5', sa.String(32), nullable=True),
        sa.Column('analysis_hash', sa.String(64), nullable=True),
        sa.Column('report_hash', sa.String(64), nullable=True),
        sa.Column('merkle_root', sa.String(64), nullable=True),

        # Blockchain
        sa.Column('blockchain_enabled', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('blockchain_network', sa.String(50), nullable=True),
        sa.Column('transaction_hash', sa.String(100), nullable=True),
        sa.Column('block_number', sa.Integer(), nullable=True),
        sa.Column('anchor_timestamp', sa.DateTime(timezone=True), nullable=True),

        # Metadata
        sa.Column('integrity_metadata', sa.JSON(), nullable=True),

        # Timestamps
        sa.Column('created_at', sa.DateTime(timezone=True),
                  nullable=False, server_default=sa.func.now()),
        sa.Column('verified_at', sa.DateTime(timezone=True), nullable=True),
    )

    # Create indexes for intelligence_reports
    op.create_index('ix_intelligence_reports_report_id',
                    'intelligence_reports', ['report_id'])
    op.create_index('ix_intelligence_reports_evidence_id',
                    'intelligence_reports', ['evidence_id'])
    op.create_index('ix_intelligence_reports_security_analysis_id',
                    'intelligence_reports', ['security_analysis_id'])
    op.create_index('ix_intelligence_reports_job_id',
                    'intelligence_reports', ['job_id'])
    op.create_index('ix_intelligence_reports_status',
                    'intelligence_reports', ['status'])
    op.create_index('ix_intelligence_evidence_status',
                    'intelligence_reports', ['evidence_id', 'status'])
    op.create_index('ix_intelligence_posture',
                    'intelligence_reports', ['security_posture_grade', 'security_posture_score'])

    # Create indexes for correlations
    op.create_index('ix_correlations_correlation_id',
                    'correlations', ['correlation_id'])
    op.create_index('ix_correlations_intelligence_report_id',
                    'correlations', ['intelligence_report_id'])
    op.create_index('ix_correlations_correlation_type',
                    'correlations', ['correlation_type'])
    op.create_index('ix_correlation_type_strength',
                    'correlations', ['correlation_type', 'strength'])

    # Create indexes for recommendations
    op.create_index('ix_recommendations_recommendation_id',
                    'recommendations', ['recommendation_id'])
    op.create_index('ix_recommendations_intelligence_report_id',
                    'recommendations', ['intelligence_report_id'])
    op.create_index('ix_recommendations_priority',
                    'recommendations', ['priority'])
    op.create_index('ix_recommendation_priority_status',
                    'recommendations', ['priority', 'status'])
    op.create_index('ix_recommendation_category',
                    'recommendations', ['category'])

    # Create indexes for ml_predictions
    op.create_index('ix_ml_predictions_prediction_id',
                    'ml_predictions', ['prediction_id'])
    op.create_index('ix_ml_predictions_intelligence_report_id',
                    'ml_predictions', ['intelligence_report_id'])
    op.create_index('ix_ml_prediction_model',
                    'ml_predictions', ['model_name', 'model_version'])
    op.create_index('ix_ml_prediction_anomaly',
                    'ml_predictions', ['is_anomaly', 'anomaly_score'])

    # Create indexes for generated_reports
    op.create_index('ix_generated_reports_report_id',
                    'generated_reports', ['report_id'])
    op.create_index('ix_generated_reports_intelligence_report_id',
                    'generated_reports', ['intelligence_report_id'])
    op.create_index('ix_generated_reports_evidence_id',
                    'generated_reports', ['evidence_id'])
    op.create_index('ix_generated_reports_format',
                    'generated_reports', ['format'])
    op.create_index('ix_generated_report_format_status',
                    'generated_reports', ['format', 'status'])

    # Create indexes for evidence_integrity
    op.create_index('ix_evidence_integrity_integrity_id',
                    'evidence_integrity', ['integrity_id'])
    op.create_index('ix_evidence_integrity_evidence_id',
                    'evidence_integrity', ['evidence_id'])
    op.create_index('ix_evidence_integrity_intelligence_report_id',
                    'evidence_integrity', ['intelligence_report_id'])
    op.create_index('ix_evidence_integrity_status',
                    'evidence_integrity', ['status'])
    op.create_index('ix_evidence_integrity_hash',
                    'evidence_integrity', ['evidence_sha256'])
    op.create_index('ix_evidence_integrity_blockchain',
                    'evidence_integrity', ['blockchain_enabled', 'transaction_hash'])


def downgrade() -> None:
    """Remove Phase 4 database changes."""

    # Drop indexes - evidence_integrity
    op.drop_index('ix_evidence_integrity_blockchain', table_name='evidence_integrity')
    op.drop_index('ix_evidence_integrity_hash', table_name='evidence_integrity')
    op.drop_index('ix_evidence_integrity_status', table_name='evidence_integrity')
    op.drop_index('ix_evidence_integrity_intelligence_report_id', table_name='evidence_integrity')
    op.drop_index('ix_evidence_integrity_evidence_id', table_name='evidence_integrity')
    op.drop_index('ix_evidence_integrity_integrity_id', table_name='evidence_integrity')

    # Drop indexes - generated_reports
    op.drop_index('ix_generated_report_format_status', table_name='generated_reports')
    op.drop_index('ix_generated_reports_format', table_name='generated_reports')
    op.drop_index('ix_generated_reports_evidence_id', table_name='generated_reports')
    op.drop_index('ix_generated_reports_intelligence_report_id', table_name='generated_reports')
    op.drop_index('ix_generated_reports_report_id', table_name='generated_reports')

    # Drop indexes - ml_predictions
    op.drop_index('ix_ml_prediction_anomaly', table_name='ml_predictions')
    op.drop_index('ix_ml_prediction_model', table_name='ml_predictions')
    op.drop_index('ix_ml_predictions_intelligence_report_id', table_name='ml_predictions')
    op.drop_index('ix_ml_predictions_prediction_id', table_name='ml_predictions')

    # Drop indexes - recommendations
    op.drop_index('ix_recommendation_category', table_name='recommendations')
    op.drop_index('ix_recommendation_priority_status', table_name='recommendations')
    op.drop_index('ix_recommendations_priority', table_name='recommendations')
    op.drop_index('ix_recommendations_intelligence_report_id', table_name='recommendations')
    op.drop_index('ix_recommendations_recommendation_id', table_name='recommendations')

    # Drop indexes - correlations
    op.drop_index('ix_correlation_type_strength', table_name='correlations')
    op.drop_index('ix_correlations_correlation_type', table_name='correlations')
    op.drop_index('ix_correlations_intelligence_report_id', table_name='correlations')
    op.drop_index('ix_correlations_correlation_id', table_name='correlations')

    # Drop indexes - intelligence_reports
    op.drop_index('ix_intelligence_posture', table_name='intelligence_reports')
    op.drop_index('ix_intelligence_evidence_status', table_name='intelligence_reports')
    op.drop_index('ix_intelligence_reports_status', table_name='intelligence_reports')
    op.drop_index('ix_intelligence_reports_job_id', table_name='intelligence_reports')
    op.drop_index('ix_intelligence_reports_security_analysis_id', table_name='intelligence_reports')
    op.drop_index('ix_intelligence_reports_evidence_id', table_name='intelligence_reports')
    op.drop_index('ix_intelligence_reports_report_id', table_name='intelligence_reports')

    # Drop tables in reverse order due to foreign keys
    op.drop_table('evidence_integrity')
    op.drop_table('generated_reports')
    op.drop_table('ml_predictions')
    op.drop_table('recommendations')
    op.drop_table('correlations')
    op.drop_table('intelligence_reports')

    # Note: PostgreSQL enums cannot be easily dropped if referenced elsewhere

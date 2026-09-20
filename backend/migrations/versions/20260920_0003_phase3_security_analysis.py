"""Phase 3: Security Analysis Models

Create security_analyses table for Phase 3 security intelligence engine.

Stores:
- TCP stream reconstruction
- Email security sessions
- TLS observations
- Certificate observations
- Security findings
- Risk assessment

Revision ID: 003_phase3
Revises: 002_phase2
Create Date: 2026-09-20

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '003_phase3'
down_revision: Union[str, None] = '002_phase2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create Phase 3 database changes."""

    # Create securityanalysisstatus enum
    op.execute("""
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'securityanalysisstatus') THEN
                CREATE TYPE securityanalysisstatus AS ENUM (
                    'QUEUED', 'RUNNING', 'COMPLETED', 'FAILED', 'PARTIAL'
                );
            END IF;
        END
        $$;
    """)

    # Create security_analyses table
    op.create_table(
        'security_analyses',
        sa.Column('analysis_id', sa.String(50), primary_key=True),
        sa.Column('job_id', sa.String(50),
                  sa.ForeignKey('analysis_jobs.job_id', ondelete='CASCADE'),
                  nullable=False, unique=True),
        sa.Column('evidence_id', sa.String(50),
                  sa.ForeignKey('pcap_evidence.evidence_id', ondelete='CASCADE'),
                  nullable=False),
        sa.Column('packet_analysis_id', sa.String(50),
                  sa.ForeignKey('packet_analyses.analysis_id', ondelete='CASCADE'),
                  nullable=True),

        # Status
        sa.Column('status', sa.Enum('QUEUED', 'RUNNING', 'COMPLETED', 'FAILED', 'PARTIAL',
                                     name='securityanalysisstatus'),
                  nullable=False, server_default='QUEUED'),

        # Timestamps
        sa.Column('created_at', sa.DateTime(timezone=True),
                  nullable=False, server_default=sa.func.now()),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('duration_seconds', sa.Float(), nullable=True),

        # Analysis counts
        sa.Column('total_streams', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('total_sessions', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('total_tls_observations', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('total_certificates', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('total_findings', sa.Integer(), nullable=False, server_default='0'),

        # Finding severity counts
        sa.Column('critical_findings', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('high_findings', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('medium_findings', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('low_findings', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('info_findings', sa.Integer(), nullable=False, server_default='0'),

        # Risk assessment summary
        sa.Column('overall_risk_level', sa.String(20), nullable=True),
        sa.Column('overall_risk_score', sa.Float(), nullable=True),

        # Analysis metadata
        sa.Column('confidence', sa.String(20), nullable=True, server_default='UNKNOWN'),
        sa.Column('coverage', sa.String(20), nullable=True, server_default='UNKNOWN'),

        # JSON fields for detailed results
        sa.Column('tcp_streams', sa.JSON(), nullable=False, server_default='[]'),
        sa.Column('email_sessions', sa.JSON(), nullable=False, server_default='[]'),
        sa.Column('tls_observations', sa.JSON(), nullable=False, server_default='[]'),
        sa.Column('certificates', sa.JSON(), nullable=False, server_default='[]'),
        sa.Column('findings', sa.JSON(), nullable=False, server_default='[]'),
        sa.Column('risk_assessment', sa.JSON(), nullable=True),

        # Error information
        sa.Column('error_code', sa.String(50), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),

        # Policy version
        sa.Column('policy_version', sa.String(20), nullable=True, server_default='1.0.0'),
    )

    # Create indexes
    op.create_index('ix_security_analyses_analysis_id',
                    'security_analyses', ['analysis_id'])
    op.create_index('ix_security_analyses_job_id',
                    'security_analyses', ['job_id'])
    op.create_index('ix_security_analyses_evidence_id',
                    'security_analyses', ['evidence_id'])
    op.create_index('ix_security_analyses_packet_analysis_id',
                    'security_analyses', ['packet_analysis_id'])
    op.create_index('ix_security_analyses_status',
                    'security_analyses', ['status'])
    op.create_index('ix_security_analysis_evidence_status',
                    'security_analyses', ['evidence_id', 'status'])
    op.create_index('ix_security_analysis_risk',
                    'security_analyses', ['overall_risk_level', 'overall_risk_score'])


def downgrade() -> None:
    """Remove Phase 3 database changes."""

    # Drop indexes
    op.drop_index('ix_security_analysis_risk', table_name='security_analyses')
    op.drop_index('ix_security_analysis_evidence_status', table_name='security_analyses')
    op.drop_index('ix_security_analyses_status', table_name='security_analyses')
    op.drop_index('ix_security_analyses_packet_analysis_id', table_name='security_analyses')
    op.drop_index('ix_security_analyses_evidence_id', table_name='security_analyses')
    op.drop_index('ix_security_analyses_job_id', table_name='security_analyses')
    op.drop_index('ix_security_analyses_analysis_id', table_name='security_analyses')

    # Drop table
    op.drop_table('security_analyses')

    # Note: securityanalysisstatus enum cannot be easily removed in PostgreSQL
    # The enum will remain

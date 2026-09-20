"""Phase 1: Evidence Ingestion Models

Create tables for Case, PcapEvidence, and AnalysisJob models.

Revision ID: 001_phase1
Revises:
Create Date: 2026-09-20

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '001_phase1'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create Phase 1 database tables."""

    # Create cases table
    op.create_table(
        'cases',
        sa.Column('case_id', sa.String(50), primary_key=True),
        sa.Column('case_name', sa.String(255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('status', sa.Enum(
            'OPEN', 'PROCESSING', 'COMPLETED', 'FAILED', 'PARTIAL', 'ARCHIVED',
            name='casestatus'
        ), nullable=False, server_default='OPEN'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )

    # Create indexes for cases
    op.create_index('ix_cases_case_id', 'cases', ['case_id'])
    op.create_index('ix_cases_case_name', 'cases', ['case_name'])
    op.create_index('ix_cases_status', 'cases', ['status'])
    op.create_index('ix_cases_created_at', 'cases', ['created_at'])
    op.create_index('ix_cases_status_created', 'cases', ['status', 'created_at'])

    # Create pcap_evidence table
    op.create_table(
        'pcap_evidence',
        sa.Column('evidence_id', sa.String(50), primary_key=True),
        sa.Column('case_id', sa.String(50), sa.ForeignKey('cases.case_id', ondelete='CASCADE'), nullable=False),
        sa.Column('original_filename', sa.String(512), nullable=False),
        sa.Column('stored_filename', sa.String(128), nullable=False, unique=True),
        sa.Column('file_format', sa.Enum('pcap', 'pcapng', 'unknown', name='fileformat'), nullable=False),
        sa.Column('file_size_bytes', sa.BigInteger(), nullable=False),
        sa.Column('sha256', sa.String(64), nullable=False),
        sa.Column('mime_type', sa.String(128), nullable=True),
        sa.Column('upload_timestamp', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('status', sa.Enum(
            'PENDING', 'VALIDATING', 'VALIDATED', 'INVALID', 'STORED', 'FAILED',
            name='evidencestatus'
        ), nullable=False, server_default='PENDING'),
        sa.Column('storage_location', sa.String(1024), nullable=True),
        sa.Column('validation_status', sa.String(50), nullable=True),
        sa.Column('error_code', sa.String(50), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )

    # Create indexes for pcap_evidence
    op.create_index('ix_evidence_evidence_id', 'pcap_evidence', ['evidence_id'])
    op.create_index('ix_evidence_case_id', 'pcap_evidence', ['case_id'])
    op.create_index('ix_evidence_sha256', 'pcap_evidence', ['sha256'])
    op.create_index('ix_evidence_upload_timestamp', 'pcap_evidence', ['upload_timestamp'])
    op.create_index('ix_evidence_status', 'pcap_evidence', ['status'])
    op.create_index('ix_evidence_case_status', 'pcap_evidence', ['case_id', 'status'])
    op.create_index('ix_evidence_sha256_case', 'pcap_evidence', ['sha256', 'case_id'])

    # Create analysis_jobs table
    op.create_table(
        'analysis_jobs',
        sa.Column('job_id', sa.String(50), primary_key=True),
        sa.Column('evidence_id', sa.String(50), sa.ForeignKey('pcap_evidence.evidence_id', ondelete='CASCADE'), nullable=False),
        sa.Column('job_type', sa.Enum(
            'FULL_ANALYSIS', 'PROTOCOL_DETECTION', 'TLS_ANALYSIS', 'CERTIFICATE_ANALYSIS',
            name='jobtype'
        ), nullable=False, server_default='FULL_ANALYSIS'),
        sa.Column('status', sa.Enum(
            'QUEUED', 'RUNNING', 'COMPLETED', 'FAILED', 'PARTIAL', 'CANCELLED',
            name='jobstatus'
        ), nullable=False, server_default='QUEUED'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('error_code', sa.String(50), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('progress_percent', sa.String(10), nullable=True, server_default='0'),
        sa.Column('stage', sa.String(100), nullable=True),
    )

    # Create indexes for analysis_jobs
    op.create_index('ix_jobs_job_id', 'analysis_jobs', ['job_id'])
    op.create_index('ix_jobs_evidence_id', 'analysis_jobs', ['evidence_id'])
    op.create_index('ix_jobs_status', 'analysis_jobs', ['status'])
    op.create_index('ix_jobs_created_at', 'analysis_jobs', ['created_at'])
    op.create_index('ix_jobs_evidence_status', 'analysis_jobs', ['evidence_id', 'status'])
    op.create_index('ix_jobs_status_created', 'analysis_jobs', ['status', 'created_at'])


def downgrade() -> None:
    """Remove Phase 1 database tables."""

    # Drop analysis_jobs indexes
    op.drop_index('ix_jobs_status_created', table_name='analysis_jobs')
    op.drop_index('ix_jobs_evidence_status', table_name='analysis_jobs')
    op.drop_index('ix_jobs_created_at', table_name='analysis_jobs')
    op.drop_index('ix_jobs_status', table_name='analysis_jobs')
    op.drop_index('ix_jobs_evidence_id', table_name='analysis_jobs')
    op.drop_index('ix_jobs_job_id', table_name='analysis_jobs')

    # Drop analysis_jobs table
    op.drop_table('analysis_jobs')

    # Drop pcap_evidence indexes
    op.drop_index('ix_evidence_sha256_case', table_name='pcap_evidence')
    op.drop_index('ix_evidence_case_status', table_name='pcap_evidence')
    op.drop_index('ix_evidence_status', table_name='pcap_evidence')
    op.drop_index('ix_evidence_upload_timestamp', table_name='pcap_evidence')
    op.drop_index('ix_evidence_sha256', table_name='pcap_evidence')
    op.drop_index('ix_evidence_case_id', table_name='pcap_evidence')
    op.drop_index('ix_evidence_evidence_id', table_name='pcap_evidence')

    # Drop pcap_evidence table
    op.drop_table('pcap_evidence')

    # Drop cases indexes
    op.drop_index('ix_cases_status_created', table_name='cases')
    op.drop_index('ix_cases_created_at', table_name='cases')
    op.drop_index('ix_cases_status', table_name='cases')
    op.drop_index('ix_cases_case_name', table_name='cases')
    op.drop_index('ix_cases_case_id', table_name='cases')

    # Drop cases table
    op.drop_table('cases')

    # Drop enum types
    op.execute('DROP TYPE IF EXISTS jobstatus')
    op.execute('DROP TYPE IF EXISTS jobtype')
    op.execute('DROP TYPE IF EXISTS evidencestatus')
    op.execute('DROP TYPE IF EXISTS fileformat')
    op.execute('DROP TYPE IF EXISTS casestatus')

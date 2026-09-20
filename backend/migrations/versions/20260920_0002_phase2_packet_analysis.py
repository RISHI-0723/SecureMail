"""Phase 2: Packet Analysis Models

Create packet_analyses table and add TIMEOUT to job status enum.

Revision ID: 002_phase2
Revises: 001_phase1
Create Date: 2026-09-20

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '002_phase2'
down_revision: Union[str, None] = '001_phase1'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create Phase 2 database changes."""

    # Add TIMEOUT to jobstatus enum
    # PostgreSQL requires special handling for adding enum values
    op.execute("ALTER TYPE jobstatus ADD VALUE IF NOT EXISTS 'TIMEOUT'")

    # Create packet_analyses table
    op.create_table(
        'packet_analyses',
        sa.Column('analysis_id', sa.String(50), primary_key=True),
        sa.Column('job_id', sa.String(50),
                  sa.ForeignKey('analysis_jobs.job_id', ondelete='CASCADE'),
                  nullable=False, unique=True),
        sa.Column('evidence_id', sa.String(50),
                  sa.ForeignKey('pcap_evidence.evidence_id', ondelete='CASCADE'),
                  nullable=False),

        # TShark metadata
        sa.Column('tshark_version', sa.String(50), nullable=True),
        sa.Column('analysis_timestamp', sa.DateTime(timezone=True),
                  nullable=False, server_default=sa.func.now()),
        sa.Column('duration_seconds', sa.Float(), nullable=True),

        # Packet counts
        sa.Column('total_packets', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('email_packets', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('smtp_packets', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('imap_packets', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('pop3_packets', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('tls_packets', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('other_packets', sa.Integer(), nullable=False, server_default='0'),

        # JSON fields for flexible storage
        sa.Column('protocols_detected', sa.JSON(), nullable=False, server_default='[]'),
        sa.Column('protocol_detections', sa.JSON(), nullable=False, server_default='[]'),
        sa.Column('session_candidates', sa.JSON(), nullable=False, server_default='[]'),

        # Status message
        sa.Column('message', sa.Text(), nullable=True),

        # Timestamps
        sa.Column('created_at', sa.DateTime(timezone=True),
                  nullable=False, server_default=sa.func.now()),
    )

    # Note: Indexes are created automatically by SQLAlchemy via index=True on columns
    # No need for explicit index creation here


def downgrade() -> None:
    """Remove Phase 2 database changes."""

    # Drop packet_analyses table (indexes are dropped automatically with the table)
    op.drop_table('packet_analyses')

    # Note: TIMEOUT cannot be easily removed from enum in PostgreSQL
    # This is a known limitation - the enum value will remain

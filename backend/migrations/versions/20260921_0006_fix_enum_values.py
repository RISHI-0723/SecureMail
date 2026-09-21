"""Fix enum values - Add missing SECURITY_ANALYSIS and INTELLIGENCE to jobtype.

Revision ID: 0006_fix_enums
Revises: 0005_phase5_auth
Create Date: 2026-09-21

Fixes:
- Adds SECURITY_ANALYSIS to jobtype enum (Phase 3)
- Adds INTELLIGENCE to jobtype enum (Phase 4)
"""
from alembic import op


# Revision identifiers
revision = '0006_fix_enums'
down_revision = '0005_phase5_auth'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add missing values to jobtype enum
    # Using raw SQL because ALTER TYPE ADD VALUE cannot run inside a transaction
    # We use IF NOT EXISTS to make this idempotent

    # Commit any pending transaction first
    op.execute("COMMIT")

    # Add SECURITY_ANALYSIS if not exists
    op.execute("""
        DO $$ BEGIN
            ALTER TYPE jobtype ADD VALUE IF NOT EXISTS 'SECURITY_ANALYSIS';
        EXCEPTION
            WHEN duplicate_object THEN null;
        END $$;
    """)

    # Add INTELLIGENCE if not exists
    op.execute("""
        DO $$ BEGIN
            ALTER TYPE jobtype ADD VALUE IF NOT EXISTS 'INTELLIGENCE';
        EXCEPTION
            WHEN duplicate_object THEN null;
        END $$;
    """)


def downgrade() -> None:
    # PostgreSQL does not support removing values from enums
    # The values will remain but won't cause issues
    pass

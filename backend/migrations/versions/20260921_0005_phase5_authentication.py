"""Phase 5 - Authentication and audit logging.

Revision ID: 0005_phase5_auth
Revises: 0004_phase4
Create Date: 2026-09-21

Creates:
- users table for authentication
- audit_logs table for security logging
- Initial admin user (password must be set via environment)
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
from datetime import datetime, timezone


# Revision identifiers
revision = '0005_phase5_auth'
down_revision = '004_phase4'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Create UserRole enum
    op.execute("""
        DO $$ BEGIN
            CREATE TYPE userrole AS ENUM ('ADMIN', 'ANALYST', 'VIEWER');
        EXCEPTION
            WHEN duplicate_object THEN null;
        END $$;
    """)

    # Create UserStatus enum
    op.execute("""
        DO $$ BEGIN
            CREATE TYPE userstatus AS ENUM ('ACTIVE', 'INACTIVE', 'LOCKED');
        EXCEPTION
            WHEN duplicate_object THEN null;
        END $$;
    """)

    # Create users table
    op.create_table(
        'users',
        sa.Column('user_id', sa.String(50), primary_key=True, index=True),
        sa.Column('username', sa.String(50), unique=True, nullable=False, index=True),
        sa.Column('email', sa.String(255), unique=True, nullable=False, index=True),
        sa.Column('password_hash', sa.String(255), nullable=False),
        sa.Column('role', postgresql.ENUM('ADMIN', 'ANALYST', 'VIEWER', name='userrole', create_type=False), nullable=False, default='VIEWER'),
        sa.Column('status', postgresql.ENUM('ACTIVE', 'INACTIVE', 'LOCKED', name='userstatus', create_type=False), nullable=False, default='ACTIVE', index=True),
        sa.Column('full_name', sa.String(255), nullable=True),
        sa.Column('failed_login_attempts', sa.String(10), nullable=False, default='0'),
        sa.Column('last_login', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_failed_login', sa.DateTime(timezone=True), nullable=True),
        sa.Column('password_changed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_by', sa.String(50), nullable=True),
    )

    # Create index for role and status
    op.create_index('ix_users_role_status', 'users', ['role', 'status'])

    # Create audit_logs table
    op.create_table(
        'audit_logs',
        sa.Column('log_id', sa.String(50), primary_key=True, index=True),
        sa.Column('timestamp', sa.DateTime(timezone=True), nullable=False, default=sa.func.now(), index=True),
        sa.Column('user_id', sa.String(50), nullable=True, index=True),
        sa.Column('username', sa.String(50), nullable=True),
        sa.Column('ip_address', sa.String(45), nullable=True),
        sa.Column('user_agent', sa.Text(), nullable=True),
        sa.Column('action', sa.String(100), nullable=False, index=True),
        sa.Column('resource_type', sa.String(50), nullable=True),
        sa.Column('resource_id', sa.String(100), nullable=True),
        sa.Column('status', sa.String(20), nullable=False, default='SUCCESS'),
        sa.Column('details', sa.Text(), nullable=True),
        sa.Column('request_id', sa.String(50), nullable=True, index=True),
    )

    # Create indexes for audit queries
    op.create_index('ix_audit_user_action', 'audit_logs', ['user_id', 'action'])
    op.create_index('ix_audit_timestamp_action', 'audit_logs', ['timestamp', 'action'])


def downgrade() -> None:
    op.drop_table('audit_logs')
    op.drop_table('users')

    # Drop enums
    op.execute("DROP TYPE IF EXISTS userstatus")
    op.execute("DROP TYPE IF EXISTS userrole")

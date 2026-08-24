"""create evidence_records table

Revision ID: 0010_create_evidence_records_table
Revises: 0009_create_case_iocs_table
Create Date: 2026-08-24 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "0010_create_evidence_records_table"
down_revision: Union[str, None] = "0009_create_case_iocs_table"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "evidence_records",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("case_id", sa.String(length=36), nullable=False),
        sa.Column("evidence_type", sa.String(length=50), nullable=False),
        sa.Column("sha256_hash", sa.String(length=64), nullable=False),
        sa.Column("file_name", sa.String(length=255), nullable=True),
        sa.Column("file_size_bytes", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("metadata_json", sa.JSON(), nullable=False),
        sa.Column("calculated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_evidence_records_id"), "evidence_records", ["id"], unique=False)
    op.create_index(op.f("ix_evidence_records_case_id"), "evidence_records", ["case_id"], unique=False)
    op.create_index(op.f("ix_evidence_records_evidence_type"), "evidence_records", ["evidence_type"], unique=False)
    op.create_index(op.f("ix_evidence_records_sha256_hash"), "evidence_records", ["sha256_hash"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_evidence_records_sha256_hash"), table_name="evidence_records")
    op.drop_index(op.f("ix_evidence_records_evidence_type"), table_name="evidence_records")
    op.drop_index(op.f("ix_evidence_records_case_id"), table_name="evidence_records")
    op.drop_index(op.f("ix_evidence_records_id"), table_name="evidence_records")
    op.drop_table("evidence_records")

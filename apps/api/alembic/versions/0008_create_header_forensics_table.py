"""create header_forensics table

Revision ID: 0008_create_header_forensics_table
Revises: 0007_create_risk_assessments_table
Create Date: 2026-08-23 07:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "0008_create_header_forensics_table"
down_revision: Union[str, None] = "0007_create_risk_assessments_table"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "header_forensics",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("case_id", sa.String(length=36), nullable=False),
        sa.Column("relay_hops", sa.JSON(), nullable=False),
        sa.Column("origin_ip_candidates", sa.JSON(), nullable=False),
        sa.Column("probable_origin_ip", sa.String(length=64), nullable=True),
        sa.Column("spf_status", sa.String(length=20), nullable=False),
        sa.Column("dkim_status", sa.String(length=20), nullable=False),
        sa.Column("dmarc_status", sa.String(length=20), nullable=False),
        sa.Column("authentication_details", sa.JSON(), nullable=False),
        sa.Column("spoofing_indicators", sa.JSON(), nullable=False),
        sa.Column("anomalies", sa.JSON(), nullable=False),
        sa.Column("forensics_risk_score", sa.Float(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("case_id"),
    )
    op.create_index(op.f("ix_header_forensics_id"), "header_forensics", ["id"], unique=False)
    op.create_index(op.f("ix_header_forensics_case_id"), "header_forensics", ["case_id"], unique=True)


def downgrade() -> None:
    op.drop_index(op.f("ix_header_forensics_case_id"), table_name="header_forensics")
    op.drop_index(op.f("ix_header_forensics_id"), table_name="header_forensics")
    op.drop_table("header_forensics")

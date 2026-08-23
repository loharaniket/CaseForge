"""create case_iocs table

Revision ID: 0009_create_case_iocs_table
Revises: 0008_create_header_forensics_table
Create Date: 2026-08-23 08:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "0009_create_case_iocs_table"
down_revision: Union[str, None] = "0008_create_header_forensics_table"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "case_iocs",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("case_id", sa.String(length=36), nullable=False),
        sa.Column("ioc_type", sa.String(length=20), nullable=False),
        sa.Column("value", sa.String(length=512), nullable=False),
        sa.Column("source", sa.String(length=255), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("context", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_case_iocs_id"), "case_iocs", ["id"], unique=False)
    op.create_index(op.f("ix_case_iocs_case_id"), "case_iocs", ["case_id"], unique=False)
    op.create_index(op.f("ix_case_iocs_ioc_type"), "case_iocs", ["ioc_type"], unique=False)
    op.create_index(op.f("ix_case_iocs_value"), "case_iocs", ["value"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_case_iocs_value"), table_name="case_iocs")
    op.drop_index(op.f("ix_case_iocs_ioc_type"), table_name="case_iocs")
    op.drop_index(op.f("ix_case_iocs_case_id"), table_name="case_iocs")
    op.drop_index(op.f("ix_case_iocs_id"), table_name="case_iocs")
    op.drop_table("case_iocs")

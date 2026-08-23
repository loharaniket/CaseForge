"""create threat_assessments table

Revision ID: 0006_create_threat_assessments_table
Revises: 0005_add_case_error_message_and_status
Create Date: 2026-08-23 05:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "0006_create_threat_assessments_table"
down_revision: Union[str, None] = "0005_add_case_error_message_and_status"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "threat_assessments",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("case_id", sa.String(length=36), nullable=False),
        sa.Column("classification", sa.String(length=50), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("reasons", sa.JSON(), nullable=False),
        sa.Column("model_version", sa.String(length=100), nullable=False),
        sa.Column("signals_detected", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("case_id"),
    )
    op.create_index(op.f("ix_threat_assessments_id"), "threat_assessments", ["id"], unique=False)
    op.create_index(op.f("ix_threat_assessments_case_id"), "threat_assessments", ["case_id"], unique=True)


def downgrade() -> None:
    op.drop_index(op.f("ix_threat_assessments_case_id"), table_name="threat_assessments")
    op.drop_index(op.f("ix_threat_assessments_id"), table_name="threat_assessments")
    op.drop_table("threat_assessments")

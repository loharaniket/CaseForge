"""create risk_assessments table

Revision ID: 0007_create_risk_assessments_table
Revises: 0006_create_threat_assessments_table
Create Date: 2026-08-23 06:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "0007_create_risk_assessments_table"
down_revision: Union[str, None] = "0006_create_threat_assessments_table"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "risk_assessments",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("case_id", sa.String(length=36), nullable=False),
        sa.Column("total_score", sa.Float(), nullable=False),
        sa.Column("severity", sa.String(length=20), nullable=False),
        sa.Column("breakdown", sa.JSON(), nullable=False),
        sa.Column("weights_applied", sa.JSON(), nullable=False),
        sa.Column("missing_components", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("case_id"),
    )
    op.create_index(op.f("ix_risk_assessments_id"), "risk_assessments", ["id"], unique=False)
    op.create_index(op.f("ix_risk_assessments_case_id"), "risk_assessments", ["case_id"], unique=True)


def downgrade() -> None:
    op.drop_index(op.f("ix_risk_assessments_case_id"), table_name="risk_assessments")
    op.drop_index(op.f("ix_risk_assessments_id"), table_name="risk_assessments")
    op.drop_table("risk_assessments")

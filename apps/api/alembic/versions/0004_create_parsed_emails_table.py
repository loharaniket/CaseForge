"""create parsed_emails table

Revision ID: 0004_create_parsed_emails_table
Revises: 0003_create_cases_table
Create Date: 2026-08-23 03:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "0004_create_parsed_emails_table"
down_revision: Union[str, None] = "0003_create_cases_table"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "parsed_emails",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("case_id", sa.String(length=36), nullable=False),
        sa.Column("sender", sa.String(length=255), nullable=True),
        sa.Column("from_name", sa.String(length=255), nullable=True),
        sa.Column("from_address", sa.String(length=255), nullable=True),
        sa.Column("recipients", sa.JSON(), nullable=False),
        sa.Column("cc", sa.JSON(), nullable=False),
        sa.Column("bcc", sa.JSON(), nullable=False),
        sa.Column("reply_to", sa.JSON(), nullable=False),
        sa.Column("subject", sa.Text(), nullable=True),
        sa.Column("date_raw", sa.String(length=255), nullable=True),
        sa.Column("date_parsed", sa.DateTime(timezone=True), nullable=True),
        sa.Column("message_id", sa.String(length=255), nullable=True),
        sa.Column("body_plain", sa.Text(), nullable=True),
        sa.Column("body_html", sa.Text(), nullable=True),
        sa.Column("extracted_urls", sa.JSON(), nullable=False),
        sa.Column("attachments_metadata", sa.JSON(), nullable=False),
        sa.Column("raw_headers", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("case_id"),
    )
    op.create_index(op.f("ix_parsed_emails_id"), "parsed_emails", ["id"], unique=False)
    op.create_index(op.f("ix_parsed_emails_case_id"), "parsed_emails", ["case_id"], unique=True)
    op.create_index(op.f("ix_parsed_emails_message_id"), "parsed_emails", ["message_id"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_parsed_emails_message_id"), table_name="parsed_emails")
    op.drop_index(op.f("ix_parsed_emails_case_id"), table_name="parsed_emails")
    op.drop_index(op.f("ix_parsed_emails_id"), table_name="parsed_emails")
    op.drop_table("parsed_emails")

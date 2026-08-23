"""add case error_message column

Revision ID: 0005_add_case_error_message_and_status
Revises: 0004_create_parsed_emails_table
Create Date: 2026-08-23 04:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "0005_add_case_error_message_and_status"
down_revision: Union[str, None] = "0004_create_parsed_emails_table"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("cases", sa.Column("error_message", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("cases", "error_message")

"""Add user telegram id

Revision ID: 0003
Revises: 0002
Create Date: 2026-09-30 16:32:00.750812

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0003'
down_revision: Union[str, Sequence[str], None] = '0002'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column('users', sa.Column('telegram_id', sa.String(length=30), nullable=True))
    op.add_column('users', sa.Column('token', sa.String(), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('users', 'telegram_id')
    op.drop_column('users', 'token')

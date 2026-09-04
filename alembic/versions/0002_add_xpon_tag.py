from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.sql import table, column


# revision identifiers, used by Alembic.
revision: str = '0002'
down_revision: Union[str, Sequence[str], None] = '0001'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

cfg_helper = table('cfg',
    column('key', sa.String),
    column('value', sa.String)
)


def upgrade() -> None:
    """Upgrade schema."""
    op.bulk_insert(
        cfg_helper,
        [
            {'key': 'XPON_TAG', 'value': 'xpon'}
        ]
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.execute(
        cfg_helper.delete().where(cfg_helper.c.key == 'XPON_TAG')
    )

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = '0005'
down_revision: Union[str, Sequence[str], None] = '0004'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    conn = op.get_bind()

    conn.execute(
                sa.text("DELETE FROM menu_cfg WHERE menuname IN ('Настройка MikBill', 'Настройка SNMP', 'Токены API', 'Просмотр логов')")
            )

    cfg_table = sa.table(
        'cfg',
        sa.column('id'),
        sa.column('key'),
        sa.column('value'),
        )

    conn.execute(
        cfg_table.insert().values(
            [
                {'key': 'MIKBILL_KEY', 'value': 'None'},
                {'key': 'MIKBILL_URL', 'value': 'None'},
            ]
        )
    )

    menu_table = sa.table(
            'menu_cfg',
            sa.column('id'),
            sa.column('menuname'),
            sa.column('url'),
            sa.column('privilage'),
            )

    conn.execute(
            menu_table.insert().values(
                [
                    {'menuname': 'Настройка MikBill', 'url': '/settings/cfgmb', 'privilage': 'Administrator'},
                    {'menuname': 'Настройка SNMP', 'url': '/settings/cfgsnmp', 'privilage': 'Administrator'},
                    {'menuname': 'Токены API', 'url': '/settings/tokens', 'privilage': 'Administrator'},
                    {'menuname': 'Просмотр логов', 'url': '/settings/showlogs', 'privilage': 'Administrator'},
                ]
            )
        )

def downgrade() -> None:
    """Downgrade schema."""
    conn = op.get_bind()

    conn.execute(
        sa.text("DELETE FROM cfg WHERE key IN ('MIKBILL_KEY', 'MIKBILL_URL')")
    )

    conn.execute(
            sa.text("DELETE FROM menu_cfg WHERE menuname IN ('Настройка MikBill')")
        )

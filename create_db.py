from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from werkzeug.security import generate_password_hash

from models.base import Base
from models.models import Users, Cfg, MenuCfg


# Имя базы и путь до неё, папка должна быть instance, иначе не будет работать
NAMEDB = "onulist.db"
PATHDB = f"instance/{NAMEDB}"

engine = create_engine(
                    "sqlite:///instance/onulist.db",
                    echo=False,
                    )

if __name__ == "__main__":
    Base.metadata.create_all(engine)
    print(f"Создана новая база данных: {PATHDB}")

    with Session(engine) as session:
        # Создаём дефолтного пользователя root
        username  = 'root'
        psw       = 'admin'
        psw_hash  = generate_password_hash(psw)
        privilage = 'Administrator'

        default_user = Users(
            login     = username,
            password  = psw_hash,
            privilage = privilage,
            )

        session.add(default_user)

        # Создаём дефолтные настройки для NetBox (как образец)
        nb_cfg = [
            ['API_KEY', 'Token'],
            ['EPON_TAG', 'epon'],
            ['GPON_TAG', 'gpon'],
            ['URLNB', 'https://'],
            ['PL_H', 'Huawei_OLT'],
            ['PL_B', 'BDCOM'],
            ['PL_C', 'C-Data']
            ]

        for nb in nb_cfg:
            tmp_nb = Cfg(
                key   = nb[0],
                value = nb[1],
                )
            session.add(tmp_nb)

        # Создаём дефолтные настройки для SNMP (как образец)
        snmp_cfg = [
            ['SNMP_READ_H', 'public'],
            ['SNMP_READ_B', 'public'],
            ['SNMP_CONF_H', 'private'],
            ['SNMP_CONF_B', 'private'],
            ['SNMP_READ_C', 'public'],
            ['SNMP_CONF_C', 'private'],
        ]
        for sn in snmp_cfg:
            tmp_sn = Cfg(
                key   = sn[0],
                value = sn[1],
                )
            session.add(tmp_sn)

        menu_cfg = [
            ['Профиль', '/settings/profile', 'Operator'],
            ['Пользователи', '/settings/adduser', 'Administrator'],
            ['Добавить OLT', '/settings/oltadd', 'Administrator'],
            ['Настройка NetBox', '/settings/cfgnb', 'Administrator'],
            ['Настройка SNMP', '/settings/cfgsnmp', 'Administrator'],
        ]
        for mn in menu_cfg:
            tmp_mn = MenuCfg(
                menuname=mn[0],
                url=mn[1],
                privilage=mn[2],
                )
            session.add(tmp_mn)

        session.commit()

    print("Добавлены дефолтные данные")
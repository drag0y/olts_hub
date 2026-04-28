from sqlalchemy import ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from typing import List

from .base import Base


class OLTs(Base):
    __tablename__ = 'olts'
    id:          Mapped[int] = mapped_column(primary_key=True)
    hostname:    Mapped[str] = mapped_column(unique=True)
    descr:       Mapped[str] = mapped_column(nullable=True)
    group_id:    Mapped[int] = mapped_column(ForeignKey('groups.id'))
    ip_address:  Mapped[str] = mapped_column(unique=True)
    platform:    Mapped[str]
    pon_type:    Mapped[str]
    snmp_read:   Mapped[str] = mapped_column(nullable=True)
    snmp_write:  Mapped[str] = mapped_column(nullable=True)
    conn_type:   Mapped[str] = mapped_column(nullable=True)
    conn_login:  Mapped[str] = mapped_column(nullable=True)
    conn_psw:    Mapped[str] = mapped_column(nullable=True)

    group:       Mapped["Groups"] = relationship()
    onts:        Mapped[List['Onu']] = relationship(
        back_populates='olt',
    )


class PonPorts(Base):
    __tablename__ = 'ponports'
    id:         Mapped[int] = mapped_column(primary_key=True)
    pon_port:   Mapped[str]
    pon_type:   Mapped[str] = mapped_column(nullable=True)
    port_oid:   Mapped[str]
    olt_id:     Mapped[str] = mapped_column(ForeignKey('olts.id'))


class Users(Base):
    __tablename__ = 'users'
    id:        Mapped[int] = mapped_column(primary_key=True)
    username:  Mapped[str] = mapped_column(unique=True)
    password:  Mapped[str] 
    privilage: Mapped[str]
    group_id:  Mapped[int] = mapped_column(ForeignKey('groups.id'))

    group:     Mapped["Groups"] = relationship()


class Cfg(Base):
    __tablename__ = 'cfg'
    id:    Mapped[int] = mapped_column(primary_key=True)
    key:   Mapped[str] = mapped_column(unique=True)
    value: Mapped[str]


class MenuCfg(Base):
    __tablename__ = 'menu_cfg'
    id:        Mapped[int] = mapped_column(primary_key=True)
    menuname:  Mapped[str] = mapped_column(unique=True)
    url:       Mapped[str]
    privilage: Mapped[str]


class Onu(Base):
    __tablename__ = 'onu'
    id:       Mapped[int] = mapped_column(primary_key=True)
    onu:      Mapped[str]
    port_oid: Mapped[int]
    onu_oid:  Mapped[int]
    olt_id:   Mapped[int] = mapped_column(ForeignKey('olts.id'))

    olt:      Mapped['OLTs'] = relationship(back_populates='onts')
    pon_port_info: Mapped['PonPorts'] = relationship(
        'PonPorts',
        primaryjoin="and_("
                    "foreign(Onu.port_oid) == remote(PonPorts.port_oid), "
                    "foreign(Onu.olt_id) == remote(PonPorts.olt_id)"
                    ")",
        viewonly=True,
        overlaps="olt"
    )


class ApiTokens(Base):
    __tablename__ = 'api_tokens'
    id:           Mapped[int] = mapped_column(primary_key=True)
    user_id:      Mapped[int] = mapped_column(ForeignKey('users.id'))
    created_date: Mapped[str]


class Groups(Base):
    __tablename__ = 'groups'
    id:         Mapped[int] = mapped_column(primary_key=True)
    group_name: Mapped[str] = mapped_column(unique=True)


class History(Base):
    __tablename__ = 'history'
    id:     Mapped[int] = mapped_column(primary_key=True)
    onu:    Mapped[str]
    olt_id: Mapped[str] = mapped_column(ForeignKey('olts.id'))
    date:   Mapped[str]
    status: Mapped[str]
    descr:  Mapped[str] = mapped_column(nullable=True)
    rx_onu: Mapped[str]
    rx_olt: Mapped[str]
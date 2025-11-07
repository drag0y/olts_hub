from sqlalchemy.orm import Mapped, mapped_column

from .base import Base


class OLTs(Base):
    __tablename__ = 'olts'
    number:     Mapped[int] = mapped_column(primary_key=True)
    hostname:   Mapped[str] = mapped_column(unique=True)
    ip_address: Mapped[str] = mapped_column(unique=True)
    platform:   Mapped[str]
    pon:        Mapped[str]

    def __repr__(self):
        return '<OLTs %r>' % self.number


class Users(Base):
    __tablename__ = 'users'
    id:        Mapped[int] = mapped_column(primary_key=True)
    login:     Mapped[str] = mapped_column(unique=True)
    password:  Mapped[str] 
    privilage: Mapped[str]

    def __repr__(self):
        return '<Users %r>' % self.id


class Cfg(Base):
    __tablename__ = 'cfg'
    id:    Mapped[int] = mapped_column(primary_key=True)
    key:   Mapped[str] = mapped_column(unique=True)
    value: Mapped[str]

    def __repr__(self):
        return '<Cfg %r>' % self.id


class MenuCfg(Base):
    __tablename__ = 'menu_cfg'
    id:        Mapped[int] = mapped_column(primary_key=True)
    menuname:  Mapped[str] = mapped_column(unique=True)
    url:       Mapped[str]
    privilage: Mapped[str]

    def __repr__(self):
        return '<MenuCfg %r>' % self.id


class PonPorts(Base):
    __tablename__ = 'ponports'
    number:     Mapped[int] = mapped_column(primary_key=True)
    hostname:   Mapped[str]
    ip_address: Mapped[str]
    ponport:    Mapped[str]
    portoid:    Mapped[str]

    def __repr__(self):
        return '<PonPorts %r>' % self.number


class Epon(Base):
    __tablename__ = 'epon'
    number:  Mapped[int] = mapped_column(primary_key=True)
    maconu:  Mapped[str]
    portonu: Mapped[str]
    idonu:   Mapped[str]
    oltip:   Mapped[str]
    oltname: Mapped[str]

    def __repr__(self):
        return '<Epon %r>' % self.number


class Gpon(Base):
    __tablename__ = 'gpon'
    number:  Mapped[int] = mapped_column(primary_key=True)
    snonu:   Mapped[str]
    portonu: Mapped[str]
    idonu:   Mapped[str]
    oltip:   Mapped[str]
    oltname: Mapped[str]

    def __repr__(self):
        return '<Gpon %r>' % self.number

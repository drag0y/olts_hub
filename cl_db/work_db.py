import sqlite3
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from cl_db.db_cfg import Init_Cfg
from cl_olt.bdcom_olts import BdcomGetOltInfo
from cl_olt.huawei_olts import HuaweiGetOltInfo
from cl_olt.cdata_olts import CdataGetOltInfo
from models.base import Base
from models.models import Users, Cfg, MenuCfg, OLTs, PonPorts


class WorkDB:
    """
    Класс для работы с БД, создание/удаление таблиц, поиск дубликатов
    """
    def __init__(self, pathdb):
        self.pathdb = pathdb

        self.engine = create_engine(
            url = "sqlite:///instance/onulist.db",
            echo=True,
        )


    def createnewtableolts(self):
        # Создание таблицы с ОЛТами
        OLTs.__table__.drop(self.engine)
        OLTs.__table__.create(self.engine)


    def createnewtableponports(self):
        # Создание таблицы с pon портами
        PonPorts.__table__.drop(self.engine)
        PonPorts.__table__.create(self.engine)


    def createnewtableepon(self):
        # Создание таблицы с ОНУ, epon
        conn = sqlite3.connect(self.pathdb)
        cursor = conn.cursor()
        cursor.execute("DROP TABLE IF EXISTS epon")
        cursor.execute("CREATE TABLE epon(number integer primary key autoincrement, maconu text, portonu text, idonu text, oltip text, oltname text)")
        conn.close()


    def createnewtablegpon(self):
        # Создание таблицы с ОНУ, gpon
        conn = sqlite3.connect(self.pathdb)
        cursor = conn.cursor()
        cursor.execute("DROP TABLE IF EXISTS gpon")
        cursor.execute("CREATE TABLE gpon(number integer primary key autoincrement, snonu text, portonu text, idonu text, oltip text, oltname text)")
        conn.close()


    def finddoublemac(self):
        # Поиск дубликатов ОНУ в базе по МАКу
        outdoublemac = []

        conn = sqlite3.connect(self.pathdb)
        cursor = conn.cursor()

        dubleonu = cursor.execute('select maconu, count(*) from epon group by maconu having count(*) > 1')
        dublicatemac = []
        dublicatemac2 = []

        for row in dubleonu:
            dublicatemac.append(row[0])

        if dublicatemac:
            for row in dublicatemac:
                macdoubleonu = cursor.execute(f'select * from epon where maconu glob "{row}"')
                for row in macdoubleonu:
                    outdoublemac.append(row[1] + ";" + row[4])

        else:
            outdoublemac = [';']
        
        conn.close()

        return outdoublemac


    def finddoublesn(self):
        # Поиск дубликатов ОНУ в базе по серийному номеру
        outdoublesn = []
        dublicatesn = []
        dublicatesn2 = []

        conn = sqlite3.connect(self.pathdb)
        cursor = conn.cursor()

        dubleonusn = cursor.execute('select snonu, count(*) from gpon group by snonu having count(*) > 1')

        for row in dubleonusn:
            dublicatesn.append(row[0])

        if dublicatesn:
            for row in dublicatesn:
                sndoubleonu = cursor.execute(f'select * from gpon where snonu glob "{row}"')
                for row in sndoubleonu:
                    outdoublesn.append(row[1] + ";" + row[4])

        else:
            outdoublesn = [';']

        conn.close()
        
        return outdoublesn


class WorkingDB:
    """
    Класс для работы с БД, с конкретными ОЛТами
    """
    def __init__(self, pathdb, ip_address):
        self.pathdb = pathdb
        self.ip_address = ip_address
        snmp_cfg = Init_Cfg(pathdb)
        cfg = snmp_cfg.getcfg()
        self.PF_HUAWEI = cfg['PL_H']
        self.PF_BDCOM = cfg['PL_B']
        self.PF_CDATA = cfg['PL_C']
        self.SNMP_READ_H = cfg['SNMP_READ_H']
        self.SNMP_READ_B = cfg['SNMP_READ_B']
        self.SNMP_READ_C = cfg['SNMP_READ_C']


    def drop_olt(self):
        # Удалить порты и ОНУ конкретного ОЛТА перед опросом
        conn = sqlite3.connect(self.pathdb)
        cursor = conn.cursor()
        cursor.execute(f"DELETE FROM ponports WHERE ip_address='{self.ip_address}'")
        cursor.execute(f"DELETE FROM epon WHERE oltip='{self.ip_address}'")
        cursor.execute(f"DELETE FROM gpon WHERE oltip='{self.ip_address}'")

        conn.commit()
        conn.close()


    def drop_olt_fromdb(self):
        # Удалить ОЛТ из базы
        conn = sqlite3.connect(self.pathdb)
        cursor = conn.cursor()
        cursor.execute(f"DELETE FROM ponports WHERE ip_address='{self.ip_address}'")
        cursor.execute(f"DELETE FROM epon WHERE oltip='{self.ip_address}'")
        cursor.execute(f"DELETE FROM gpon WHERE oltip='{self.ip_address}'")
        cursor.execute(f"DELETE FROM olts WHERE ip_address='{self.ip_address}'")

        conn.commit()
        conn.close()


    def olt_update(self):
        # Опросить ОЛТ
        conn = sqlite3.connect(self.pathdb)
        cursor = conn.cursor()
        findolt = cursor.execute(f"SELECT * FROM olts WHERE ip_address='{self.ip_address}'")
    
        if findolt:
            for olt_info in findolt:
                hostname = olt_info[1]
                ip_address = olt_info[2]
                platform = olt_info[3]
                pon_type = olt_info[4]

                if self.PF_HUAWEI in platform:
                    olt = HuaweiGetOltInfo(hostname, ip_address, self.SNMP_READ_H, self.pathdb, pon_type)
                    olt.getoltports()
                    olt.getonulist()

                elif self.PF_BDCOM in platform:
                    olt = BdcomGetOltInfo(hostname, ip_address, self.SNMP_READ_B, self.pathdb, pon_type)
                    olt.getoltports()
                    olt.getonulist()
                
                elif self.PF_CDATA in platform:
                    olt = CdataGetOltInfo(hostname, ip_address, self.SNMP_READ_C, self.pathdb, pon_type)
                    olt.getoltports()
                    olt.getonulist()

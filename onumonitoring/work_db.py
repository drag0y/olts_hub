import sqlite3
import os

from onumonitoring.bdcom_olts import BdcomGetOltInfo
from onumonitoring.huawei_olts import HuaweiGetOltInfo
#from config import SNMP_READ_H, SNMP_READ_B, PF_HUAWEI, PF_BDCOM

from dotenv import load_dotenv


load_dotenv()

SNMP_READ_H = os.getenv('SNMP_READ_H')
SNMP_READ_B = os.getenv('SNMP_READ_B')
SNMP_CONF_H = os.getenv('SNMP_CONF_H')
SNMP_CONF_B = os.getenv('SNMP_CONF_B')
PF_HUAWEI = os.getenv('PF_HUAWEI')
PF_BDCOM = os.getenv('PF_BDCOM')



class WorkDB:
    ''' Класс для работы с БД, создание/удаление таблиц, поиск дубликатов '''
    def __init__(self, pathdb):
        self.pathdb = pathdb
       

    def createnewdb(self):
        # Создание новой базы, если база уже есть, то она удаляется
        conn = sqlite3.connect(self.pathdb)
        cursor = conn.cursor()
        cursor.execute("DROP TABLE IF EXISTS users")
        cursor.execute("DROP TABLE IF EXISTS olts")
        cursor.execute("DROP TABLE IF EXISTS ponports")
        cursor.execute("DROP TABLE IF EXISTS epon")
        cursor.execute("DROP TABLE IF EXISTS gpon")
        cursor.execute("CREATE TABLE users(number integer primary key autoincrement, login text, password text, privilage text)")
        cursor.execute("CREATE TABLE olts(number integer primary key autoincrement, hostname text, ip_address text, platform text, pon text)")
        cursor.execute("CREATE TABLE ponports(number integer primary key autoincrement, hostname text, ip_address text, ponport text, portoid text)")
        cursor.execute("CREATE TABLE epon(number integer primary key autoincrement, maconu text, portonu text, idonu text, oltip text, oltname text)")
        cursor.execute("CREATE TABLE gpon(number integer primary key autoincrement, snonu text, portonu text, idonu text, oltip text, oltname text)")
        conn.close()


    def createnewtableolts(self):
        # Создание таблицы с ОЛТами
        conn = sqlite3.connect(self.pathdb)
        cursor = conn.cursor()
        cursor.execute("DROP TABLE IF EXISTS olts")
        cursor.execute("CREATE TABLE olts(number integer primary key autoincrement, hostname text, ip_address text, platform text, pon text)")
        conn.close()


    def createnewtableponports(self):
        # Создание таблицы с pon портами
        conn = sqlite3.connect(self.pathdb)
        cursor = conn.cursor()
        cursor.execute("DROP TABLE IF EXISTS ponports")
        cursor.execute("CREATE TABLE ponports(number integer primary key autoincrement, hostname text, ip_address text, ponport text, portoid text)")
        conn.close()


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
            outdoublemac = ["На OLTах EPON; нет повторяющихся ОНУ"]
        
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
            outdoublesn = ["На OLTах GPON; нет повторяющихся ОНУ"]

        conn.close()
        
        return outdoublesn


class WorkingDB:
    ''' Класс для работы с БД, с конкретными ОЛТами '''
    def __init__(self, pathdb, ip_address):
        self.pathdb = pathdb
        self.ip_address = ip_address


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

                if PF_HUAWEI in platform:
                    olt = HuaweiGetOltInfo(hostname, ip_address, SNMP_READ_H, self.pathdb, pon_type)
                    olt.getoltports()
                    olt.getonulist()

                elif PF_BDCOM in platform:
                    olt = BdcomGetOltInfo(hostname, ip_address, SNMP_READ_B, self.pathdb, pon_type)
                    olt.getoltports()
                    olt.getonulist()



import sqlite3
import os

from cl_db.db_cfg import Init_Cfg
from cl_olt.bdcom_olts import BdcomGetOltInfo
from cl_olt.huawei_olts import HuaweiGetOltInfo
from cl_olt.cdata_olts import CdataGetOltInfo
from werkzeug.security import generate_password_hash


class WorkDB:
    ''' Класс для работы с БД, создание/удаление таблиц, поиск дубликатов '''
    def __init__(self, pathdb):
        self.pathdb = pathdb     


    def createnewdb(self):
        # Создание новой базы
        conn = sqlite3.connect(self.pathdb)
        cursor = conn.cursor()
        # Удаляем таблицы если есть
        cursor.execute("DROP TABLE IF EXISTS users")
        cursor.execute("DROP TABLE IF EXISTS cfg")
        cursor.execute("DROP TABLE IF EXISTS menu_cfg")
        cursor.execute("DROP TABLE IF EXISTS olts")
        cursor.execute("DROP TABLE IF EXISTS ponports")
        cursor.execute("DROP TABLE IF EXISTS epon")
        cursor.execute("DROP TABLE IF EXISTS gpon")

        # Создаём таблицы
        cursor.execute("CREATE TABLE users(id integer primary key autoincrement, login text UNIQUE NOT NULL, password text NOT NULL, privilage text NOT NULL)")
        cursor.execute("CREATE TABLE cfg(id integer primary key autoincrement, key text UNIQUE NOT NULL, value text)")
        cursor.execute("CREATE TABLE menu_cfg(id integer primary key autoincrement, menuname text UNIQUE NOT NULL, url text, privilage text)")
        cursor.execute("CREATE TABLE olts(number integer primary key autoincrement, hostname text, ip_address text, platform text, pon text)")
        cursor.execute("CREATE TABLE ponports(number integer primary key autoincrement, hostname text, ip_address text, ponport text, portoid text)")
        cursor.execute("CREATE TABLE epon(number integer primary key autoincrement, maconu text, portonu text, idonu text, oltip text, oltname text)")
        cursor.execute("CREATE TABLE gpon(number integer primary key autoincrement, snonu text, portonu text, idonu text, oltip text, oltname text)")

        # Создаём дефолтного пользователя root
        username = 'root'
        psw = 'admin'
        psw_hash = generate_password_hash(psw)
        privilage = 'Administrator'
        user = [username, psw_hash, privilage]
        query_user = "INSERT into users(login, password, privilage) values (?, ?, ?)"
        cursor.execute(query_user, user)
        conn.commit()

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
        # Создаём дефолтные настройки для SNMP (как образец)
        snmp_cfg = [
                ['SNMP_READ_H', 'public'],
                ['SNMP_READ_B', 'public'],
                ['SNMP_CONF_H', 'private'],
                ['SNMP_CONF_B', 'private'],
                ['SNMP_READ_C', 'public'],
                ['SNMP_CONF_C', 'private'],
            ]

        menu_cfg = [
                ['Профиль', '/settings/profile', 'Operator'],
                ['Пользователи', '/settings/adduser', 'Administrator'],
                ['Добавить OLT', '/settings/oltadd', 'Administrator'],
                ['Настройка NetBox', '/settings/cfgnb', 'Administrator'],
                ['Настройка SNMP', '/settings/cfgsnmp', 'Administrator'],
            ]
        insert_menucfg = "INSERT into menu_cfg(menuname, url, privilage) values (?, ?, ?)"
        insert_cfg = "INSERT into cfg(key, value) values (?, ?)" 
        for n in nb_cfg:
            cursor.execute(insert_cfg, n)

        for s in snmp_cfg:
            cursor.execute(insert_cfg, s)

        for m in menu_cfg:
            cursor.execute(insert_menucfg, m)

        conn.commit()
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
    ''' Класс для работы с БД, с конкретными ОЛТами '''
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

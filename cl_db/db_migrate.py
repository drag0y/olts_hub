import sqlite3
from werkzeug.security import generate_password_hash

class MigrateDB:
    '''
    Обновление базы с 1й версии OLTsHUB до 2й
    '''
    def __init__(self, pathdb):
        self.pathdb = pathdb     


    def updatev1v2(self):
        # Создание новой базы
        conn = sqlite3.connect(self.pathdb)
        cursor = conn.cursor()
        # Удаляем таблицы если есть
        cursor.execute("DROP TABLE IF EXISTS users")
        cursor.execute("DROP TABLE IF EXISTS cfg")
        cursor.execute("DROP TABLE IF EXISTS menu_cfg")

        # Создаём таблицы
        cursor.execute("CREATE TABLE users(id integer primary key autoincrement, login text UNIQUE NOT NULL, password text NOT NULL, privilage text NOT NULL)")
        cursor.execute("CREATE TABLE cfg(id integer primary key autoincrement, key text UNIQUE NOT NULL, value text)")
        cursor.execute("CREATE TABLE menu_cfg(id integer primary key autoincrement, menuname text UNIQUE NOT NULL, url text, privilage text)")

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
            ]
        # Создаём дефолтные настройки для SNMP (как образец)
        snmp_cfg = [
                ['SNMP_READ_H', 'public'],
                ['SNMP_READ_B', 'public'],
                ['SNMP_CONF_H', 'private'],
                ['SNMP_CONF_B', 'private'],
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


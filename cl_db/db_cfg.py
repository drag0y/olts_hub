import sqlite3


class Init_Cfg:
    '''
    Класс для работы с конфигурациями
    '''
    def __init__(self, pathdb):
        self.pathdb = pathdb


    def getcfg(self):
        '''
        Получить словарь со всеми настройками
        '''
        nb_values = {}
        conn = sqlite3.connect(self.pathdb)
        cursor = conn.cursor()

        db_values = cursor.execute('SELECT * FROM cfg;')
        
        for v in db_values:
            values = {
                v[1]: v[2]
            }
            nb_values.update(values)

        conn.close()

        return nb_values


    def insertcfgnb(self, api_key, epon_tag, gpon_tag, urlnb, pl_h, pl_b, pl_c):
        '''
        Редактирование конфигурации NetBox
        '''
        conn = sqlite3.connect(self.pathdb)
        cursor = conn.cursor()
        if api_key:
            cursor.execute(f"UPDATE cfg SET value = '{api_key}' WHERE key = 'API_KEY'")
        if epon_tag:
            cursor.execute(f"UPDATE cfg SET value = '{epon_tag}' WHERE key = 'EPON_TAG'")
        if gpon_tag:
            cursor.execute(f"UPDATE cfg SET value = '{gpon_tag}' WHERE key = 'GPON_TAG'")
        if urlnb:
            cursor.execute(f"UPDATE cfg SET value = '{urlnb}' WHERE key = 'URLNB'")
        if pl_h:
            cursor.execute(f"UPDATE cfg SET value = '{pl_h}' WHERE key = 'PL_H'")
        if pl_b:
            cursor.execute(f"UPDATE cfg SET value = '{pl_b}' WHERE key = 'PL_B'")
        if pl_c:
            cursor.execute(f"UPDATE cfg SET value = '{pl_c}' WHERE key = 'PL_C'")

        conn.commit()
        conn.close()

        return 'Настройки отредактированы.'


    def insercfgsnmp(self, snmp_read_h, snmp_conf_h, snmp_read_b, snmp_conf_b, snmp_read_c, snmp_conf_c):
        '''
        Редактирование конфигурации SNMP
        '''
        conn = sqlite3.connect(self.pathdb)
        cursor = conn.cursor()
        if snmp_read_h:
            cursor.execute(f"UPDATE cfg SET value = '{snmp_read_h}' WHERE key = 'SNMP_READ_H'")
        if snmp_conf_h:
            cursor.execute(f"UPDATE cfg SET value = '{snmp_conf_h}' WHERE key = 'SNMP_CONF_H'")
        if snmp_read_b:
            cursor.execute(f"UPDATE cfg SET value = '{snmp_read_b}' WHERE key = 'SNMP_READ_B'")
        if snmp_conf_b:
            cursor.execute(f"UPDATE cfg SET value = '{snmp_conf_b}' WHERE key = 'SNMP_CONF_B'")
        if snmp_read_c:
            cursor.execute(f"UPDATE cfg SET value = '{snmp_read_c}' WHERE key = 'SNMP_READ_C'")
        if snmp_conf_c:
            cursor.execute(f"UPDATE cfg SET value = '{snmp_conf_c}' WHERE key = 'SNMP_CONF_C'")

        conn.commit()
        conn.close()        

        return 'Настройки отредактированы.'

import re
import sqlite3

from onumonitoring.snmpwalk import SnmpWalk


class BdcomGetOltInfo:
    ''' Класс для работы с ОЛТами BDCOM '''
    def __init__(self, olt_name, olt_ip, snmp_com, pathdb, port_type):
        self.olt_name = olt_name
        self.olt_ip = olt_ip
        self.snmp_com = snmp_com
        self.pathdb = pathdb
        self.port_type = port_type


    def getoltports(self):
        # --- Метод для запроса портов с ОЛТа

        oidoltports = "1.3.6.1.2.1.31.1.1.1.1"
        parseports = r'(?P<portoid>\d+) = STRING: "(?P<ponport>EPON\S+)"'

        conn = sqlite3.connect(self.pathdb)
        cursor = conn.cursor()
        query_ports = "INSERT into ponports(hostname, ip_address, ponport, portoid) values (?, ?, ?, ?)"

        # --- Команда опроса OLTа
        snmpget = SnmpWalk(self.olt_ip, self.snmp_com, oidoltports)
        portslist = snmpget.snmpget()

        for l in portslist:
            match = re.search(parseports, l)
            if match:
                portlist = self.olt_name, self.olt_ip, match.group('ponport'), match.group('portoid')
                cursor.execute(query_ports, portlist)

        conn.commit()
        conn.close()


    def getonulist(self):
        # --- Функция для запроса списка зареганых ONU и парсинг

        oid_epon = "1.3.6.1.4.1.3320.101.10.1.1.3"
        oid_gpon = ""

        parseoutmac = r'(?P<portonu>\d+)=hex-string:(?P<maconu>\S+)'
        parseoutsn = r'(?P<portonu>\d{10}).(?P<onuid>\d+) = (.+: "|.+: )(?P<snonu>(\S+ ){7}\S+|.+(?="))'

        conn = sqlite3.connect(self.pathdb)
        cursor = conn.cursor()

        query = "INSERT into epon(maconu, portonu, idonu, oltip, oltname) values (?, ?, ?, ?, ?)"
        querygpon = "INSERT into gpon(snonu, portonu, idonu, oltip, oltname) values (?, ?, ?, ?, ?)"

        # --- Команда опроса OLTа
        if self.port_type == "epon":
            snmpget = SnmpWalk(self.olt_ip, self.snmp_com, oid_epon)
            onulist = snmpget.snmpget()
        
        if self.port_type == "gpon":
            pass

        # --- Парсинг Мак адресов и добавление в базу
        if self.port_type == "epon":
            for l in onulist:
                match = re.search(parseoutmac, l.replace(" ", "").lower())
                if match:
                    listont = match.group('maconu'), match.group('portonu'), match.group('portonu'), self.olt_ip, self.olt_name
                    cursor.execute(query, listont)

            conn.commit()
            conn.close()

        # --- Парсинг серийников и добавление в базу
        if self.port_type == "gpon":
            pass

import re
import sqlite3

from onumonitoring.snmpwalk import SnmpWalk


class HuaweiGetOltInfo:
    ''' Класс для работы с ОЛТами Huawei '''
    def __init__(self, olt_name, olt_ip, snmp_com, pathdb, port_type):
        self.olt_name = olt_name
        self.olt_ip = olt_ip
        self.snmp_com = snmp_com
        self.pathdb = pathdb
        self.port_type = port_type


    def getoltports(self):
        # Запрос портов с ОЛТа

        snmp_oid = "1.3.6.1.2.1.31.1.1.1.1"
        parseout = r'(?P<portoid>\d{10}).+ (?P<ponport>\d+\/\d+\/\d+)'

        conn = sqlite3.connect(self.pathdb)
        cursor = conn.cursor()
        query_ports = "INSERT into ponports(hostname, ip_address, ponport, portoid) values (?, ?, ?, ?)"

        snmpget = SnmpWalk(self.olt_ip, self.snmp_com, snmp_oid)
        oltportslist = snmpget.snmpget()

        # Парсинг Мак адресов и добавление в базу
        for l in oltportslist:
            match = re.search(parseout, l)

            if match:
                portlist = self.olt_name, self.olt_ip, match.group('ponport'), match.group('portoid')
                cursor.execute(query_ports, portlist)

        conn.commit()
        conn.close()


    def getonulist(self):
        # --- Функция для запроса списка зареганых ONU и парсинг

        snmp_epon = "1.3.6.1.4.1.2011.6.128.1.1.2.53.1.3"
        snmp_gpon = "1.3.6.1.4.1.2011.6.128.1.1.2.43.1.3"

        parseout = r'(?P<portonu>\d{10}).(?P<onuid>\d+)=\S+:(?P<maconu>\S+)'
        parseoutsn = r'(?P<portonu>\d{10}).(?P<onuid>\d+) = (.+: "|.+: )(?P<snonu>(\S+ ){7}\S+|.+(?="))'

        conn = sqlite3.connect(self.pathdb)
        cursor = conn.cursor()
        query = "INSERT into epon(maconu, portonu, idonu, oltip, oltname) values (?, ?, ?, ?, ?)"
        querygpon = "INSERT into gpon(snonu, portonu, idonu, oltip, oltname) values (?, ?, ?, ?, ?)"

        # --- Команда опроса OLTа
        if self.port_type == "epon":
            snmpget = SnmpWalk(self.olt_ip, self.snmp_com, snmp_epon)
            onulist = snmpget.snmpget()
           
        elif self.port_type == "gpon":
            snmpget = SnmpWalk(self.olt_ip, self.snmp_com, snmp_gpon)
            onulist = snmpget.snmpget()

        # --- Парсинг Мак адресов и добавление в базу
        if self.port_type == "epon":
            for l in onulist:
                match = re.search(parseout, l.replace(" ", "").lower())
                if match:
                    listont = match.group('maconu'), match.group('portonu'), match.group('onuid'), self.olt_ip, self.olt_name
                    cursor.execute(query, listont)
            conn.commit()
            conn.close()

        # --- Парсинг серийников и добавление в базу
        if self.port_type == "gpon":
            try:
                for l in onulist:
                    match = re.search(parseoutsn, l.replace('\\"', '"').replace("\\\\", "\\"))
                    if match:
                        if len(match.group('snonu')) > 16:
                            listont = match.group('snonu').lower().replace(" ", ""), match.group('portonu'), match.group('onuid'), self.olt_ip, self.olt_name
                            cursor.execute(querygpon, listont)
                        elif len(match.group('snonu')) < 16:
                            listont = match.group('snonu').encode().hex(), match.group('portonu'), match.group('onuid'), self.olt_ip, self.olt_name
                            cursor.execute(querygpon, listont)
            except ValueError:
                print("Кривая ONU")

            conn.commit()
            conn.close()

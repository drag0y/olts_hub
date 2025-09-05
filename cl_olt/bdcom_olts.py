import re
import sqlite3

from cl_other.snmpwalk import SnmpWalk
from funcs.hextodec import convert


class BdcomGetOltInfo:
    '''
    Класс для работы с ОЛТами BDCOM
    '''
    def __init__(self, olt_name, olt_ip, snmp_com, pathdb, pontype):
        self.olt_name = olt_name
        self.olt_ip = olt_ip
        self.snmp_com = snmp_com
        self.pathdb = pathdb
        self.pontype = pontype


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
        if self.pontype == "epon":
            snmpget = SnmpWalk(self.olt_ip, self.snmp_com, oid_epon)
            onulist = snmpget.snmpget()
        
        if self.pontype == "gpon":
            pass

        # --- Парсинг Мак адресов и добавление в базу
        if self.pontype == "epon":
            for l in onulist:
                match = re.search(parseoutmac, l.replace(" ", "").lower())
                if match:
                    listont = match.group('maconu'), match.group('portonu'), match.group('portonu'), self.olt_ip, self.olt_name
                    cursor.execute(query, listont)

            conn.commit()
            conn.close()

        # --- Парсинг серийников и добавление в базу
        if self.pontype == "gpon":
            pass


    def ponstatustree(self, port_oid):
        '''
        Статус и уровни с дерева (порта) ОЛТа BDCOM
        '''
        if "epon" in self.pontype:
            oid_state = "1.3.6.1.2.1.2.2.1.8"
            oid_down_reason = "1.3.6.1.4.1.3320.101.11.1.1.11"
            oid_rx_onu = "1.3.6.1.4.1.3320.101.10.5.1.5"
            oid_rx_olt = "1.3.6.1.4.1.3320.101.108.1.3"
        if "gpon" in self.pontype:
            oid_state = "-"
            oid_cose = "-"

        parse_state = r'INTEGER: (?P<onustate>\d+|-\d+)'
        parse_down = r'(\d+){10}.(?P<onuid>\S+) .+INTEGER: (?P<downcose>\d+|-\d+)'
        parse_tree = r'INTEGER: (?P<level>.+)'

        # ---- Ищем порт олта
        conn = sqlite3.connect(self.pathdb)
        cursor = conn.cursor()
        sqlgetport = f'SELECT * FROM ponports WHERE ip_address="{self.olt_ip}" AND portoid like "{port_oid}";'
        ponportonu = cursor.execute(sqlgetport)

        portonu_out = "Не удалось определить порт"
        for portonu in ponportonu:
            portonu_out = portonu[3]

        sqlgetallonu = f'SELECT * FROM ponports WHERE ip_address="{self.olt_ip}" AND ponport like "{portonu_out}:%";'
        getallonu = cursor.execute(sqlgetallonu)

        oltportinfo = []
        for onu in getallonu:
        # Делаем список со словарями в которых пон порт с индексом ону, oid порта
            oltportinfo.append(
                            {
                            'ponport': onu[3],
                            'portoid': onu[4], 
                            }
                        )
        db_onuinfo = []
        for o in oltportinfo:
            # Создаём список со словарями, в которых информация об ОНУ из БД
            onuid = o['ponport'].split(':')[1]
            ponport = o['ponport'].split(':')[0]
            sqlgetonu = f'''SELECT * FROM {self.pontype} WHERE oltip="{self.olt_ip}" AND portonu="{o['portoid']}";'''
            getonu = cursor.execute(sqlgetonu)

            for ol in getonu:
                db_onuinfo.append(
                            {
                            'id' :     onuid,
                            'onu':     ol[1],
                            'ponport': ponport,
                            "portoid": o['portoid'], 
                            }
                        )
        conn.close()

        # Получаем статус с дерева
        out_tree = []
        for oi in db_onuinfo:
            # Перебираем список и по очереди опрашиваем ОНУ
            onustateoid = f'''{oid_state}.{oi['portoid']}'''
            snmpget = SnmpWalk(self.olt_ip, self.snmp_com, onustateoid)
            onustate = snmpget.snmpget()

            status_tree = []
            for s in onustate:
                # Опрашиваем статус ОНУ
                match = re.search(parse_state, s)
                if match:
                    onustatus = match.group('onustate')
                    onustatus = onustatus.replace("1", "ONLINE").replace("2", "OFFLINE").replace("-1", "OFFLINE")
                    if onustatus == 'OFFLINE':
                        # Если ОНУ не в сети, выясняем причину
                        parse_down_reason = r'(?P<onudec>\d+.\d+.\d+.\d+.\d+.\d+) = INTEGER: (?P<downreason>\d+)'
                        # Конвертируем HEX формат ОНУ в десятичный 
                        onudec = convert(oi['onu'])
                        onudownreasonoid = f'{oid_down_reason}.{port_oid}{onudec}'
                        snmpget = SnmpWalk(self.olt_ip, self.snmp_com, onudownreasonoid)
                        onudownreason = snmpget.snmpget()
                        for l in onudownreason:
                            match = re.search(parse_down_reason, l)
                            if match:
                                onu = match.group('onudec')
                                onudownreason = match.group('downreason')
                                onustatus = onudownreason.replace("8", "LOS").replace("9", "POWER-OFF").replace("0", "Неизвестно")
                            else:
                                onustatus = 'Неизвестно'
                        rx_onu = 0.00
                        rx_olt = 0.00
                                
                    elif onustatus == 'ONLINE':
                        # Если ОНУ в сети, смотрим уровни сигналов
                        rxonuoid = f'''{oid_rx_onu}.{oi['portoid']}'''
                        rxoltoid = f'''{oid_rx_olt}.{oi['portoid']}'''
                        snmpget = SnmpWalk(self.olt_ip, self.snmp_com, rxonuoid)
                        rxonu = snmpget.snmpget()
                        for l in rxonu:
                            match = re.search(parse_tree, l)
                            if match:
                                level_onu = match.group('level')
                                rx_onu = int(level_onu)/10
                            else:
                                rx_onu = 0.00

                        snmpget = SnmpWalk(self.olt_ip, self.snmp_com, rxoltoid)
                        rxolt = snmpget.snmpget()        
                        for l in rxolt:
                            match = re.search(parse_tree, l)
                            if match:
                                level_olt = match.group('level')
                                rx_olt = int(level_olt)/10
                            else:
                                rx_olt = 0.00

                else:
                    onustatus = 'Удалена, опросите ОЛТ'
                    rx_onu = 0.00
                    rx_olt = 0.00

                out_tree.append(
                            {
                            'id':         oi['id'],
                            'onu':        oi['onu'],
                            'onu_status': onustatus,
                            'rx_onu':     rx_onu,
                            'rx_olt':     rx_olt,
                            }
                        )
            
        return out_tree

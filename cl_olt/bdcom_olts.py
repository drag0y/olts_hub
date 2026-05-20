import re
import sqlite3

from cl_other.snmpwalk import SnmpWalk
from funcs.hextodec import convert
from db_services.db_ports import PortsServiceDb
from db_services.db_onu import OnuServiceDb
from cl_olt.oltbase import GetOltInfoBase


class BdcomGetOltInfo(GetOltInfoBase):
    '''
    Класс для работы с ОЛТами BDCOM
    '''
    def __init__(self, olt_name, olt_ip, snmp_com, pontype):
        self.olt_name = olt_name
        self.olt_ip = olt_ip
        self.snmp_com = snmp_com
        self.pontype = pontype


    def getoltports(self):
        '''
        Метод для запроса портов с ОЛТа
        '''
        ports = []
        oidoltports = "1.3.6.1.2.1.31.1.1.1.1"
        parseports = r'(?P<portoid>\d+) = STRING: "(?P<ponport>EPON\S+)"'
        parseportsgpon = r'(?P<portoid>\d+) = STRING: "(?P<ponport>GPON\S+)"'

        # --- Команда опроса OLTа
        snmpget = SnmpWalk(self.olt_ip, self.snmp_com, oidoltports)
        portslist = snmpget.snmpget()

        for l in portslist:
            match = re.search(parseports, l)
            match2 = re.search(parseportsgpon, l)
            if match:
                port = {
                    'pon_port': match.group('ponport'),
                    'port_oid': match.group('portoid'),
                }
                ports.append(port)
                
            elif match2:
                port = {
                    'pon_port': match2.group('ponport'),
                    'port_oid': match2.group('portoid'),
                }
                ports.append(port)
        
        return ports


    def getonulist(self):
        '''
        Метод для запроса списка зареганых ONU и парсинг
        '''
        onu_list = []
        oid_epon = "1.3.6.1.4.1.3320.101.10.1.1.3"
        oid_gpon = "1.3.6.1.4.1.3320.10.3.1.1.4"

        parseoutmac = r'(?P<portonu>\d+)=hex-string:(?P<maconu>\S+)'
        parseoutsn = r'(?P<portonu>\d+)=string:(?P<snonu>\S+)'

        # --- Команда опроса OLTа
        if self.pontype == "epon":
            snmpget = SnmpWalk(self.olt_ip, self.snmp_com, oid_epon)
            onulist = snmpget.snmpget()

        elif self.pontype == "gpon":
            snmpget = SnmpWalk(self.olt_ip, self.snmp_com, oid_gpon)
            onulist = snmpget.snmpget()

        # --- Парсинг Мак адресов и добавление в базу
        if self.pontype == "epon":
            for l in onulist:
                match = re.search(parseoutmac, l.replace(" ", "").lower())
                if match:
                    onu = {
                        'onu': match.group('maconu'),
                        'port_oid': match.group('portonu'),
                        'onu_oid': match.group('portonu'),
                    }
                    onu_list.append(onu)
            
            return onu_list

        # --- Парсинг серийников и добавление в базу
        elif self.pontype == "gpon":
            for l in onulist:               
                match = re.search(parseoutsn, l.replace(" ", "").replace('"', '').lower())
                if match:
                    onu = {
                        'onu': match.group('snonu'),
                        'port_oid': match.group('portonu'),
                        'onu_oid': match.group('portonu'),
                    }
                    onu_list.append(onu)
            
            return onu_list


    def ponstatustree(self, olt_id, port_oid):
        '''
        Статус и уровни с дерева (порта) ОЛТа BDCOM
        '''
        if "epon" in self.pontype:
            oid_state = "1.3.6.1.2.1.2.2.1.8"
            oid_down_reason = "1.3.6.1.4.1.3320.101.11.1.1.11"
            oid_rx_onu = "1.3.6.1.4.1.3320.101.10.5.1.5"
            oid_rx_olt = "1.3.6.1.4.1.3320.101.108.1.3"
        if "gpon" in self.pontype:
            oid_state = "1.3.6.1.2.1.2.2.1.8"
            oid_down_reason = "1.3.6.1.4.1.3320.10.3.1.1.35"
            oid_rx_onu = "1.3.6.1.4.1.3320.10.3.4.1.2"
            oid_rx_olt = "1.3.6.1.4.1.3320.10.2.3.1.3"

        parse_state = r'INTEGER: (?P<onustate>\d+|-\d+)'
        parse_down_reason = r'(?P<onudec>\d+.\d+.\d+.\d+.\d+.\d+) = INTEGER: (?P<downreason>\d+)'
        parse_tree = r'INTEGER: (?P<level>.+)'

        # ---- Ищем порт олта
        onuonport = PortsServiceDb()
        portinfo = onuonport.find_port_by_oid(olt_id, port_oid)
        for p in portinfo:
            portonu_out = p.pon_port

        onuonport = PortsServiceDb()
        getallonu = onuonport.find_port(olt_id, f"{portonu_out}:%")

        oltportinfo = []
        for onu in getallonu:
            
        # Делаем список со словарями в которых пон порт с индексом ону, oid порта
            oltportinfo.append(
                {
                    'ponport': onu.pon_port,
                    'portoid': onu.port_oid, 
                }
            )
        db_onuinfo = []

        for o in oltportinfo:
            # Создаём список со словарями, в которых информация об ОНУ из БД
            onuid = o['ponport'].split(':')[1]
            ponport = o['ponport'].split(':')[0]

            sqlgetonu = OnuServiceDb()
            getonu = sqlgetonu.find_onu_on_port(olt_id, o['portoid'])

            for ol in getonu:
                db_onuinfo.append(
                    {
                    'id' :     onuid,
                    'onu':     ol['onu'],
                    'ponport': ponport,
                    "portoid": o['portoid'], 
                    }
                )

        # Получаем статус с дерева
        out_tree = []
        for oi in db_onuinfo:
            # Перебираем список и по очереди опрашиваем ОНУ
            onustateoid = f'''{oid_state}.{oi['portoid']}'''
            snmpget = SnmpWalk(self.olt_ip, self.snmp_com, onustateoid)
            onustate = snmpget.snmpget()

            for s in onustate:
                # Опрашиваем статус ОНУ
                match = re.search(parse_state, s)
                if match:
                    onustatus = match.group('onustate')
                    onustatus = onustatus.replace("1", "ONLINE").replace("2", "OFFLINE").replace("-1", "OFFLINE")
                    if onustatus == 'OFFLINE':
                        # Если ОНУ не в сети, выясняем причину
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


    def oltuptime(self):
        '''
        Метод определяет UpTime ОЛТа
        '''
        uptime = ''
        parse_uptime = r'\) (?P<uptime>\d+ days, \d+:\d+:\d+)'
        oid_uptime = '1.3.6.1.2.1.1.3.0'

        snmpget = SnmpWalk(self.olt_ip, self.snmp_com, oid_uptime)
        onulist = snmpget.snmpget()

        for u in onulist:
            match = re.search(parse_uptime, u)
            if match:
                uptime = match.group('uptime')

        return uptime
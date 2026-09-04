import re

from services.snmpwalk import SnmpWalk
from db_services.db_onu import OnuServiceDb
from db_services.db_ports import PortsServiceDb
from cl_olt.oltbase import GetOltInfoBase


class HuaweiGetOltInfo(GetOltInfoBase):
    '''
    Класс для работы с ОЛТами Huawei
    '''
    def __init__(self, olt_name, olt_ip, snmp_com, pontype, snmp_wr = ''):
        self.olt_name = olt_name
        self.olt_ip = olt_ip
        self.snmp_com = snmp_com
        self.pontype = pontype
        self.snmp_wr = snmp_wr


    def getoltports(self):
        '''
        Метод запрашивает порты с ОЛТа
        '''
        ports = []
        snmp_oid = "1.3.6.1.2.1.31.1.1.1.1"
        parseout = r'(?P<portoid>\d{10}).+ (?P<pontype>.+) (?P<ponport>\d+\/\d+\/\d+)'

        snmpget = SnmpWalk(self.olt_ip, self.snmp_com, snmp_oid)
        oltportslist = snmpget.snmpget()

        # Парсинг Мак адресов и добавление в базу
        for p in oltportslist:
            match = re.search(parseout, p)
            if match:
                port = {
                    'pon_port': match.group('ponport'),
                    'pon_type': match.group('pontype').replace(' ', '').replace('"', '').lower(),
                    'port_oid': match.group('portoid'),
                }
                ports.append(port)

        return ports
    
    
    def getonulist(self):
        # --- Функция для запроса списка зареганых ONU и парсинг
        onulist = []
        result = []
        onulistoid = {
            'epon': '1.3.6.1.4.1.2011.6.128.1.1.2.53.1.3',
            'gpon': '1.3.6.1.4.1.2011.6.128.1.1.2.43.1.3',
        }

        parsemac = r'(?P<portonu>\d{10}).(?P<onuid>\d+)=\S+:(?P<maconu>\S+)'
        parsesn = r'(?P<portonu>\d{10}).(?P<onuid>\d+) = (.+: "|.+: )(?P<snonu>(\S+ ){7}\S+|.+(?="))'

        # --- Команда опроса OLTа
        if 'epon' in self.pontype:
            onulistoid = [onulistoid['epon']]
        elif 'gpon' in self.pontype:
            onulistoid = [onulistoid['gpon']]
        elif 'xpon' in self.pontype:
            onulistoid = [onulistoid['epon'], onulistoid['gpon']]
        
        for oid in onulistoid:
            snmpget = SnmpWalk(self.olt_ip, self.snmp_com, oid).snmpget()
            onulist.extend(snmpget)

        try:
            for l in onulist:
                # --- Парсинг серийников и добавление в базу
                match = re.search(parsesn, l.replace('\\"', '"').replace("\\\\", "\\"))
                if match:
                    if len(match.group('snonu')) > 16:
                        onu = {
                            'onu': match.group('snonu').lower().replace(" ", ""),
                            'port_oid': match.group('portonu'),
                            'onu_oid': match.group('onuid'),
                        }
                        result.append(onu)
                        
                    # Если серийник кривой, то из строки его надо распарсить в hex формат
                    elif len(match.group('snonu')) < 16:
                        onu = {
                            'onu': match.group('snonu').encode().hex(),
                            'port_oid': match.group('portonu'),
                            'onu_oid': match.group('onuid'),
                        }
                        result.append(onu)

                # --- Парсинг Мак адресов и добавление в базу
                match2 = re.search(parsemac, l.replace(" ", "").lower())
                if match2:
                    if len(match2.group('maconu')) == 12:
                        onu = {
                            'onu': match2.group('maconu'),
                            'port_oid': match2.group('portonu'),
                            'onu_oid': match2.group('onuid'),
                        }
                        result.append(onu)
                        
        except ValueError:
            print("Кривая ONU")

        return result


    def ponstatustree(self, olt_id, port_oid):
        '''
        Метод для построение статуса и уровней с дерева Huawei
        '''
        parse_state = r'(\d+){10}.(?P<onuid>\S+) .+INTEGER: (?P<onustate>\d+|-\d+)'
        parse_down = r'(\d+){10}.(?P<onuid>\S+) .+INTEGER: (?P<downcose>\d+|-\d+)'
        parse_tree =  r'(\d+){10}.(?P<onuid>\S+) = INTEGER: (?P<treelevel>\S+)' # r'(\d+){10}.(?P<onuid>\S+) .+(?P<treelevel>-\S+)'
        parse_tree_rx_olt = r'(\d+){10}.(?P<onuid>\S+) .+INTEGER: (?P<treelevel>\d+)'
        parse_descr = r'(\d+){10}.(?P<onuid>\S+) = STRING: "(?P<onudescr>\S+)"'
        parse_downtime = r'(\d+){10}.(?P<onuid>\S+) = Hex-STRING: (?P<downtime>.+)'

        if "xpon" in self.pontype:
            ponport = PortsServiceDb().find_port_by_oid(olt_id, port_oid)
            for p in ponport:
                self.pontype = p.pon_type

        if "epon" in self.pontype:
            oid_rx_onu = "1.3.6.1.4.1.2011.6.128.1.1.2.104.1.5"
            oid_rx_olt = "1.3.6.1.4.1.2011.6.128.1.1.2.104.1.1"
            oid_state = "1.3.6.1.4.1.2011.6.128.1.1.2.57.1.15"
            oid_cose = "1.3.6.1.4.1.2011.6.128.1.1.2.57.1.25"
            oid_onu_descr = "1.3.6.1.4.1.2011.6.128.1.1.2.53.1.9"
            downtimeoid = "1.3.6.1.4.1.2011.6.128.1.1.2.57.1.24"

        elif "gpon" in self.pontype:
            oid_rx_onu = "1.3.6.1.4.1.2011.6.128.1.1.2.51.1.4"
            oid_rx_olt = "1.3.6.1.4.1.2011.6.128.1.1.2.51.1.6"
            oid_state = "1.3.6.1.4.1.2011.6.128.1.1.2.46.1.15"
            oid_cose = "1.3.6.1.4.1.2011.6.128.1.1.2.46.1.24"
            oid_onu_descr = "1.3.6.1.4.1.2011.6.128.1.1.2.43.1.9"
            downtimeoid = "1.3.6.1.4.1.2011.6.128.1.1.2.46.1.23"

        # Собираем список со всеми ОНУ находящимися на порту ОЛТа
        onuonport = OnuServiceDb()
        db_onuinfo = onuonport.find_onu_on_port(olt_id, port_oid)

        # Определяем причину отключени всех ону на пон порту
        onudownreasonoid = f'{oid_cose}.{port_oid}'
        snmpget = SnmpWalk(self.olt_ip, self.snmp_com, onudownreasonoid)
        onudownreason = snmpget.snmpget()

        down_reason = {}
        for l in onudownreason:
            match = re.search(parse_down, l)
            if match:
                onuid = match.group('onuid')
                downreason = match.group('downcose')
                downreason = downreason.replace("-1", "Неизвестно") \
                                       .replace("18", "RING") \
                                       .replace("13", "POWER-OFF") \
                                       .replace("2", "LOS") \
                                       .replace("1", "LOS") \
                                       .replace("3", "LOS") \
                                       .replace("9", "ADMIN-RESET")
                
                down_reason.setdefault(onuid)
                down_reason.update({onuid: {'down_reason': downreason}})

        # Определяем статус (в сети/не в сети) всех ОНУ на пон порту
        onustateoid = f'{oid_state}.{port_oid}'
        snmpget = SnmpWalk(self.olt_ip, self.snmp_com, onustateoid)
        onustate = snmpget.snmpget()

        status_onu = {}
        for l in onustate:
            match = re.search(parse_state, l)
            if match:
                onuid = match.group('onuid')
                onustatus = match.group('onustate')
                onustatus = onustatus.replace("1", "ONLINE") \
                                     .replace("2", "OFFLINE") \
                                     .replace("-1", "OFFLINE")

                status_onu.setdefault(onuid)
                if onustatus == 'OFFLINE':
                    onustatus = down_reason[onuid]['down_reason']
                    status_onu.update({onuid: {'status': onustatus}})
                else:
                    status_onu.update({onuid: {'status': onustatus}})
        
        # Смотрим уровни со всего пон порта в сторону ОНУ (rxonu)
        rx_onu = {}
        rxonuoid = f'{oid_rx_onu}.{port_oid}'
        snmpget = SnmpWalk(self.olt_ip, self.snmp_com, rxonuoid)
        getrxonu = snmpget.snmpget()

        for l in getrxonu:
            match = re.search(parse_tree, l)
            if match:
                onuid = match.group('onuid')
                level = match.group('treelevel')
                level_rx = int(level)/100
        
                rx_onu.setdefault(onuid)
                rx_onu.update({onuid: {'rxonu': float(level_rx)}})
                            
        # Смотрим уровни со всего пон порта в сторону ОЛТа (rxolt)
        rx_olt = {}
        rxoltoid = f'{oid_rx_olt}.{port_oid}'
        snmpget = SnmpWalk(self.olt_ip, self.snmp_com, rxoltoid)
        rxolt = snmpget.snmpget()

        for l in rxolt:
            match = re.search(parse_tree_rx_olt, l)
            if match:
                onuid = match.group('onuid')
                level = match.group('treelevel')
                if len(level) == 4:
                    level_rx = int(level)/100-100
                    level_rx = format(level_rx, '.2f')

                    rx_olt.setdefault(onuid)
                    rx_olt.update({onuid: {'rxolt': float(level_rx)}})


        # Смотрим дескрипшены ОНУ со всего пон порта
        descr_onu = {}
        descronuoid = f'{oid_onu_descr}.{port_oid}'
        snmpget = SnmpWalk(self.olt_ip, self.snmp_com, descronuoid)
        descronu = snmpget.snmpget()

        for d in descronu:
            match = re.search(parse_descr, d)
            if match:
                onuid = match.group('onuid')
                onudescr = match.group('onudescr')

                descr_onu.setdefault(onuid)
                descr_onu.update({onuid: {'descr': onudescr}})

        # Смотрим время отключения ОНУ
        timedown_onu = {}
        timedownonuoid = f'{downtimeoid}.{port_oid}'
        snmpget = SnmpWalk(self.olt_ip, self.snmp_com, timedownonuoid)
        downtime = snmpget.snmpget()

        for d in downtime:
            match = re.search(parse_downtime, d)
            if match:
                onuid = match.group('onuid')
                downtime = match.group('downtime')
                
                b = [int(x, 16) for x in downtime.split()]
                year = (b[0] << 8) | b[1]

                out_downtime = (
                    f"{year:04d}-{b[2]:02d}-{b[3]:02d} "
                    f"{b[4]:02d}:{b[5]:02d}:{b[6]:02d}"
                )

                timedown_onu.setdefault(onuid)
                timedown_onu.update({onuid: {'down_time': out_downtime}})        

        # Перебираем список ОНУ из БД, и создаем список со словарями с метриками
        out_tree=[]    
        for onu in db_onuinfo:
            if status_onu[onu['id']]['status'] == 'ONLINE':
                out_tree.append(
                    {
                    'id':         onu['id'],
                    'onu':        onu['onu'],
                    'descr':      descr_onu[onu['id']]['descr'],
                    'onu_status': status_onu[onu['id']]['status'],
                    'down_time':  '',
                    'rx_onu':     rx_onu[onu['id']]['rxonu'],
                    'rx_olt':     rx_olt[onu['id']]['rxolt'],
                    }
                )
            else:
                out_tree.append(
                    {
                    'id':         onu['id'],
                    'onu':        onu['onu'],
                    'descr':      descr_onu[onu['id']]['descr'],
                    'onu_status': status_onu[onu['id']]['status'],
                    'down_time':  timedown_onu[onu['id']]['down_time'],
                    'rx_onu':     0.00,
                    'rx_olt':     0.00,
                    }
                )

        return out_tree


    def unregonu(self, oltid):
        '''
        Метод проверяет есть ли на ОЛТе не зарегистрированные ОНУ
        '''
        result = []
        onulist = []
        unregoid = {
            'epon': '1.3.6.1.4.1.2011.6.128.1.1.2.58.1.2',
            'gpon': '1.3.6.1.4.1.2011.6.128.1.1.2.48.1.2',
        }

        if 'epon' in self.pontype:
            unregoid = [unregoid['epon']]
        elif 'gpon' in self.pontype:
            unregoid = [unregoid['gpon']]
        elif 'xpon' in self.pontype:
            unregoid = [unregoid['epon'], unregoid['gpon']]
            
        parse_onu = "(?P<portoid>\d{10}).+ Hex-STRING: (?P<onu>.+)"

        for oid in unregoid:
            snmpget = SnmpWalk(self.olt_ip, self.snmp_com, oid).snmpget()
            onulist.extend(snmpget)
            
        for l in onulist:
            match = re.search(parse_onu, l)
            if match:
                unreg_onu = match.group('onu').replace(' ', '')
                oltport_oid = match.group('portoid')

                ponport = PortsServiceDb().find_port_by_oid(oltid, oltport_oid)
                for p in ponport:
                    oltport = p.pon_port

                onudict = {
                    'mac': unreg_onu,
                    'oltport': oltport,
                }
                result.append(onudict)

        return result
    

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
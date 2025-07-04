import sqlite3
import re
import os
from sqlalchemy import create_engine, text

from onumonitoring.bdcom_onu import BdcomGetOnuInfo
from onumonitoring.huawei_onu import HuaweiGetOnuInfo
from onumonitoring.snmpwalk import SnmpWalk
from dotenv import load_dotenv


load_dotenv()

SNMP_READ_H = os.getenv('SNMP_READ_H')
SNMP_READ_B = os.getenv('SNMP_READ_B')
SNMP_CONF_H = os.getenv('SNMP_CONF_H')
SNMP_CONF_B = os.getenv('SNMP_CONF_B')
PF_HUAWEI = os.getenv('PF_HUAWEI')
PF_BDCOM = os.getenv('PF_BDCOM')


class OltInfo:
    """
    Класс для поиска ОЛТа, и определения состояния
    """
    def __init__(self, pathdb, olt_ip, olt_port, platform, pontype):

        self.olt_ip = olt_ip
        self.olt_port = olt_port
        self.pathdb = pathdb
        self.platform = platform
        self.pontype = pontype
        
        # ---- Подключение к базе и поиск ОЛТа
        conn = sqlite3.connect(self.pathdb)
        cursor = conn.cursor()
       
        ponport = cursor.execute(f'SELECT * FROM ponports WHERE ip_address="{self.olt_ip}" AND ponport LIKE "{self.olt_port}";')
             
        for p in ponport:
            self.hostname = p[1]
            self.port_oid = p[4]
        
        conn.close()


    def hwponstatustree(self):
        ''' Определение статуса всего дерева (порта) на ОЛТе Huawei '''

        onulist = []
        statuslist = []
#        out_tree2 = []
        downlist = []
        tree_in = []
        tree_out = []
        onulist2 = []
        status_tree = {}

        parse_state = r'(\d+){10}.(?P<onuid>\S+) .+INTEGER: (?P<onustate>\d+|-\d+)'
        parse_down = r'(\d+){10}.(?P<onuid>\S+) .+INTEGER: (?P<downcose>\d+|-\d+)'
        parse_tree = r'(\d+){10}.(?P<onuid>\S+) .+(?P<treelevel>-\S+)'

        if "epon" in self.pontype:
            oid_rx_onu = "1.3.6.1.4.1.2011.6.128.1.1.2.104.1.5"
            oid_rx_olt = "1.3.6.1.4.1.2011.6.128.1.1.2.104.1.1"
            oid_state = "1.3.6.1.4.1.2011.6.128.1.1.2.57.1.15"
            oid_cose = "1.3.6.1.4.1.2011.6.128.1.1.2.57.1.25"

        if "gpon" in self.pontype:
            oid_rx_onu = "1.3.6.1.4.1.2011.6.128.1.1.2.51.1.4"
            oid_rx_olt = "1.3.6.1.4.1.2011.6.128.1.1.2.51.1.6"
            oid_state = "1.3.6.1.4.1.2011.6.128.1.1.2.46.1.15"
            oid_cose = "1.3.6.1.4.1.2011.6.128.1.1.2.46.1.24"


    # ---- Ищем в базе мак ОНУ для сопоставления с индексами
        onureplace = {}

        conn = sqlite3.connect(self.pathdb)
        cursor = conn.cursor()

        onureplace_in = cursor.execute(f'SELECT * FROM {self.pontype} WHERE oltip="{self.olt_ip}" AND portonu="{self.port_oid}";')
        onu_count = 0

        for onu in onureplace_in:
            onu_count += 1
            indexonu_out = onu[3]
            onu_out = onu[1]

            onureplace.setdefault(indexonu_out)
            onureplace.update({indexonu_out: onu_out})

        if PF_HUAWEI: #in self.platform and "gpon" in self.pontype:
            '''
            Получение статуса с дерева
            '''
            onustateoid = f'{oid_state}.{self.port_oid}'
            snmpget = SnmpWalk(self.olt_ip, SNMP_READ_H, onustateoid)
            onustate = snmpget.snmpget()
            for l in onustate:
                match = re.search(parse_state, l)
                if match:
                    onuid = match.group('onuid')
                    onustatus = match.group('onustate')
                    onustatus = onustatus.replace("1", "ONLINE").replace("2", "OFFLINE").replace("-1", "OFFLINE")

                    onulist.append(onuid)
                    statuslist.append(onustatus)

            onudownreasonoid = f'{oid_cose}.{self.port_oid}'
            snmpget = SnmpWalk(self.olt_ip, SNMP_READ_H, onudownreasonoid)
            onudownreason = snmpget.snmpget()
            for l in onudownreason:
                match = re.search(parse_down, l)
                if match:
                    downcose = match.group('downcose')
                    downcose = downcose.replace("-1", "Неизвестно").replace("18", "RING").replace("13", "POWER-OFF").replace("2", "LOS").replace("1", "LOS").replace("3", "LOS")
                    downlist.append(downcose)

        # ----
            for i in range(len(onulist)):
                onu = str(onulist[i])
                onudown = str(downlist[i])
                if statuslist[i] == "OFFLINE":
                    statuslist[i] = statuslist[i].replace("OFFLINE", onudown)

#                out_tree2.append(str(onureplace[onu]) + " ; " + str(statuslist[i]))

                status_tree.setdefault(onureplace[onu])
                status_tree.update({onureplace[onu]: {'onustatus': statuslist[i], 'levelin': '0', 'levelout': '0'}})

        # ---- Получение уровня сигнала в сторону ОНУ
        rxonuoid = f'{oid_rx_onu}.{self.port_oid}'
        snmpget = SnmpWalk(self.olt_ip, SNMP_READ_H, rxonuoid)
        rxonu = snmpget.snmpget()

        for l in rxonu:
            match = re.search(parse_tree, l)
            if match:
                onuid = match.group('onuid')
                level = match.group('treelevel')
                level_rx = int(level)/100

                onulist2.append(onuid)
                tree_in.append(level_rx)

        # ---- Получение результата уровня в сторону ОЛТа
        parse_tree_sn = r'(\d+){10}.(?P<onuid>\S+) .+INTEGER: (?P<treelevel>\d+)'
        rxoltoid = f'{oid_rx_olt}.{self.port_oid}'
        snmpget = SnmpWalk(self.olt_ip, SNMP_READ_H, rxoltoid)
        rxolt = snmpget.snmpget()

        for l in rxolt:
            match = re.search(parse_tree_sn, l)
            if match:
                onuid = match.group('onuid')
                level = match.group('treelevel')
                if len(level) == 4:
                    level_tx2 = int(level)/100-100
                    level_tx = format(level_tx2, '.2f')

                    tree_out.append(level_tx)
        
        for i in range(len(onulist2)):
            onu = str(onulist2[i])
            status_tree.update({onureplace[onu]: {'onustatus': 'ONLINE', 'levelin': tree_in[i], 'levelout': tree_out[i]}})

        return status_tree


    def bdcomponstatustree(self):
        ''' Статус и уровни с дерева (порта) ОЛТа BDCOM '''

        status_tree = {}
        onulist = []
        statuslist = []
        downlist = []

        onustatus = ""
        downcose = ""

        tree_in = []
        tree_out = []
        level_rx = ""
        level_tx = ""

        if "epon" in self.pontype:
            oid_state = "1.3.6.1.2.1.2.2.1.8"
            oid_cose = "1.3.6.1.4.1.3320.101.11.1.1.11"
            snmp_rx_onu = "1.3.6.1.4.1.3320.101.10.5.1.5"
            snmp_rx_olt = "1.3.6.1.4.1.3320.101.108.1.3"
        if "gpon" in self.pontype:
            oid_state = "-"
            oid_cose = "-"

        parse_state = r'INTEGER: (?P<onustate>\d+|-\d+)'
        parse_down = r'(\d+){10}.(?P<onuid>\S+) .+INTEGER: (?P<downcose>\d+|-\d+)'
        parse_tree = r'INTEGER: (?P<level>.+)'

        # ---- Ищем порт олта
        conn = sqlite3.connect(self.pathdb)
        cursor = conn.cursor()
        sqlgetport = f'SELECT * FROM ponports WHERE ip_address="{self.olt_ip}" AND portoid like "{self.port_oid}";'
        ponportonu = cursor.execute(sqlgetport)

        portonu_out = "Не удалось определить порт"
        for portonu in ponportonu:
            portonu_out = portonu[3]

        sqlgetallonu = f'SELECT * FROM ponports WHERE ip_address="{self.olt_ip}" AND ponport like "{portonu_out}:%";'
        getallonu = cursor.execute(sqlgetallonu)

        onuinfo = {}
        for onu in getallonu:
            indexonu_out = onu[3]

            onuinfo.setdefault(indexonu_out)
            onuinfo.update({indexonu_out: {"portid": onu[4], "oltip": onu[2]}})

        for getonuport in onuinfo:
            sqlgetonu = f'''SELECT * FROM {self.pontype} WHERE oltip="{self.olt_ip}" AND portonu="{onuinfo[getonuport]['portid']}";'''
            getonu = cursor.execute(sqlgetonu)

            for onulist in getonu:
                onuinfo.update({getonuport: {"onu": onulist[1], "portid": onulist[2], "oltip": onulist[4]}})

        # ---- Получение причины отключения ONU
        parse_down_reason = r'(?P<onudec>\d+.\d+.\d+.\d+.\d+.\d+) = INTEGER: (?P<downreason>\d+)'
        down_reason = {}

        onudownreasonoid = f'{oid_cose}.{self.port_oid}'
        snmpget = SnmpWalk(self.olt_ip, SNMP_READ_B, onudownreasonoid)
        onudownreason = snmpget.snmpget()
        for l in onudownreason:
            match = re.search(parse_down_reason, l)
            if match:
                onu = match.group('onudec')
                onudownreason = match.group('downreason')
                onudownreason = onudownreason.replace("8", "LOS").replace("9", "POWER-OFF").replace("0", "Неизвестно")
                down_reason.update({onu: onudownreason})

        # ---- Получение статуса с дерева
        for createcmd in onuinfo:
            portonu = createcmd
            portid = onuinfo[createcmd]['portid']
            oltip = onuinfo[createcmd]['oltip']
            onu = onuinfo[createcmd]['onu']

            onustateoid = f'{oid_state}.{portid}'
            snmpget = SnmpWalk(self.olt_ip, SNMP_READ_B, onustateoid)
            onustate = snmpget.snmpget()
            for l in onustate:
                match = re.search(parse_state, l)
                if match:
                    onustatus = match.group('onustate')
                    onustatus = onustatus.replace("1", "ONLINE").replace("2", "OFFLINE").replace("-1", "OFFLINE")
                    if onustatus == "OFFLINE":
                        try:
                            outmacdec = ""
                            n = 2
                            out = [onu[i:i+n] for i in range(0, len(onu), n)]
                            for i in out:
                                dece = int(i, 16)
                                outmacdec = outmacdec + "." + str(dece)

                            onustatus = down_reason[outmacdec[1:]]

                        except KeyError:
                            onustatus = "Неизвестно"

                    status_tree.setdefault(onu)
                    status_tree.update({onu: {'onustatus': onustatus, 'levelin': '0', 'levelout': '0'}})

        # ---- Получение уровня сигнала в сторону ОНУ
        out_treeinfo = ["ОНУ ; Сигнал в сторону ОНУ; Сигнал в сторону ОЛТа"]
        for createcmd in onuinfo:
            portonu = createcmd
            portid = onuinfo[createcmd]['portid']
            oltip = onuinfo[createcmd]['oltip']
            onu = onuinfo[createcmd]['onu']

            rxonuoid = f'{snmp_rx_onu}.{portid}'
            snmpget = SnmpWalk(self.olt_ip, SNMP_READ_B, rxonuoid)
            rxonu = snmpget.snmpget()
            for l in rxonu:
                match = re.search(parse_tree, l)
                if match:
                    rx_onu = match.group('level')
                    level_onu = int(rx_onu)/10
                    status_tree.update({onu: {'onustatus': 'ONLINE', 'levelin': level_onu, 'levelout': '0'}})

        conn.close()

        return status_tree


    def hwunregonu(self):
        '''
        Метод проверяет есть ли на ОЛТе не зарегистрированные ОНУ
        '''    
        unregonu_out = []

        if 'epon' in self.pontype:
            unregoid = '1.3.6.1.4.1.2011.6.128.1.1.2.61.1.2'

        elif 'gpon' in self.pontype:
            unregoid = '1.3.6.1.4.1.2011.6.128.1.1.2.48.1.2'

        parse_onu = "(?P<portoid>\d{10}).+ Hex-STRING: (?P<onu>.+)"

        snmpget = SnmpWalk(self.olt_ip, SNMP_READ_H, unregoid)
        onulist = snmpget.snmpget()
        
        for l in onulist:
            match = re.search(parse_onu, l)
            if match:
                unreg_onu = match.group('onu').replace(' ', '')
                oltport_oid = match.group('portoid')

                conn = sqlite3.connect(self.pathdb)
                cursor = conn.cursor()
                ponport = cursor.execute(f'SELECT * FROM ponports WHERE ip_address="{self.olt_ip}" AND portoid LIKE "{oltport_oid}";')
                
                for p in ponport:
                    oltport = p[3]

                conn.close()
 
                onudict = {
                'mac': unreg_onu,
                'oltport': oltport,
                }
                unregonu_out.append(onudict)

        return unregonu_out

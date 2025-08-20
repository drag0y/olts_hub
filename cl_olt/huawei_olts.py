import re
import os
import sqlite3
from dotenv import load_dotenv

from cl_other.snmpwalk import SnmpWalk


class HuaweiGetOltInfo:
    '''
    Класс для работы с ОЛТами Huawei
    '''
    def __init__(self, olt_name, olt_ip, snmp_com, pathdb, pontype):
        self.olt_name = olt_name
        self.olt_ip = olt_ip
        self.snmp_com = snmp_com
        self.pathdb = pathdb
        self.pontype = pontype


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
        if self.pontype == "epon":
            snmpget = SnmpWalk(self.olt_ip, self.snmp_com, snmp_epon)
            onulist = snmpget.snmpget()
           
        elif self.pontype == "gpon":
            snmpget = SnmpWalk(self.olt_ip, self.snmp_com, snmp_gpon)
            onulist = snmpget.snmpget()

        # --- Парсинг Мак адресов и добавление в базу
        if self.pontype == "epon":
            for l in onulist:
                match = re.search(parseout, l.replace(" ", "").lower())
                if match:
                    listont = match.group('maconu'), match.group('portonu'), match.group('onuid'), self.olt_ip, self.olt_name
                    cursor.execute(query, listont)
            conn.commit()
            conn.close()

        # --- Парсинг серийников и добавление в базу
        if self.pontype == "gpon":
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


    def hwponstatustree(self, port_oid):
        ''' Îïðåäåëåíèå ñòàòóñà âñåãî äåðåâà (ïîðòà) íà ÎËÒå Huawei '''

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


    # ---- Èùåì â áàçå ìàê ÎÍÓ äëÿ ñîïîñòàâëåíèÿ ñ èíäåêñàìè
        onureplace = {}

        conn = sqlite3.connect(self.pathdb)
        cursor = conn.cursor()

        onureplace_in = cursor.execute(f'SELECT * FROM {self.pontype} WHERE oltip="{self.olt_ip}" AND portonu="{port_oid}";')
        onu_count = 0

        for onu in onureplace_in:
            onu_count += 1
            indexonu_out = onu[3]
            onu_out = onu[1]

            onureplace.setdefault(indexonu_out)
            onureplace.update({indexonu_out: onu_out})

#        if PF_HUAWEI: #in self.platform and "gpon" in self.pontype:
        '''
        Ïîëó÷åíèå ñòàòóñà ñ äåðåâà
        '''
        onustateoid = f'{oid_state}.{port_oid}'
        snmpget = SnmpWalk(self.olt_ip, self.snmp_com, onustateoid)
        onustate = snmpget.snmpget()
        for l in onustate:
            match = re.search(parse_state, l)
            if match:
                onuid = match.group('onuid')
                onustatus = match.group('onustate')
                onustatus = onustatus.replace("1", "ONLINE").replace("2", "OFFLINE").replace("-1", "OFFLINE")

                onulist.append(onuid)
                statuslist.append(onustatus)

        onudownreasonoid = f'{oid_cose}.{port_oid}'
        snmpget = SnmpWalk(self.olt_ip, self.snmp_com, onudownreasonoid)
        onudownreason = snmpget.snmpget()
        for l in onudownreason:
            match = re.search(parse_down, l)
            if match:
                downcose = match.group('downcose')
                downcose = downcose.replace("-1", "Íåèçâåñòíî").replace("18", "RING").replace("13", "POWER-OFF").replace("2", "LOS").replace("1", "LOS").replace("3", "LOS")
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

        # ---- Ïîëó÷åíèå óðîâíÿ ñèãíàëà â ñòîðîíó ÎÍÓ
        rxonuoid = f'{oid_rx_onu}.{port_oid}'
        snmpget = SnmpWalk(self.olt_ip, self.snmp_com, rxonuoid)
        rxonu = snmpget.snmpget()

        for l in rxonu:
            match = re.search(parse_tree, l)
            if match:
                onuid = match.group('onuid')
                level = match.group('treelevel')
                level_rx = int(level)/100

                onulist2.append(onuid)
                tree_in.append(level_rx)

        # ---- Ïîëó÷åíèå ðåçóëüòàòà óðîâíÿ â ñòîðîíó ÎËÒà
        parse_tree_sn = r'(\d+){10}.(?P<onuid>\S+) .+INTEGER: (?P<treelevel>\d+)'
        rxoltoid = f'{oid_rx_olt}.{port_oid}'
        snmpget = SnmpWalk(self.olt_ip, self.snmp_com, rxoltoid)
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

        snmpget = SnmpWalk(self.olt_ip, self.snmp_com, unregoid)
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

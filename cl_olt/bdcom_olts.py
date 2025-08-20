import re
import sqlite3

from cl_other.snmpwalk import SnmpWalk


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


    def bdcomponstatustree(self, port_oid):
        '''
        Статус и уровни с дерева (порта) ОЛТа BDCOM
        '''

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
        sqlgetport = f'SELECT * FROM ponports WHERE ip_address="{self.olt_ip}" AND portoid like "{port_oid}";'
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

        onudownreasonoid = f'{oid_cose}.{port_oid}'
        snmpget = SnmpWalk(self.olt_ip, self.snmp_com, onudownreasonoid)
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
            snmpget = SnmpWalk(self.olt_ip, self.snmp_com, onustateoid)
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
            snmpget = SnmpWalk(self.olt_ip, self.snmp_com, rxonuoid)
            rxonu = snmpget.snmpget()
            for l in rxonu:
                match = re.search(parse_tree, l)
                if match:
                    rx_onu = match.group('level')
                    level_onu = int(rx_onu)/10
                    status_tree.update({onu: {'onustatus': 'ONLINE', 'levelin': level_onu, 'levelout': '0'}})

        conn.close()

        return status_tree

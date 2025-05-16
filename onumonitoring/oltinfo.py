import subprocess
import sqlite3
import re
import os

from onumonitoring.bdcom_onu import BdcomGetOnuInfo
from onumonitoring.huawei_onu import HuaweiGetOnuInfo
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
        out_tree2 = []
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
    # ---- Получение статуса с дерева

        if PF_HUAWEI: #in self.platform and "gpon" in self.pontype:
            print("STARTED GET PORT STATUS")

            cmd_onu_state = f"snmpwalk -c {SNMP_READ_H} -v2c {self.olt_ip} {oid_state}.{self.port_oid}"
            cmd = cmd_onu_state.split()
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE)

            while True:
                output = process.stdout.readline()

                if output == b'' and process.poll() is not None:
                    break

                if output:
                    outlist = output.decode('utf-8')
                    match = re.search(parse_state, outlist)
                    if match:
                        onuid = match.group('onuid')
                        onustatus = match.group('onustate')
                        onustatus = onustatus.replace("1", "ONLINE").replace("2", "OFFLINE").replace("-1", "OFFLINE")

                        onulist.append(onuid)
                        statuslist.append(onustatus)

            cmd_down_cose = f"snmpwalk -c {SNMP_READ_H} -v2c {self.olt_ip} {oid_cose}.{self.port_oid}"
            cmd = cmd_down_cose.split()
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE)

            while True:
                output = process.stdout.readline()

                if output == b'' and process.poll() is not None:
                    break

                if output:
                    outlist = output.decode('utf-8')
                    match = re.search(parse_down, outlist)
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

                out_tree2.append(str(onureplace[onu]) + " ; " + str(statuslist[i]))

                status_tree.setdefault(onureplace[onu])
                status_tree.update({onureplace[onu]: {'onustatus': statuslist[i], 'levelin': '0', 'levelout': '0'}})

        # ---- Получение уровня сигнала с ОНУ
        cmd_rx_onu = f"snmpwalk -c {SNMP_READ_H} -v2c {self.olt_ip} {oid_rx_onu}.{self.port_oid}"
        cmd = cmd_rx_onu.split()

        process = subprocess.Popen(cmd, stdout=subprocess.PIPE)


        while True:
            output = process.stdout.readline()

            if output == b'' and process.poll() is not None:
                break

            if output:
                outlist = output.decode('utf-8')
                match = re.search(parse_tree, outlist)
                if match:
                    onuid = match.group('onuid')
                    level = match.group('treelevel')
                    level_rx = int(level)/100

                    onulist2.append(onuid)
                    tree_in.append(level_rx)

        # ---- Получение результата уровня в сторону ОЛТа
        parse_tree_sn = r'(\d+){10}.(?P<onuid>\S+) .+INTEGER: (?P<treelevel>\d+)'

        cmd_rx_olt = f"snmpwalk -c {SNMP_READ_H} -v2c {self.olt_ip} {oid_rx_olt}.{self.port_oid}"
        cmd = cmd_rx_olt.split()
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE)

        while True:
            output = process.stdout.readline()

            if output == b'' and process.poll() is not None:
                break

            if output:
                outlist2 = output.decode('utf-8')
                match = re.search(parse_tree_sn, outlist2)
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

        cmd_onu_state = f"snmpwalk -c {SNMP_READ_B} -v2c {self.olt_ip} {oid_cose}.{self.port_oid}"
        cmd = cmd_onu_state.split()

        process = subprocess.Popen(cmd, stdout=subprocess.PIPE)

        down_reason = {}
        while True:
            output = process.stdout.readline()

            if output == b'' and process.poll() is not None:
                break

            if output:
                outlist = output.decode('utf-8')
                match = re.search(parse_down_reason, outlist)

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

            cmd_onu_state = f"snmpwalk -c {SNMP_READ_B} -v2c {self.olt_ip} {oid_state}.{portid}"
            cmd = cmd_onu_state.split()
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE)

            while True:
                output = process.stdout.readline()

                if output == b'' and process.poll() is not None:
                    break

                if output:
                    outlist = output.decode('utf-8')
                    match = re.search(parse_state, outlist)

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

        # ---- Получение уровня сигнала с ОНУ
        out_treeinfo = ["ОНУ ; Сигнал в сторону ОНУ; Сигнал в сторону ОЛТа"]
        for createcmd in onuinfo:
            portonu = createcmd
            portid = onuinfo[createcmd]['portid']
            oltip = onuinfo[createcmd]['oltip']
            onu = onuinfo[createcmd]['onu']

            cmd_rx_onu = f"snmpwalk -c {SNMP_READ_B} -v2c {self.olt_ip} {snmp_rx_onu}.{portid}"
            cmd = cmd_rx_onu.split()
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE)

            while True:
                output = process.stdout.readline()

                if output == b'' and process.poll() is not None:
                    break

                if output:
                    outlist = output.decode('utf-8')
                    match = re.search(parse_tree, outlist)

                    if match:
                        rx_onu = match.group('level')
                        level_onu = int(rx_onu)/10

                        status_tree.update({onu: {'onustatus': 'ONLINE', 'levelin': '0', 'levelout': level_onu}})

        conn.close()

        return status_tree


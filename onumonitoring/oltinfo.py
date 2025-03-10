import subprocess
import sqlite3
import re

from onumonitoring.bdcom_onu import BdcomGetOnuInfo
from onumonitoring.huawei_onu import HuaweiGetOnuInfo
from config import SNMP_READ_H, SNMP_READ_B, SNMP_CONF_H, SNMP_CONF_B, PF_HUAWEI, PF_BDCOM


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

        onulist = []
        statuslist = []
        out_tree2 = []
        downlist = []
        out_tree = ["ОНУ ; Сигнал в сторону ОНУ; Сигнал в сторону ОЛТа"]
        tree_in = []
        tree_out = []
        onulist2 = []
        level_rx = ""
        level_tx = ""
        status_tree = {}
        level_tree = {}

        parse_state = r'(\d+){10}.(?P<onuid>\S+) .+INTEGER: (?P<onustate>\d+|-\d+)'
        parse_down = r'(\d+){10}.(?P<onuid>\S+) .+INTEGER: (?P<downcose>\d+|-\d+)'
        parse_tree = r'(\d+){10}.(?P<onuid>\S+) .+(?P<treelevel>-\S+)'

        if PF_HUAWEI in self.platform and "epon" in self.pontype:
            oid_rx_onu = "1.3.6.1.4.1.2011.6.128.1.1.2.104.1.5"
            oid_rx_olt = "1.3.6.1.4.1.2011.6.128.1.1.2.104.1.1"
            oid_state = "1.3.6.1.4.1.2011.6.128.1.1.2.57.1.15"
            oid_cose = "1.3.6.1.4.1.2011.6.128.1.1.2.57.1.25"
            pon_total = "64"

        if PF_HUAWEI in self.platform and "gpon" in self.pontype:
            oid_rx_onu = "1.3.6.1.4.1.2011.6.128.1.1.2.51.1.4"
            oid_rx_olt = "1.3.6.1.4.1.2011.6.128.1.1.2.51.1.6"
            oid_state = "1.3.6.1.4.1.2011.6.128.1.1.2.46.1.15"
            oid_cose = "1.3.6.1.4.1.2011.6.128.1.1.2.46.1.24"
            pon_total = "128"



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

        if PF_HUAWEI in self.platform and "gpon" in self.pontype:

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
            out_tree.append(str(onureplace[onu]) + " ; " + str(tree_in[i]) + " ; " + str(tree_out[i]))
            status_tree.update({onureplace[onu]: {'onustatus': 'ONLINE', 'levelin': tree_in[i], 'levelout': tree_out[i]}})

        result_tree = []

        return status_tree

import subprocess
import re
import sqlite3


class HuaweiGetOnuInfo:
    ''' Класс для работы с ОНУ Huawei '''
    def __init__(self, hostname, pon_type, olt_ip, portoid, onuid, snmp_com, pathdb, snmp_conf):
        self.hostname = hostname
        self.pon_type = pon_type
        self.olt_ip = olt_ip
        self.portoid = portoid
        self.onuid = onuid
        self.snmp_com = snmp_com
        self.pathdb = pathdb
        self.snmp_conf = snmp_conf


    def getonustatus(self):
        # Определение статуса ОНУ (В сети/Не в сети)
        if "epon" in self.pon_type:
            ponstateoid = "1.3.6.1.4.1.2011.6.128.1.1.2.57.1.15"

        if "gpon" in self.pon_type:
            ponstateoid = "1.3.6.1.4.1.2011.6.128.1.1.2.46.1.15"

        cmd = f"snmpwalk -c {self.snmp_com} -v2c {self.olt_ip} {ponstateoid}.{self.portoid}.{self.onuid}"
        cmd_to_subprocess = cmd.split()

        process = subprocess.Popen(cmd_to_subprocess, stdout=subprocess.PIPE)
        data = process.communicate(timeout=5)
        data2 = data[-2].decode('utf-8')
        onu_state = data2.split()
        onu_state_out = onu_state[-1]


        return onu_state_out


    def getlanstatus(self):
        # Метод определяет статус LAN порта
        try:
            if "epon" in self.pon_type:
                ethstatusoid = "1.3.6.1.4.1.2011.6.128.1.1.2.81.1.31"

            if "gpon" in self.pon_type:
                ethstatusoid = "1.3.6.1.4.1.2011.6.128.1.1.2.62.1.22"


            cmd = f"snmpwalk -c {self.snmp_com} -v2c {self.olt_ip} {ethstatusoid}.{self.portoid}.{self.onuid}.1"
            cmd_to_subprocess = cmd.split()
            process = subprocess.Popen(cmd_to_subprocess, stdout=subprocess.PIPE)
            data = process.communicate(timeout=3)
            data2 = data[-2].decode('utf-8')
            lanstatus = data2.split()

            if lanstatus[-1] == '1':
                lan_out = "UP"
            elif lanstatus[-1] == '2':
                lan_out = "DOWN"
            else:
                lan_out = "Не удалось определить"

        except subprocess.TimeoutExpired:
            lan_out = "Не удалось определить"

        return lan_out

    def getcatvstate(self):
        # Метод определяет статус CATV порта
        try:
            if self.pon_type == "epon":
                catv_out = "Не поддерживается"
                catv_level = "Не поддерживается"
            if self.pon_type == "gpon":
                catvstatusoid = "1.3.6.1.4.1.2011.6.128.1.1.2.63.1.2"
                cmd = f"snmpwalk -c {self.snmp_com} -v2c {self.olt_ip} {catvstatusoid}.{self.portoid}.{self.onuid}.1"
                cmd_to_subprocess = cmd.split()

                process = subprocess.Popen(cmd_to_subprocess, stdout=subprocess.PIPE)
                data = process.communicate(timeout=3)
                data2 = data[-2].decode('utf-8')
                catvstatus = data2.split()

                if catvstatus[-1] == '1':
                    catv_out = "ON"
                    catv_level = self.getcatvlevel()
                elif catvstatus[-1] == '2':
                    catv_out = "OFF"
                    catv_level = self.getcatvlevel()
                else:
                    catv_out = "Не удалось определить"
                    catv_level = "0"

        except subprocess.TimeoutExpired:
                catv_out = "Не удалось определить"
                catv_level = "0"

        return catv_out, catv_level

    
    def getcatvlevel(self):
        # Метод определяет уровень сигнала CATV порта
        ''' Метод для получения уровня сигнала CATV порта '''
        parse_data = r'INTEGER: (?P<level>-.+)'
        level_catv = "0"

        snmp_rx_catv = "1.3.6.1.4.1.2011.6.128.1.1.2.51.1.7"

        cmd = f"snmpwalk -c {self.snmp_com} -v2c {self.olt_ip} {snmp_rx_catv}.{self.portoid}.{self.onuid}"

        cmd_to_subprocess = cmd.split()
        process = subprocess.Popen(cmd_to_subprocess, stdout=subprocess.PIPE)

        while True:
            output = process.stdout.readline()

            if output == b'' and process.poll() is not None:
                break

            if output:
                outlist = output.decode('utf-8')
                match = re.search(parse_data, outlist)
                if match:
                    rx_catv = match.group('level')
                    level_catv = int(rx_catv)/100

        return level_catv


    def getlastdown(self):
        # Метод определяет причину последнего отключения ОНУ
        if "epon" in self.pon_type:
            lastdownoid = "1.3.6.1.4.1.2011.6.128.1.1.2.57.1.25"

        if "gpon" in self.pon_type:
            lastdownoid = "1.3.6.1.4.1.2011.6.128.1.1.2.46.1.24"

        cmd = f"snmpwalk -c {self.snmp_com} -v2c {self.olt_ip} {lastdownoid}.{self.portoid}.{self.onuid}"
        cmd_to_subprocess = cmd.split()

        process = subprocess.Popen(cmd_to_subprocess, stdout=subprocess.PIPE)
        data = process.communicate(timeout=5)
        data2 = data[-2].decode('utf-8')
        last_down_onu = data2.split()

        if last_down_onu[-1] == '13':
            lastdownonu = "Power-Off"
        elif last_down_onu[-1] == '1' or '2':
            lastdownonu = "LOS"
        else:
            lastdownonu = "Неизвестно"

        return lastdownonu


    def getonuuptime(self):
        # Метод определяет время включения ОНУ
        timelist = "Нет времени отключения"

        parse_data = r'STRING: "(?P<regtime>\S+ \S+)"'

        if "epon" in self.pon_type:
            datatimeoid = "1.3.6.1.4.1.2011.6.128.1.1.2.103.1.6"

        if "gpon" in self.pon_type:
            datatimeoid = "1.3.6.1.4.1.2011.6.128.1.1.2.101.1.6"

        cmd = f"snmpwalk -c {self.snmp_com} -v2c {self.olt_ip} {datatimeoid}.{self.portoid}.{self.onuid}"
        cmd_to_subprocess = cmd.split()
        process = subprocess.Popen(cmd_to_subprocess, stdout=subprocess.PIPE)

        while True:
            output = process.stdout.readline()

            if output == b'' and process.poll() is not None:
                break

            if output:
                outlist = output.decode('utf-8')
                match = re.search(parse_data, outlist)
                if match:
                    timelist = match.group('regtime')

        datatime = timelist.replace("Z", "+03:00")

        return datatime


    def gettimedown(self):
        # Метод определяет время последнего отключения
        timelist = "Нет времени отключения"

        parse_data = r'STRING: "(?P<regtime>\S+ \S+)"'

        if "epon" in self.pon_type:
            datatimeoid = "1.3.6.1.4.1.2011.6.128.1.1.2.103.1.7"

        if "gpon" in self.pon_type:
            datatimeoid = "1.3.6.1.4.1.2011.6.128.1.1.2.101.1.7"

        cmd = f"snmpwalk -c {self.snmp_com} -v2c {self.olt_ip} {datatimeoid}.{self.portoid}.{self.onuid}"
        cmd_to_subprocess = cmd.split()
        process = subprocess.Popen(cmd_to_subprocess, stdout=subprocess.PIPE)

        while True:
            output = process.stdout.readline()

            if output == b'' and process.poll() is not None:
                break

            if output:
                outlist = output.decode('utf-8')
                match = re.search(parse_data, outlist)
                if match:
                    timelist = match.group('regtime')

        datatime = timelist.replace("Z", "+03:00")

        return datatime

    def getonulevel(self):
        # Метод определяет уровни сигнала ОНУ
        if "epon" in self.pon_type:
            snmp_rx_onu = "1.3.6.1.4.1.2011.6.128.1.1.2.104.1.5"
            snmp_rx_olt = "1.3.6.1.4.1.2011.6.128.1.1.2.104.1.1"

        if "gpon" in self.pon_type:
            snmp_rx_onu = "1.3.6.1.4.1.2011.6.128.1.1.2.51.1.4"
            snmp_rx_olt = "1.3.6.1.4.1.2011.6.128.1.1.2.51.1.6"

        # ---- Получение уровня сигнала с ОНУ
        cmd = f"snmpwalk -c {self.snmp_com} -v2c {self.olt_ip} {snmp_rx_onu}.{self.portoid}.{self.onuid}"
        cmd_to_subprocess = cmd.split()
        process = subprocess.Popen(cmd_to_subprocess, stdout=subprocess.PIPE)
        data = process.communicate(timeout=2)
        data2 = data[-2].decode('utf-8')
        rx_onu = data2.split()
        level_onu = int(rx_onu[-1])/100

        # ---- Получение результата уровня в сторону ОЛТа

        cmd = f"snmpwalk -c {self.snmp_com} -v2c {self.olt_ip} {snmp_rx_olt}.{self.portoid}.{self.onuid}"
        cmd_to_subprocess = cmd.split()
        process = subprocess.Popen(cmd_to_subprocess, stdout=subprocess.PIPE)
        data = process.communicate(timeout=2)
        data2 = data[-2].decode('utf-8')
        rx_olt = data2.split()
        level_olt = int(rx_olt[-1])/100-100

        return level_onu, format(level_olt, '.2f')

    
    def getstatustree(self):
        # Определение статуса всего дерева (pon порта)
        onulist = []
        statuslist = []
        downlist = []

        out_tree = ""
        out_tree2 = ["ОНУ ; Статус"]
        onustatus = ""
        downcose = ""

        if "epon" in self.pon_type:
            oid_state = "1.3.6.1.4.1.2011.6.128.1.1.2.57.1.15"
            oid_cose = "1.3.6.1.4.1.2011.6.128.1.1.2.57.1.25"
            pon_total = "64"
        if "gpon" in self.pon_type:
            oid_state = "1.3.6.1.4.1.2011.6.128.1.1.2.46.1.15"
            oid_cose = "1.3.6.1.4.1.2011.6.128.1.1.2.46.1.24"
            pon_total = "128"


        parse_state = r'(\d+){10}.(?P<onuid>\S+) .+INTEGER: (?P<onustate>\d+|-\d+)'
        parse_down = r'(\d+){10}.(?P<onuid>\S+) .+INTEGER: (?P<downcose>\d+|-\d+)'
    

        # ---- Ищем порт олта

        conn = sqlite3.connect(self.pathdb)
        cursor = conn.cursor()

        ponportonu = cursor.execute(f'SELECT ponport FROM ponports WHERE ip_address="{self.olt_ip}" AND portoid="{self.portoid}";')

        portonu_out = "Не удалось определить порт"
        for portonu in ponportonu:
            portonu_out = portonu[0]

        getoltname = cursor.execute(f'SELECT hostname FROM ponports WHERE ip_address="{self.olt_ip}" AND portoid="{self.portoid}";')

        oltname_out = "Не удалось определить имя OLTа"
        for oltname in getoltname:
            oltname_out = oltname[0]


        # ---- Ищем в базе мак ОНУ для сопоставления с индексами
        onureplace = {}

        conn = sqlite3.connect(self.pathdb)
        cursor = conn.cursor()

        onureplace_in = cursor.execute(f'SELECT * FROM {self.pon_type} WHERE oltip="{self.olt_ip}" AND portonu="{self.portoid}";')
        onu_count = 0
        for onu in onureplace_in:
            onu_count += 1
            indexonu_out = onu[3]
            onu_out = onu[1]

            onureplace.setdefault(indexonu_out)
            onureplace.update({indexonu_out: onu_out})

        
        # ---- Получение статуса с дерева
        cmd_onu_state = f"snmpwalk -c {self.snmp_com} -v2c {self.olt_ip} {oid_state}.{self.portoid}"
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

    
        # ---- Получение причины отключения ONU
        cmd_down_cose = f"snmpwalk -c {self.snmp_com} -v2c {self.olt_ip} {oid_cose}.{self.portoid}"
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

        conn.close()
        return out_tree2 


    def getleveltree(self):
        # Получение уровня сигнала с дерева (pon порта)
        out_tree = ""
        out_tree2 = ["ОНУ ; Сигнал в сторону ОНУ; Сигнал в сторону ОЛТа"]
        tree_in = []
        tree_out = []
        onulist = []
        level_rx = ""
        level_tx = ""

        if "epon" in self.pon_type:
            snmp_rx_onu = "1.3.6.1.4.1.2011.6.128.1.1.2.104.1.5"
            snmp_rx_olt = "1.3.6.1.4.1.2011.6.128.1.1.2.104.1.1"
        if "gpon" in self.pon_type:
            snmp_rx_onu = "1.3.6.1.4.1.2011.6.128.1.1.2.51.1.4"
            snmp_rx_olt = "1.3.6.1.4.1.2011.6.128.1.1.2.51.1.6"

        parse_tree = r'(\d+){10}.(?P<onuid>\S+) .+(?P<treelevel>-\S+)'

        # ---- Ищем порт олта

        conn = sqlite3.connect(self.pathdb)
        cursor = conn.cursor()

        ponportonu = cursor.execute(f'SELECT ponport FROM ponports WHERE ip_address="{self.olt_ip}" AND portoid="{self.portoid}";')

        portonu_out = "Не удалось определить порт"
        for portonu in ponportonu:
            portonu_out = portonu[0]

        getoltname = cursor.execute(f'SELECT hostname FROM ponports WHERE ip_address="{self.olt_ip}" AND portoid="{self.portoid}";')

        oltname_out = "Не удалось определить имя OLTа"
        for oltname in getoltname:
            oltname_out = oltname[0]


        # ---- Ищем в базе маке ОНУ для сопоставления с индексами
        onureplace = {}

        onureplace_in = cursor.execute(f'SELECT * FROM {self.pon_type} WHERE oltip="{self.olt_ip}" AND portonu="{self.portoid}";')
        for onu in onureplace_in:
            indexonu_out = onu[3]
            onu_out = onu[1]

            onureplace.setdefault(indexonu_out)
            onureplace.update({indexonu_out: onu_out})

        # ---- Получение уровня сигнала с ОНУ
        cmd_rx_onu = f"snmpwalk -c {self.snmp_com} -v2c {self.olt_ip} {snmp_rx_onu}.{self.portoid}"
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

                    onulist.append(onuid)
                    tree_in.append(level_rx)

        # ---- Получение результата уровня в сторону ОЛТа
        parse_tree_sn = r'(\d+){10}.(?P<onuid>\S+) .+INTEGER: (?P<treelevel>\d+)'

        cmd_rx_olt = f"snmpwalk -c {self.snmp_com} -v2c {self.olt_ip} {snmp_rx_olt}.{self.portoid}"
        cmd = cmd_rx_olt.split()

        process = subprocess.Popen(cmd, stdout=subprocess.PIPE)

        while True:
            output = process.stdout.readline()

            if output == b'' and process.poll() is not None:
                break

            if output:
                outlist = output.decode('utf-8')
                match = re.search(parse_tree_sn, outlist)
                if match:
                    onuid = match.group('onuid')
                    level = match.group('treelevel')

                    if len(level) == 4:
                        level_tx2 = int(level)/100-100
                        level_tx = format(level_tx2, '.2f')

                        tree_out.append(level_tx)

        # ----
        for i in range(len(onulist)):
            onu = str(onulist[i])
            out_tree2.append(str(onureplace[onu]) + " ; " + str(tree_in[i]) + " ; " + str(tree_out[i]))

        conn.close()

        return out_tree2


    def setcatvon(self):

        if self.pon_type == "epon":
            catv_out = "Не поддерживается"
        if self.pon_type == "gpon":
            catvstatusoid = "1.3.6.1.4.1.2011.6.128.1.1.2.63.1.2"
            cmd = f"snmpset -c {self.snmp_conf} -v2c {self.olt_ip} {catvstatusoid}.{self.portoid}.{self.onuid}.1 i 1"
            cmd_to_subprocess = cmd.split()
            process = subprocess.Popen(cmd_to_subprocess, stdout=subprocess.PIPE)
            data = process.communicate(timeout=3)
            data2 = data[-2].decode('utf-8')
            catvstatus = data2.split()

            if catvstatus[-1] == '1':
                catv_out = "ON"
            elif catvstatus[-1] == '2':
                catv_out = "OFF"
            else:
                catv_out = "Не удалось определить"

        return catv_out


    def setcatvoff(self):

        if self.pon_type == "epon":
            catv_out = "Не поддерживается"
        if self.pon_type == "gpon":
            catvstatusoid = "1.3.6.1.4.1.2011.6.128.1.1.2.63.1.2"
            cmd = f"snmpset -c {self.snmp_conf} -v2c {self.olt_ip} {catvstatusoid}.{self.portoid}.{self.onuid}.1 i 2"
            cmd_to_subprocess = cmd.split()
            process = subprocess.Popen(cmd_to_subprocess, stdout=subprocess.PIPE)
            data = process.communicate(timeout=3)
            data2 = data[-2].decode('utf-8')
            catvstatus = data2.split()

            if catvstatus[-1] == '1':
                catv_out = "ON"
            elif catvstatus[-1] == '2':
                catv_out = "OFF"
            else:
                catv_out = "Не удалось определить"

        return catv_out


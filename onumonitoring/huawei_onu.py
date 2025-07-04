import subprocess
import re
import sqlite3

from onumonitoring.snmpwalk import SnmpWalk


class HuaweiGetOnuInfo:
    ''' 
    Класс для работы с ОНУ Huawei 
    '''
    def __init__(self, hostname, pon_type, olt_ip, portoid, onuid, snmp_com, pathdb, snmp_wr):
        self.hostname = hostname
        self.pon_type = pon_type
        self.olt_ip = olt_ip
        self.portoid = portoid
        self.onuid = onuid
        self.snmp_com = snmp_com
        self.pathdb = pathdb
        self.snmp_wr = snmp_wr


    def getonustatus(self):
        ''' 
        Определение статуса ОНУ (В сети/Не в сети)
        '''
        if "epon" in self.pon_type:
            ponstateoid = "1.3.6.1.4.1.2011.6.128.1.1.2.57.1.15"
        elif "gpon" in self.pon_type:
            ponstateoid = "1.3.6.1.4.1.2011.6.128.1.1.2.46.1.15"

        parse_state = r'INTEGER: (?P<onustate>\d)'

        onustateoid = f'{ponstateoid}.{self.portoid}.{self.onuid}'
        snmpget = SnmpWalk(self.olt_ip, self.snmp_com, onustateoid)
        onustate = snmpget.snmpget()
        
        onu_state_out = '3' # Если ОЛТ не отвечает
        for l in onustate:
            match = re.search(parse_state, l)
            if match:
                onu_state_out = match.group('onustate')

        return onu_state_out


    def getlanstatus(self):
        ''' 
        Метод определяет статус LAN порта
        '''
        lan_out = "Не удалось определить"
        if "epon" in self.pon_type:
            ethstatusoid = "1.3.6.1.4.1.2011.6.128.1.1.2.81.1.31"
        elif "gpon" in self.pon_type:
            ethstatusoid = "1.3.6.1.4.1.2011.6.128.1.1.2.62.1.22"

        parse_lanstate = r'INTEGER: (?P<lanstate>\d)'

        lanstateoid = f'{ethstatusoid}.{self.portoid}.{self.onuid}.1'
        snmpget = SnmpWalk(self.olt_ip, self.snmp_com, lanstateoid)
        lanstate = snmpget.snmpget()

        for l in lanstate:
            match = re.search(parse_lanstate, l)
            if match:
                lanstatus = match.group('lanstate')
                if lanstatus == '1':
                    lan_out = "UP"
                elif lanstatus == '2':
                    lan_out = "DOWN"
                else:
                    lan_out = "Не удалось определить"

        return lan_out


    def getcatvstate(self):
        ''' 
        Метод определяет статус CATV порта
        '''
        catv_out = "Неизвестно"
        catv_level = "0"
        if self.pon_type == "epon":
            catv_out = 'Не поддерживается'
            catv_level = -0.0
        elif self.pon_type == "gpon":
            catvstatusoid = "1.3.6.1.4.1.2011.6.128.1.1.2.63.1.2"

            parse_catvstate = r'INTEGER: (?P<catvstate>\d)'
            catvstateoid = f'{catvstatusoid}.{self.portoid}.{self.onuid}.1'
            snmpget = SnmpWalk(self.olt_ip, self.snmp_com, catvstateoid)
            catvstate = snmpget.snmpget()

            for l in catvstate:
                match = re.search(parse_catvstate, l)
                if match:
                    catv_status = match.group('catvstate')
                    if catv_status == '1':
                        catv_out = "ON"
                        catv_level = self.getcatvlevel()
                    elif catv_status == '2':
                        catv_out = "OFF"
                        catv_level = self.getcatvlevel()
                    else:
                        catv_out = "Неизвестно"
                        catv_level = -0.0

        return catv_out, catv_level

    
    def getcatvlevel(self):
        ''' 
        Метод для получения уровня сигнала CATV порта 
        '''
        parse_catvlevel = r'INTEGER: (?P<level>.+)'
        level_catv = "0"

        snmp_rx_catv = "1.3.6.1.4.1.2011.6.128.1.1.2.51.1.7"

        catvleveloid = f'{snmp_rx_catv}.{self.portoid}.{self.onuid}'

        snmpget = SnmpWalk(self.olt_ip, self.snmp_com, catvleveloid)
        catvlevel = snmpget.snmpget()

        for l in catvlevel:
            match = re.search(parse_catvlevel, l)            
            if match:
                rx_catv = match.group('level')
                level_catv = int(rx_catv)/100

        return level_catv


    def getlastdown(self):
        ''' 
        Метод определяет причину последнего отключения ОНУ
        '''
        lastdownonu = "Неизвестно"
        if "epon" in self.pon_type:
            lastdownoid = "1.3.6.1.4.1.2011.6.128.1.1.2.57.1.25"
        elif "gpon" in self.pon_type:
            lastdownoid = "1.3.6.1.4.1.2011.6.128.1.1.2.46.1.24"

        parse_onulastdown = r'INTEGER: (?P<onulastdown>.+)'

        onulastdownoid = f'{lastdownoid}.{self.portoid}.{self.onuid}'
        snmpget = SnmpWalk(self.olt_ip, self.snmp_com, onulastdownoid)
        onulastdown = snmpget.snmpget()

        for l in onulastdown:
            match = re.search(parse_onulastdown, l)
            if match:
                last_down_onu = match.group('onulastdown')
                if last_down_onu == '13':
                    lastdownonu = "Power-Off"
                elif last_down_onu == '1' or last_down_onu == '2':
                    lastdownonu = "LOS"
                elif last_down_onu == '9':
                    lastdownonu = "Admin Reset"
                else:
                    lastdownonu = "Неизвестно"

        return lastdownonu


    def getonuuptime(self):
        ''' 
        Метод определяет время включения ОНУ
        '''
        timelist = "Нет времени отключения"
        parse_uptime = r'STRING: "(?P<regtime>\S+ \S+)"'

        if "epon" in self.pon_type:
            datatimeoid = "1.3.6.1.4.1.2011.6.128.1.1.2.103.1.6"

            i = 9
            while i > 0:
                uptimeoid = f'{datatimeoid}.{self.portoid}.{self.onuid}.{i}'
                snmpget = SnmpWalk(self.olt_ip, self.snmp_com, uptimeoid)
                onuuptime = snmpget.snmpget()

                for l in onuuptime:
                    match = re.search(parse_uptime, l)
                    if match:
                        timelist = match.group('regtime')

                i = i - 1
                if timelist != "Нет времени отключения":
                    break

            datatime = timelist.replace("Z", "+03:00")

        elif "gpon" in self.pon_type:
            datatimeoid = "1.3.6.1.4.1.2011.6.128.1.1.2.101.1.6"
            
            uptimeoid = f'{datatimeoid}.{self.portoid}.{self.onuid}'
            snmpget = SnmpWalk(self.olt_ip, self.snmp_com, uptimeoid)
            onuuptime = snmpget.snmpget()

            for l in onuuptime:
                match = re.search(parse_uptime, l)
                if match:
                    timelist = match.group('regtime')

            datatime = timelist.replace("Z", "+03:00")

        return datatime


    def gettimedown(self):
        # Метод определяет время последнего отключения
        timelist = "Нет времени отключения"
        parse_downtime = r'STRING: "(?P<downtime>\S+ \S+)"'

        if "epon" in self.pon_type:
            datatimeoid = "1.3.6.1.4.1.2011.6.128.1.1.2.103.1.7"

            i = 9
            while i > 0:
                timedownoid = f'{datatimeoid}.{self.portoid}.{self.onuid}.{i}'
                snmpget = SnmpWalk(self.olt_ip, self.snmp_com, timedownoid)
                onudowntime = snmpget.snmpget()

                for l in onudowntime:
                    match = re.search(parse_downtime, l)
                    if match:
                        timelist = match.group('downtime')

                i = i - 1
                if timelist != "Нет времени отключения":
                    break

            datatime = timelist.replace("Z", "+03:00")

        elif "gpon" in self.pon_type:
            datatimeoid = "1.3.6.1.4.1.2011.6.128.1.1.2.101.1.7"

            timedownoid = f'{datatimeoid}.{self.portoid}.{self.onuid}'
            snmpget = SnmpWalk(self.olt_ip, self.snmp_com, timedownoid)
            onudowntime = snmpget.snmpget()

            for l in onudowntime:
                match = re.search(parse_downtime, l)
                if match:
                    timelist = match.group('downtime')

            datatime = timelist.replace("Z", "+03:00")

        return datatime


    def getonulevel(self):
        ''' 
        Метод определяет уровни сигнала ОНУ
        '''
        if "epon" in self.pon_type:
            rx_onu_oid = "1.3.6.1.4.1.2011.6.128.1.1.2.104.1.5"
            rx_olt_oid = "1.3.6.1.4.1.2011.6.128.1.1.2.104.1.1"

        if "gpon" in self.pon_type:
            rx_onu_oid = "1.3.6.1.4.1.2011.6.128.1.1.2.51.1.4"
            rx_olt_oid = "1.3.6.1.4.1.2011.6.128.1.1.2.51.1.6"
        
        parse_level = r'INTEGER: (?P<level>.+)'
        # ---- Получение уровня сигнала с ОНУ

        rxonuoid = f'{rx_onu_oid}.{self.portoid}.{self.onuid}'
        snmpget = SnmpWalk(self.olt_ip, self.snmp_com, rxonuoid)
        rxonu = snmpget.snmpget()

        for l in rxonu:
            match = re.search(parse_level, l)
            if match:
                rx_onu = match.group('level')
                level_onu = int(rx_onu)/100

        # ---- Получение результата уровня в сторону ОЛТа
        
        rxoltoid = f'{rx_olt_oid}.{self.portoid}.{self.onuid}'
        snmpget = SnmpWalk(self.olt_ip, self.snmp_com, rxoltoid)
        rxolt = snmpget.snmpget()

        for l in rxolt:
            match = re.search(parse_level, l)
            if match:
                rx_olt = match.group('level')
                level_olt = int(rx_olt)/100-100

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
        stateonuoid = f'{oid_state}.{self.portoid}'
        snmpget = SnmpWalk(self.olt_ip, self.snmp_com, stateonuoid)
        statelist = snmpget.snmpget()
        down_reason = {}
        
        for l in statelist:
            match = re.search(parse_state, l)
            if match:
                onuid = match.group('onuid')
                onustatus = match.group('onustate')
                onustatus = onustatus.replace("1", "ONLINE").replace("2", "OFFLINE").replace("-1", "OFFLINE")

                onulist.append(onuid)
                statuslist.append(onustatus)
    
        # ---- Получение причины отключения ONU
        downcoseoid = f'{oid_cose}.{self.portoid}'
        snmpget = SnmpWalk(self.olt_ip, self.snmp_com, downcoseoid)
        downcoselist = snmpget.snmpget()
        down_reason = {}

        for l in downcoselist:
            match = re.search(parse_down, l)
            if match:
                downcose = match.group('downcose')
                downcose = downcose.replace("-1", "Неизвестно").replace("18", "RING").replace("13", "POWER-OFF").replace("2", "LOS").replace("1", "LOS").replace("3", "LOS").replace("9", "Admin Reset")
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
            rx_onu_oid = "1.3.6.1.4.1.2011.6.128.1.1.2.104.1.5"
            rx_olt_oid = "1.3.6.1.4.1.2011.6.128.1.1.2.104.1.1"
        if "gpon" in self.pon_type:
            rx_onu_oid = "1.3.6.1.4.1.2011.6.128.1.1.2.51.1.4"
            rx_olt_oid = "1.3.6.1.4.1.2011.6.128.1.1.2.51.1.6"

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
        rxonuoid = f'{rx_onu_oid}.{self.portoid}'
        snmpget = SnmpWalk(self.olt_ip, self.snmp_com, rxonuoid)
        rxonu = snmpget.snmpget()

        for l in rxonu:
            match = re.search(parse_tree, l)
            if match:
                onuid = match.group('onuid')
                level = match.group('treelevel')
                level_rx = int(level)/100

                onulist.append(onuid)
                tree_in.append(level_rx)

        # ---- Получение результата уровня в сторону ОЛТа
        parse_tree_sn = r'(\d+){10}.(?P<onuid>\S+) .+INTEGER: (?P<treelevel>\d+)'

        rxonuoid = f'{rx_olt_oid}.{self.portoid}'
        snmpget = SnmpWalk(self.olt_ip, self.snmp_com, rxonuoid)
        rxonu = snmpget.snmpget()

        for l in rxonu:
            match = re.search(parse_tree_sn, l)
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


    def setonureboot(self):
        '''
        Метод для ребута ОНУ
        '''
        parse_reboot = "INTEGER: (?P<setreboot>.+)"
        if "epon" in self.pon_type:
            setonurebootoid = "1.3.6.1.4.1.2011.6.128.1.1.2.57.1.2"

        if "gpon" in self.pon_type:
            setonurebootoid = "1.3.6.1.4.1.2011.6.128.1.1.2.46.1.2"

        onurebootoid = f'{setonurebootoid}.{self.portoid}.{self.onuid} i 1'
        snmpset = SnmpWalk(self.olt_ip, self.snmp_wr, onurebootoid)
        onureboot = snmpset.snmpset()

        setreboot_out = 'Ошибка'
        for l in onureboot:
            match = re.search(parse_reboot, l)
            if match:
                setreboot = match.group('setreboot')
                if setreboot == '1':
                    setreboot_out = "ОНУ перезагаружена"
                else:
                    setreboot_out = "Ошибка"

        return setreboot_out

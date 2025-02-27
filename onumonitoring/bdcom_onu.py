import subprocess
import re
import sqlite3


class BdcomGetOnuInfo:
    ''' Класс для работы с ОНУ BDCOM '''
    def __init__(self, hostname, pon_type, olt_ip, portoid, onuid, snmp_com, pathdb, onumacdec, portoltid):
        self.hostname = hostname
        self.pon_type = pon_type
        self.olt_ip = olt_ip
        self.portoid = portoid
        self.onuid = onuid
        self.snmp_com = snmp_com
        self.pathdb = pathdb
        self.onumacdec = onumacdec
        self.portoltid = portoltid


    def getonustatus(self):
        # Определение статуса ОНУ (В сети/Не в сети)
        if "epon" in self.pon_type:
            ponstateoid = "1.3.6.1.2.1.2.2.1.8"

        if "gpon" in self.pon_type:
            ponstateoid = ""

        cmd = f"snmpwalk -c {self.snmp_com} -v2c {self.olt_ip} {ponstateoid}.{self.portoid}"
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
                ethstatusoid = "1.3.6.1.4.1.3320.101.12.1.1.8"

            if "gpon" in self.pon_type:
                ethstatusoid = ""


            cmd = f"snmpwalk -c {self.snmp_com} -v2c {self.olt_ip} {ethstatusoid}.{self.portoid}"
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


    def getlastdown(self):
        # Метод определяет причину последнего отключения ОНУ
        lastdownonu = "Неизвестно"

        if "epon" in self.pon_type:
            lastdownoid = "1.3.6.1.4.1.3320.101.11.1.1.11"

        if "gpon" in self.pon_type:
            lastdownoid = ""

        cmd = f"snmpwalk -c {self.snmp_com} -v2c {self.olt_ip} {lastdownoid}.{self.portoltid}{self.onumacdec}"
        cmd_to_subprocess = cmd.split()

        process = subprocess.Popen(cmd_to_subprocess, stdout=subprocess.PIPE)
        data = process.communicate(timeout=5)
        data2 = data[-2].decode('utf-8')
        last_down_onu = data2.split()

        if last_down_onu[-1] == '9':
            lastdownonu = "Power-Off"
        elif last_down_onu[-1] == '8':
            lastdownonu = "LOS"
        else:
            lastdownonu = "Неизвестно"


        return lastdownonu

    def getonuuptime(self):
        # Метод определяет время включения ОНУ
        out_uptime = -666
        parse_uptime = r'INTEGER: (?P<uptime>\S+)'

        if "epon" in self.pon_type:
            datatimeoid = "1.3.6.1.4.1.3320.101.10.1.1.80"

        if "gpon" in self.pon_type:
            datatimeoid = ""

        cmd = f"snmpwalk -c {self.snmp_com} -v2c {self.olt_ip} {datatimeoid}.{self.portoid}"
        cmd_to_subprocess = cmd.split()
        process = subprocess.Popen(cmd_to_subprocess, stdout=subprocess.PIPE)

        while True:
            out_time = process.stdout.readline()

            if out_time == b'' and process.poll() is not None:
                break

            if out_time:
                time_data = out_time.decode('utf-8')
                match = re.search(parse_uptime, time_data)
                
                if match:
                    onu_up_time = match.group('uptime')
                    if int(onu_up_time) < 60:
                        out_uptime = f"{onu_up_time} секунд(ы)"
                    elif int(onu_up_time) > 60 and int(onu_up_time) < 3600:
                        onu_up_time = int(onu_up_time)/60
                        out_uptime = f"{int(onu_up_time)} минут(а)"
                    else:
                        onu_up_time = int(onu_up_time)/60/60
                        out_uptime = f"{int(onu_up_time)} часа(ов)"
    
        return out_uptime


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
        parse_data = r'INTEGER: (?P<level>.+)'
        level_onu = "0"

        if "epon" in self.pon_type:
            snmp_rx_onu = ".1.3.6.1.4.1.3320.101.10.5.1.5"
            snmp_rx_olt = ""

        if "gpon" in self.pon_type:
            snmp_rx_onu = ""
            snmp_rx_olt = ""

        # ---- Получение уровня сигнала с ОНУ        
        cmd = f"snmpwalk -c {self.snmp_com} -v2c {self.olt_ip} {snmp_rx_onu}.{self.portoid}"
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
                    rx_onu = match.group('level')
                    level_onu = int(rx_onu)/10


        return level_onu #, format(level_olt, '.2f')
   

    def getleveltree(self):
        # Получение уровня сигнала с дерева (pon порта)
        
        out_tree = ""
        out_tree2 = []
        tree_in = []
        tree_out = []
        onulist = []
        level_rx = ""
        level_tx = ""

        if "epon" in self.pon_type:
            snmp_rx_onu = "1.3.6.1.4.1.3320.101.10.5.1.5"
#            snmp_rx_olt = ""
        if "gpon" in self.pon_type:
            snmp_rx_onu = ""
#            snmp_rx_olt = ""

        parse_tree = r'INTEGER: (?P<level>.+)'

        # ---- Ищем порт олта

        conn = sqlite3.connect(self.pathdb)
        cursor = conn.cursor()
        sqlgetport = f'SELECT * FROM ponports WHERE ip_address="{self.olt_ip}" AND portoid like "{self.portoltid}";'
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
            sqlgetonu = f'''SELECT * FROM {self.pon_type} WHERE oltip="{self.olt_ip}" AND portonu="{onuinfo[getonuport]['portid']}";'''
            getonu = cursor.execute(sqlgetonu)

            for onulist in getonu:
                onuinfo.update({getonuport: {"onu": onulist[1], "portid": onulist[2], "oltip": onulist[4]}})
       
    # ---- Получение уровня сигнала с ОНУ
        out_treeinfo = ["ОНУ ; Сигнал в сторону ОНУ; Сигнал в сторону ОЛТа"]
        for createcmd in onuinfo:
            portonu = createcmd
            portid = onuinfo[createcmd]['portid']
            oltip = onuinfo[createcmd]['oltip']
            onu = onuinfo[createcmd]['onu']
            

            cmd_rx_onu = f"snmpwalk -c {self.snmp_com} -v2c {self.olt_ip} {snmp_rx_onu}.{portid}"
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

                        out_treeinfo.append(str(onu) + " ; " + " 0 " + " ; " + str(level_onu))


        conn.close()
        out_tree = "test"

        return out_treeinfo


    def getstatustree(self):
        # Определение статуса всего дерева (pon порта)

        out_treeinfo = ["ОНУ ; Статус"]
        onulist = []
        statuslist = []
        downlist = []

        out_tree = ""
        out_tree2 = []
        onustatus = ""
        downcose = ""

        if "epon" in self.pon_type:
            oid_state = "1.3.6.1.2.1.2.2.1.8"
            oid_cose = "1.3.6.1.4.1.3320.101.11.1.1.11"
            pon_total = "64"
        if "gpon" in self.pon_type:
            oid_state = "-"
            oid_cose = "-"
            pon_total = "128"


        parse_state = r'INTEGER: (?P<onustate>\d+|-\d+)'
        parse_down = r'(\d+){10}.(?P<onuid>\S+) .+INTEGER: (?P<downcose>\d+|-\d+)'
    

        # ---- Ищем порт олта
        conn = sqlite3.connect(self.pathdb)
        cursor = conn.cursor()
        sqlgetport = f'SELECT * FROM ponports WHERE ip_address="{self.olt_ip}" AND portoid like "{self.portoltid}";'
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
            sqlgetonu = f'''SELECT * FROM {self.pon_type} WHERE oltip="{self.olt_ip}" AND portonu="{onuinfo[getonuport]['portid']}";'''
            getonu = cursor.execute(sqlgetonu)

            for onulist in getonu:
                onuinfo.update({getonuport: {"onu": onulist[1], "portid": onulist[2], "oltip": onulist[4]}})

         # ---- Получение причины отключения ONU
        parse_down_reason = r'(?P<onudec>\d+.\d+.\d+.\d+.\d+.\d+) = INTEGER: (?P<downreason>\d+)'

        cmd_onu_state = f"snmpwalk -c {self.snmp_com} -v2c {self.olt_ip} {oid_cose}.{self.portoltid}"
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

            cmd_onu_state = f"snmpwalk -c {self.snmp_com} -v2c {self.olt_ip} {oid_state}.{portid}"
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

                        out_treeinfo.append(str(onu) + " ; " + str(onustatus))
                        
    

        conn.close()

        return out_treeinfo


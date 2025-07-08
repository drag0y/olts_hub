import re
import sqlite3

from onumonitoring.snmpwalk import SnmpWalk


class BdcomGetOnuInfo:
    ''' Класс для работы с ОНУ BDCOM '''
    def __init__(self, hostname, pon_type, olt_ip, portoid, onuid, snmp_com, pathdb, onumacdec, portoltid, snmp_wr):
        self.hostname = hostname
        self.pon_type = pon_type
        self.olt_ip = olt_ip
        self.portoid = portoid
        self.onuid = onuid
        self.snmp_com = snmp_com
        self.snmp_wr = snmp_wr
        self.pathdb = pathdb
        self.onumacdec = onumacdec
        self.portoltid = portoltid


    def getonustatus(self):
        # Определение статуса ОНУ (В сети/Не в сети)
        onu_state_out = 'Не удалось определить статус ОНУ, ОЛТ не отвечает'
        if "epon" in self.pon_type:
            portstateoid = "1.3.6.1.2.1.2.2.1.8"

        elif "gpon" in self.pon_type:
            portstateoid = ""

        parse_state = "INTEGER: (?P<onustate>.+)"
        onustateoid = f'{portstateoid}.{self.portoid}'
        snmpget = SnmpWalk(self.olt_ip, self.snmp_com, onustateoid)
        onustate = snmpget.snmpget()

        onu_state_out = '3' # Если ОЛТ не отвечает        
        for l in onustate:
            match = re.search(parse_state, l)
            if match:
                onu_state_out = match.group('onustate')

        return onu_state_out


    def getlanstatus(self):
        # Метод определяет статус LAN порта
        parse_lan_state = "INTEGER: (?P<lanstate>.+)"
        lan_out = "Не удалось определить"
        try:
            if "epon" in self.pon_type:
                ethstatusoid = "1.3.6.1.4.1.3320.101.12.1.1.8"

            if "gpon" in self.pon_type:
                ethstatusoid = ""

            lanstateoid = f'{ethstatusoid}.{self.portoid}'
            snmpget = SnmpWalk(self.olt_ip, self.snmp_com, lanstateoid)
            lanstatuslist = snmpget.snmpget()

            for l in lanstatuslist:
                match = re.search(parse_lan_state, l)

                if match:
                    lanstatus = match.group('lanstate')
                    lan_out = lanstatus.replace('1', 'UP').replace('2','DOWN')

                else:
                    lan_out = "Не удалось определить"

        except subprocess.TimeoutExpired:
            lan_out = "Не удалось определить"
        
        return lan_out


    def getlastdown(self):
        # Метод определяет причину последнего отключения ОНУ
        lastdownonu = "Неизвестно"
        parse_reason = "INTEGER: (?P<downreason>.+)"
        if "epon" in self.pon_type:
            lastdownoid = "1.3.6.1.4.1.3320.101.11.1.1.11"

        if "gpon" in self.pon_type:
            lastdownoid = ""

        downreasonoid = f'{lastdownoid}.{self.portoltid}{self.onumacdec}'
        snmpget = SnmpWalk(self.olt_ip, self.snmp_com, downreasonoid)
        downreason = snmpget.snmpget()

        for l in downreason:
            match = re.search(parse_reason, l)
            if match:
                reason = match.group('downreason')

                if reason == '9':
                    lastdownonu = "Power-Off"
                elif reason == '8':
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

        uptimeoid = f'{datatimeoid}.{self.portoid}'
        snmpget = SnmpWalk(self.olt_ip, self.snmp_com, uptimeoid)
        uptime = snmpget.snmpget()
        
        for l in uptime:
            match = re.search(parse_uptime, l)
                
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


    def getonulevel(self):
        # Метод определяет уровни сигнала ОНУ
        parse_level = r'INTEGER: (?P<level>.+)'
        level_onu = "0"
        level_olt = "0"

        if "epon" in self.pon_type:
            rx_onu_oid = "1.3.6.1.4.1.3320.101.10.5.1.5"
            rx_olt_oid = "1.3.6.1.4.1.3320.101.108.1.3"
        elif "gpon" in self.pon_type:
            rx_onu_oid = ""
            rx_olt_oid = ""

        # ---- Получение уровня сигнала с ОНУ       
        rxonuoid = f'{rx_onu_oid}.{self.onuid}' 
        snmpget = SnmpWalk(self.olt_ip, self.snmp_com, rxonuoid)
        rxonu = snmpget.snmpget()

        for l in rxonu:
            match = re.search(parse_level, l)
            if match:
                rx_onu = match.group('level')
                level_onu = int(rx_onu)/10
        
        rxoltoid = f'{rx_olt_oid}.{self.onuid}'         
        snmpget = SnmpWalk(self.olt_ip, self.snmp_com, rxoltoid)
        rxolt = snmpget.snmpget()
        
        for l in rxolt: 
            match = re.search(parse_level, l)
            if match:                
                rx_olt = match.group('level')
                level_olt = int(rx_olt)/10

        return level_onu, level_olt
   

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
            rx_onu_oid = "1.3.6.1.4.1.3320.101.10.5.1.5"
            rx_olt_oid = "1.3.6.1.4.1.3320.101.108.1.3"
        elif "gpon" in self.pon_type:
            rx_onu_oid = ""
            rx_olt_oid = ""

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
            
            rxonuoid = f'{rx_onu_oid}.{portid}'
            snmpget = SnmpWalk(self.olt_ip, self.snmp_com, rxonuoid)
            rxonu = snmpget.snmpget()

            for l in rxonu:
                match = re.search(parse_tree, l)
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

        downcoseoid = f'{oid_cose}.{self.portoltid}'
        snmpget = SnmpWalk(self.olt_ip, self.snmp_com, downcoseoid)
        downcoselist = snmpget.snmpget()
        down_reason = {}

        for l in downcoselist:
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

            stateonuoid = f'{oid_state}.{portid}'
            snmpget = SnmpWalk(self.olt_ip, self.snmp_com, stateonuoid)
            statelist = snmpget.snmpget()
    
            for l in statelist:        
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

                    out_treeinfo.append(str(onu) + " ; " + str(onustatus))
                        
        conn.close()

        return out_treeinfo


    def setonureboot(self):
        '''
        Метод для ребута ОНУ
        '''
        parse_reboot = "INTEGER: (?P<setreboot>.+)"
        if "epon" in self.pon_type:
            setonurebootoid = "1.3.6.1.4.1.3320.101.10.1.1.29"
                
        if "gpon" in self.pon_type:
            setonurebootoid = ""
                    
        onurebootoid = f'{setonurebootoid}.{self.onuid} i 0'
        snmpset = SnmpWalk(self.olt_ip, self.snmp_wr, onurebootoid)
        onureboot = snmpset.snmpset()
                    
        setreboot_out = 'Ошибка. OLT не отвечает или не включен SNMP Write'
        for l in onureboot:
            match = re.search(parse_reboot, l)            
            if match:
                setreboot = match.group('setreboot')
                if setreboot == '0':
                    setreboot_out = "ОНУ перезагаружена"
                else:
                    setreboot_out = "Ошибка"

        return setreboot_out


    def setonudelete(self):
        '''
        Метод для удаления ОНУ
        '''
        parse_delete = "INTEGER: (?P<setdelete>.+)"
        if "epon" in self.pon_type:
            setonudeleteoid = "1.3.6.1.4.1.3320.101.11.1.1.2"
                
        if "gpon" in self.pon_type:
            setonudeleteoid = ""
                    
        onudeleteoid = f'{setonudeleteoid}.{self.portoltid}{self.onumacdec} i 0'
        snmpset = SnmpWalk(self.olt_ip, self.snmp_wr, onudeleteoid)
        onudelete = snmpset.snmpset()
                    
        setdelete_out = 'Ошибка. OLT не отвечает или не включен SNMP Write'
        for l in onudelete:
            match = re.search(parse_delete, l)            
            if match:
                setdelete = match.group('setdelete')
                if setdelete == '0':
                    setdelete_out = "ОНУ удалена"
                else:
                    setdelete_out = "Ошибка"

        return setdelete_out
   

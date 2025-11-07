import re

from cl_onu.onubase import GetOnuInfoBase
from cl_other.snmpwalk import SnmpWalk


class HuaweiGetOnuInfo(GetOnuInfoBase):
    ''' 
    Класс для работы с ОНУ Huawei 
    '''
    def __init__(self, dbonuinfo):
        self.dbonuinfo = isinstance(dbonuinfo, dict)
        self.hostname = dbonuinfo['hostname']
        self.pon_type = dbonuinfo['pon_type']
        self.olt_ip = dbonuinfo['olt_ip']
        self.portoid = dbonuinfo['portoid']
        self.onuid = dbonuinfo['onuid']
        self.snmp_com = dbonuinfo['snmp_com']
        self.snmp_wr = dbonuinfo['snmp_wr']


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
                elif last_down_onu == '18':
                    lastdownonu = "RING"
                else:
                    lastdownonu = "Неизвестно"

        return lastdownonu


    def getonuuptime(self):
        ''' 
        Метод определяет время включения ОНУ
        '''
        timelist = "Нет времени включения"
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


    def setcatvon(self):

        if self.pon_type == "epon":
            oidcatvon = ""
            catv_out = 'Не поддерживается'
        if self.pon_type == "gpon":
            oidcatvon = "1.3.6.1.4.1.2011.6.128.1.1.2.63.1.2"

        parse_catv = "INTEGER: (?P<setcatvon>.+)"
            
        oid_setcatvon = f'{oidcatvon}.{self.portoid}.{self.onuid}.1 i 1'
        snmpset = SnmpWalk(self.olt_ip, self.snmp_wr, oid_setcatvon)
        catvseton = snmpset.snmpset()

        catv_out = 'Ошибка. OLT не отвечает или не включен SNMP Write'

        for c in catvseton:
            match = re.search(parse_catv, c)
            if match:
                setcatvon = match.group('setcatvon')
                if setcatvon == '0':
                    catv_out = "Порт CATV включен"
                else:
                    catv_out = "Ошибка"


        return catv_out


    def setcatvoff(self):

        if self.pon_type == "epon":
            oidcatvoff = ""
            catv_out = 'Не поддерживается'
        if self.pon_type == "gpon":
            oidcatvoff = "1.3.6.1.4.1.2011.6.128.1.1.2.63.1.2"

        parse_catv = "INTEGER: (?P<setcatvoff>.+)"

        oid_setcatvoff = f'{oidcatvoff}.{self.portoid}.{self.onuid}.1 i 2'
        snmpset = SnmpWalk(self.olt_ip, self.snmp_wr, oid_setcatvoff)
        catvsetoff = snmpset.snmpset()

        catv_out = 'Ошибка. OLT не отвечает или не включен SNMP Write'

        for c in catvsetoff:
            match = re.search(parse_catv, c)
            if match:
                setcatvoff = match.group('setcatvoff')
                if setcatvoff == '0':
                    catv_out = "Порт CATV выключен"
                else:
                    catv_out = "Ошибка"


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


    def getethvlandefault(self):
        '''
        Получить мак адреса с LAN порта
        '''
        if "epon" in self.pon_type:
            vlan_onu_oid = "1.3.6.1.4.1.2011.6.128.1.1.2.81.1.5"

        if "gpon" in self.pon_type:
            vlan_onu_oid = "1.3.6.1.4.1.2011.6.128.1.1.2.62.1.7"

        parse_vlan = r'INTEGER: (?P<vlan>.+)'
        # ---- Получение уровня сигнала с ОНУ

        vlanonuoid = f'{vlan_onu_oid}.{self.portoid}.{self.onuid}.1'
        snmpget = SnmpWalk(self.olt_ip, self.snmp_com, vlanonuoid)
        vlanonu = snmpget.snmpget()

        for v in vlanonu:
            match = re.search(parse_vlan, v)
            if match:
                vlan_onu = match.group('vlan')

        return f'VLAN: {vlan_onu}'
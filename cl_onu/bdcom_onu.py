import re

from cl_onu.onubase import GetOnuInfoBase
from cl_other.snmpwalk import SnmpWalk
from funcs.hextodec import convert


class BdcomGetOnuInfo(GetOnuInfoBase):
    '''
    Класс для работы с ОНУ BDCOM
    '''
    def getonustatus(self):
        # Определение статуса ОНУ (В сети/Не в сети)
        onu_state_out = 'Не удалось определить статус ОНУ, ОЛТ не отвечает'
        if "epon" in self.pon_type:
            portstateoid = "1.3.6.1.2.1.2.2.1.8"

        elif "gpon" in self.pon_type:
            portstateoid = "1.3.6.1.2.1.2.2.1.8"

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
                ethstatusoid = "1.3.6.1.4.1.3320.10.4.1.1.4"

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
        onumacdec = convert(self.onu)
        if "epon" in self.pon_type:
            lastdownoid = "1.3.6.1.4.1.3320.101.11.1.1.11"
            downreasonoid = f'{lastdownoid}.{self.portoltid}{onumacdec}'

        elif "gpon" in self.pon_type:
            lastdownoid = "1.3.6.1.4.1.3320.10.3.1.1.35"
            downreasonoid = f'{lastdownoid}.{self.portoid}'

        snmpget = SnmpWalk(self.olt_ip, self.snmp_com, downreasonoid)
        downreason = snmpget.snmpget()

        for l in downreason:
            match = re.search(parse_reason, l)
            if match:
                reason = match.group('downreason')

                if reason == '9' or reason == '1':
                    lastdownonu = "Power-Off"
                elif reason == '8':
                    lastdownonu = "LOS"
                elif reason == '11':
                    lastdownonu = "REBOOT"
                else:
                    lastdownonu = "Неизвестно"

        return lastdownonu


    def getonuuptime(self):
        # Метод определяет время включения ОНУ
        out_uptime = 'Не удалось получить время включения'
        parse_uptime = r'INTEGER: (?P<uptime>\S+)'

        if "epon" in self.pon_type:
            datatimeoid = "1.3.6.1.4.1.3320.101.10.1.1.80"
            parse_uptime = r'INTEGER: (?P<uptime>\S+)'

        if "gpon" in self.pon_type:
            datatimeoid = "1.3.6.1.4.1.3320.10.3.1.1.48"
            parse_uptime = r'= Timeticks: \(\d+\) (?P<uptime>.+)\.'

        uptimeoid = f'{datatimeoid}.{self.portoid}'
        snmpget = SnmpWalk(self.olt_ip, self.snmp_com, uptimeoid)
        uptime = snmpget.snmpget()
        
        for l in uptime:
            match = re.search(parse_uptime, l)

            if "epon" in self.pon_type:              
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

            elif "gpon" in self.pon_type:
                if match:
                    out_uptime = match.group('uptime')

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
            rx_onu_oid = "1.3.6.1.4.1.3320.10.3.4.1.2"
            rx_olt_oid = "1.3.6.1.4.1.3320.10.2.3.1.3"

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
   

    def setonureboot(self):
        '''
        Метод для ребута ОНУ
        '''
        parse_reboot = "INTEGER: (?P<setreboot>.+)"
        if "epon" in self.pon_type:
            setonurebootoid = "1.3.6.1.4.1.3320.101.10.1.1.29"
            onurebootoid = f'{setonurebootoid}.{self.onuid} i 0'

        if "gpon" in self.pon_type:
            setonurebootoid = "1.3.6.1.4.1.3320.10.3.2.1.4"            
            onurebootoid = f'{setonurebootoid}.{self.onuid} i 1'

        snmpset = SnmpWalk(self.olt_ip, self.snmp_wr, onurebootoid)
        onureboot = snmpset.snmpset()
                    
        setreboot_out = 'Ошибка. OLT не отвечает или не включен SNMP Write'
        for l in onureboot:
            match = re.search(parse_reboot, l)            
            if match:
                setreboot = match.group('setreboot')
                if setreboot == '0' or setreboot == '1':
                    setreboot_out = "ОНУ перезагаружена"
                else:
                    setreboot_out = "Ошибка"

        return setreboot_out


    def setonudelete(self):
        '''
        Метод для удаления ОНУ
        '''
        onumacdec = convert(self.onu)
        parse_delete = "INTEGER: (?P<setdelete>.+)"
        if "epon" in self.pon_type:
            setonudeleteoid = "1.3.6.1.4.1.3320.101.11.1.1.2"
            onudeleteoid = f'{setonudeleteoid}.{self.portoltid}{onumacdec} i 0'
               
        if "gpon" in self.pon_type:
            setonudeleteoid = "1.3.6.1.4.1.3320.10.2.6.1.5"
            onudeleteoid = f'{setonudeleteoid}.{self.portoltid}.{self.dbinfo["idonu"]} i 6'
               
        snmpset = SnmpWalk(self.olt_ip, self.snmp_wr, onudeleteoid)
        onudelete = snmpset.snmpset()
                    
        setdelete_out = 'Ошибка. OLT не отвечает или не включен SNMP Write'
        for l in onudelete:
            match = re.search(parse_delete, l)            
            if match:
                setdelete = match.group('setdelete')
                if setdelete == '0' or setdelete == '6':
                    setdelete_out = "ОНУ удалена, опросите ОЛТ"
                else:
                    setdelete_out = "Ошибка"

        return setdelete_out

    def getllidmacsearch(self):
        '''
        Получение абонентских маков с LAN порта ОНУ
        '''
        searchmac_out = []
        parse_mac = 'Hex-STRING: (?P<getmac>\S+ \S+ \S+ \S+ \S+ \S+)'
        parse_set = 'INTEGER: (?P<setllidmac>.+)'

        if "epon" in self.pon_type:
            setllidmacoid = '1.3.6.1.4.1.3320.101.9.2.1.0'
            getmacoid = '1.3.6.1.4.1.3320.152.1.1.3'
            getmacoid2 = '1.3.6.1.4.1.3320.101.9.2.3'
        elif "gpon" in self.pon_type:
            setllidmacoid = '1.3.6.1.4.1.3320.10.15.6.0'
            setmacsearch = '1.3.6.1.4.1.3320.10.15.2.0 i 3'
            getmacoid = '1.3.6.1.4.1.3320.152.1.1.3'
            getmacoid2 = '1.3.6.1.4.1.3320.10.15.1'

        getmac_oid = f'{getmacoid}.{self.onuid}'
        snmpget = SnmpWalk(self.olt_ip, self.snmp_com, getmac_oid)
        searchmac = snmpget.snmpget()

        for l in searchmac:
            match = re.search(parse_mac, l)
            if match:
                mac = match.group('getmac')
                searchmac_out.append(mac.replace(' ', ':'))
            else:
                if 'epon' in self.pon_type:
                    setllidmac_oid = f'{setllidmacoid} i {self.onuid}'
                    snmpset = SnmpWalk(self.olt_ip, self.snmp_wr, setllidmac_oid)
                    setllidmac = snmpset.snmpset()
                elif 'gpon' in self.pon_type:
                    setllidmac_oid = f'{setllidmacoid} i {self.onuid}'
                    snmpset = SnmpWalk(self.olt_ip, self.snmp_wr, setllidmac_oid)
                    snmpset2 = SnmpWalk(self.olt_ip, self.snmp_wr, setmacsearch)
                    setllidmac = snmpset.snmpset()
                    setllidmac2 = snmpset2.snmpset()

                if not setllidmac:
                    searchmac_out = ['Не поддерживается']

                for l in setllidmac:
                    match = re.search(parse_set, l)
                    if match:
                        setmac = match.group('setllidmac')
                        if setmac == f'{self.onuid}':
                            snmpget = SnmpWalk(self.olt_ip, self.snmp_com, getmacoid2)
                            searchmac = snmpget.snmpget()

                            for l in searchmac:
                                match = re.search(parse_mac, l)
                                if match:
                                    mac = match.group('getmac')
                                    searchmac_out.append(mac.replace(' ', ':'))

        return searchmac_out

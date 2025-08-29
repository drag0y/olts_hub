import re
import sqlite3

from cl_onu.onubase import GetOnuInfoBase
from cl_other.snmpwalk import SnmpWalk
from collections import OrderedDict
from datetime import datetime, timedelta, timezone


class CdataGetOnuInfo(GetOnuInfoBase):
    '''
    Класс для работы с ОНУ C-Data
    '''
    def __init__(self, hostname, pon_type, olt_ip, portoid, onuid, snmp_com, pathdb, onumacdec, snmp_wr, platform='C-Data'):
        self.hostname = hostname
        self.pon_type = pon_type
        self.olt_ip = olt_ip
        self.portoid = portoid
        self.onuid = onuid
        self.snmp_com = snmp_com
        self.snmp_wr = snmp_wr
        self.pathdb = pathdb
        self.onumacdec = onumacdec
        self.platform = platform


    def getonustatus(self):
        # Определение статуса ОНУ (В сети/Не в сети)
        onu_state_out = 'Не удалось определить статус ОНУ, ОЛТ не отвечает'
        if "epon" in self.pon_type:
            portstateoid = "1.3.6.1.4.1.17409.2.3.4.1.1.8"
        elif "gpon" in self.pon_type:
            portstateoid = "1.3.6.1.4.1.17409.2.8.4.1.1.7"

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
        pon_type = (self.pon_type or '').lower()

        try:
            if 'epon' in pon_type:
                ethstatusoid = "1.3.6.1.4.1.17409.2.3.5.1.1.5"
            elif 'gpon' in pon_type:
                ethstatusoid = '1.3.6.1.4.1.17409.2.8.5.1.1.5'
            else:
                return "Не удалось определить"

            base_oid = f"{ethstatusoid}.{self.portoid}.0"
            snmp = SnmpWalk(self.olt_ip, self.snmp_com, base_oid)
            rows = snmp.snmpget()  # список строк/байт вида "... = INTEGER: 1"

            state_map = {'1': 'UP', '2': 'DOWN'}
            results = {}

            for line in rows or []:
                if isinstance(line, bytes):
                    line = line.decode(errors='ignore')
                else:
                    line = str(line)

                # Быстрый парс через split, без регэкспов:
                try:
                    oid_part, rhs = line.split(' = INTEGER:', 1)
                    lanidx = int(oid_part.rsplit('.', 1)[1].strip())
                    code = rhs.strip()
                except ValueError:
                    # Запасной вариант — регэксп, если формат другой
                    m = re.search(r'\.(\d+)\s*=\s*INTEGER:\s*(\d+)', line)
                    if not m:
                        continue
                    lanidx, code = int(m.group(1)), m.group(2)

                results[lanidx] = state_map.get(code, f'UNKNOWN({code})')

            if not results:
                return "Не удалось определить"

            ordered = OrderedDict(sorted(results.items()))
            return '; '.join(f'{idx}: {state}' for idx, state in ordered.items())

        except Exception:
            return "Не удалось определить"


    def getlastdown(self):
        # Метод определяет причину последнего отключения ОНУ
        lastdownonu = "Неизвестно"
        parse_reason = "STRING: \"(?P<downreason>.+)\""
        if "epon" in self.pon_type:
            lastdownoid = "1.3.6.1.4.1.34592.1.3.100.12.3.1.1.7"

        if "gpon" in self.pon_type:
            lastdownoid = ".1.3.6.1.4.1.17409.2.8.4.1.1.103"

        downreasonoid = f'{lastdownoid}.{self.onuid}'
        snmpget = SnmpWalk(self.olt_ip, self.snmp_com, downreasonoid)
        downreason = snmpget.snmpget()

        for l in downreason:
            match = re.search(parse_reason, l)
            if match:
                reason = match.group('downreason')

                if reason == 'dying-gasp':
                    lastdownonu = "Power-Off"
                elif reason == 'losi':
                    lastdownonu = "LOS"
                elif reason == 'reboot':
                    lastdownonu = "Перезагрузка"
                else:
                    lastdownonu = reason

        return lastdownonu


    def getonuuptime(self) -> str:
        '''
        Аптайм ОНУ + дата из .29 одной строкой
        '''
        out_uptime = '-666'
        parse_uptime = r'Counter32: (?P<uptime>\S+)'
        if "epon" in self.pon_type:
            datatimeoid = "1.3.6.1.4.1.3320.101.10.1.1.80"

        if "gpon" in self.pon_type:
            datatimeoid = '.1.3.6.1.4.1.17409.2.8.4.1.1.12'

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


    def gettimedown(self):
        '''
        Метод определяет время включения ОНУ
        '''
        out_downtime = 'Нет данных'
        parse_downtime = r'STRING: "(?P<downtime>\S+ \S+)"'

        if 'epon' in self.pon_type:
            datatimeoid = "1.3.6.1.4.1.34592.1.3.100.12.3.1.1.5"
        elif 'gpon' in self.pon_type:
            datatimeoid = '1.3.6.1.4.1.17409.2.8.4.1.1.102'
        else:
            return out_downtime

        downtimeoid = f'{datatimeoid}.{self.onuid}'
        rows = SnmpWalk(self.olt_ip, self.snmp_com, downtimeoid).snmpget()
        if not rows:
            return out_downtime

        for line in rows:
            match = re.search(parse_downtime, line)
            if match:
                timelist = match.group('downtime')
                out_downtime = timelist

        return out_downtime

    
    def getonulevel(self):
        # Метод определяет уровни сигнала ОНУ
        parse_level = r'INTEGER: (?P<level>.+)'
        level_onu = "0"
        level_olt = "0"

        if "epon" in self.pon_type:
            rx_onu_oid = "1.3.6.1.4.1.17409.2.3.4.2.1.4"
            rx_olt_oid = ""
        elif "gpon" in self.pon_type:
            rx_onu_oid = "1.3.6.1.4.1.17409.2.8.4.4.1.4"
            rx_olt_oid = ""

        # ---- Получение уровня сигнала с ОНУ       
        rxonuoid = f'{rx_onu_oid}.{self.onuid}'
        snmpget = SnmpWalk(self.olt_ip, self.snmp_com, rxonuoid)
        rxonu = snmpget.snmpget()

        for l in rxonu:
            match = re.search(parse_level, l)
            if match:
                rx_onu = match.group('level')
                level_onu = int(rx_onu)/100

        rxoltoid = f'{rx_olt_oid}.{self.onuid}'
        snmpget = SnmpWalk(self.olt_ip, self.snmp_com, rxoltoid)
        rxolt = snmpget.snmpget()

        for l in rxolt:
            match = re.search(parse_level, l)
            if match:
                rx_olt = match.group('level')
                level_olt = int(rx_olt)/100

        return level_onu, level_olt


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
            catv_out = 'Не поддерживается'
            catv_level = self.getcatvlevel()
        return catv_out, catv_level
            

    def getcatvlevel(self):
        '''
        Метод для получения уровня сигнала CATV порта
        '''
        parse_catvlevel = r'INTEGER: (?P<level>.+)'
        level_catv = "0"

        snmp_rx_catv = "1.3.6.1.4.1.17409.2.8.4.4.1.100"

        catvleveloid = f'{snmp_rx_catv}.{self.onuid}'

        snmpget = SnmpWalk(self.olt_ip, self.snmp_com, catvleveloid)
        catvlevel = snmpget.snmpget()

        for l in catvlevel:
            match = re.search(parse_catvlevel, l)
            if match:
                rx_catv = match.group('level')
                level_catv = int(rx_catv)/100

        return level_catv


    def setonureboot(self):
        '''
        Метод для ребута ОНУ
        '''
        parse_reboot = "INTEGER: (?P<setreboot>.+)"
        if "epon" in self.pon_type:
            setonurebootoid = "1.3.6.1.4.1.17409.2.3.4.1.1.17"

        if "gpon" in self.pon_type:
            setonurebootoid = '1.3.6.1.4.1.17409.2.8.4.1.1.10'

        onurebootoid = f'{setonurebootoid}.{self.onuid} i 1'
        snmpset = SnmpWalk(self.olt_ip, self.snmp_wr, onurebootoid)
        onureboot = snmpset.snmpset()

        setreboot_out = 'Ошибка. OLT не отвечает или не включен SNMP Write'
        for l in onureboot:
            match = re.search(parse_reboot, l)
            if match:
                setreboot = match.group('setreboot')
                if setreboot == '1':
                    setreboot_out = "ОНУ перезагружена"
                else:
                    setreboot_out = "Ошибка"

        return setreboot_out


    def setonudelete(self):
        '''
        Метод для удаления ОНУ
        '''
        parse_delete = "INTEGER: (?P<setdelete>.+)"
        if "epon" in self.pon_type:
            setonudeleteoid = "1.3.6.1.4.1.17409.2.3.4.5.2.1.4"

        if "gpon" in self.pon_type:
            setonudeleteoid = "1.3.6.1.4.1.17409.2.8.4.6.1.1.8"

        onudeleteoid = f'{setonudeleteoid}.{self.onuid} i 2'
        snmpset = SnmpWalk(self.olt_ip, self.snmp_wr, onudeleteoid)
        onudelete = snmpset.snmpset()

        setdelete_out = 'Ошибка. OLT не отвечает или не включен SNMP Write'
        for l in onudelete:
            match = re.search(parse_delete, l)
            if match:
                setdelete = match.group('setdelete')
                if setdelete == '2':
                    setdelete_out = "ОНУ удалена"
                else:
                    setdelete_out = "Ошибка"

        return setdelete_out


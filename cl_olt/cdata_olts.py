import re
import sqlite3

from cl_other.snmpwalk import SnmpWalk


OFFSETS = {
    "1204": 6,
    "1208": 12,
    "1216": 10,
    "1616": 6,
}

def decode_index(dec_index: int, model: str):
    """
    Возвращает (tree, onu) из десятичного индекса и модели OLT.
    model — строка-ключ для OFFSETS (например, '1208').
    """
    if model not in OFFSETS:
        raise ValueError(f"Неизвестная модель '{model}'. Добавь offset в OFFSETS.")
    dec_index = int(dec_index)
    offset = OFFSETS[model]

    # В hex всегда как минимум 4 байта
    hx = f"{dec_index:08X}"  # например '0100131C'
    # Байты справа налево: b0=ONU, b1=raw_tree, b2=?, b3=?
    b0 = int(hx[-2:], 16)        # ONU
    b1 = int(hx[-4:-2], 16)      # RAW tree
    tree = b1 - offset
    if tree < 0:
        raise ValueError(f"Получился отрицательный номер дерева ({tree}). Проверь offset для модели {model}.")
    return tree, b0


class CdataGetOltInfo:
    ''' Класс для работы с ОЛТами C-Data '''
    def __init__(self, olt_name, olt_ip, snmp_com, pathdb, pontype):
        self.olt_name = olt_name
        self.olt_ip = olt_ip
        self.snmp_com = snmp_com
        self.pathdb = pathdb
        self.pontype = pontype


    def getoltports(self):
        '''
        Метод для запроса портов с ОЛТа
        '''
        oidoltports = "1.3.6.1.2.1.31.1.1.1.1"
        parseports = r'(?P<portoid>\d+)\s*=\s*STRING:\s*\"[^\"]*\b(?P<ponport>PON-\d+|pon\S+)\b[^\"]*\"'

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

        if self.pontype == 'epon':
            oidonulist = "1.3.6.1.4.1.17409.2.3.4.1.1.7"
        if self.pontype == 'gpon':
            oidonulist = '1.3.6.1.4.1.17409.2.8.4.1.1.3'

        parseoutonu = r'(?P<portonu>\d+)=hex-string:(?P<maconu>\S+)'

        # --- Команда опроса OLTа для получения списка зареганых ONU
        snmpget = SnmpWalk(self.olt_ip, self.snmp_com, oidonulist)
        onulist = snmpget.snmpget()
        snmpmodel_oid = 'iso.3.6.1.4.1.17409.2.3.1.2.1.1.3.1'
        snmpmodel_obj = SnmpWalk(self.olt_ip, self.snmp_com, snmpmodel_oid)
        snmpmodel = snmpmodel_obj.snmpget()   # теперь это список/строка

        if snmpmodel:
            value = str(snmpmodel[0])   # берём первую строку
            match = re.search(r'FD(\d+)S', value)
            if match:
                model = match.group(1)

        for l in onulist:
            match = re.search(parseoutonu, l.replace(" ", "").lower())

            if match:
                tree, onu = decode_index(match.group('portonu'), model)
                ponport = 'pon0/0/' + str(tree) + ':' + str(onu)
                listont = self.olt_name, self.olt_ip, ponport, match.group('portonu')
                cursor.execute(query_ports, listont)

        conn.commit()
        conn.close()
       

    def getonulist(self):
        '''
        Функция для запроса списка зареганых ONU и парсинг
        '''
        if self.pontype == 'epon':
            oidonuist = '1.3.6.1.4.1.17409.2.3.4.1.1.7'
            parseoutonu = r'(?P<portonu>\d+)=hex-string:(?P<onu>\S+)'
        elif self.pontype == 'gpon':
            oidonulist = '1.3.6.1.4.1.17409.2.8.4.1.1.3'
            parseoutonu = '(?P<portonu>\d{8}) = (.+: "|.+: )(?P<onu>(\S+ ){7}\S+|.+(?="))'

        conn = sqlite3.connect(self.pathdb)
        cursor = conn.cursor()

        query = "INSERT into epon(maconu, portonu, idonu, oltip, oltname) values (?, ?, ?, ?, ?)"
        querygpon = "INSERT into gpon(snonu, portonu, idonu, oltip, oltname) values (?, ?, ?, ?, ?)"

        # --- Команда опроса OLTа
        snmpget = SnmpWalk(self.olt_ip, self.snmp_com, oidonulist)
        onulist = snmpget.snmpget()

        # --- Парсинг Мак адресов и добавление в базу
        if self.pontype == "epon":
            for l in onulist:
                match = re.search(parseoutonu, l.replace(" ", "").lower())
                if match:
                    listont = match.group('onu'), match.group('portonu'), match.group('portonu'), self.olt_ip, self.olt_name
                    cursor.execute(query, listont)
        
        if self.pontype == "gpon":
            try:
                for l in onulist:
                    match = re.search(parseoutonu, l.replace('\\"', '"').replace("\\\\", "\\"))
                    if match:
                        if len(match.group('onu')) > 16:
                            listont = match.group('onu').lower().replace(" ", ""), match.group('portonu'), match.group('portonu'), self.olt_ip, self.olt_name
                            cursor.execute(querygpon, listont)
                        elif len(match.group('onu')) < 16:
                            listont = match.group('onu').encode().hex(), match.group('portonu'), match.group('portonu'), self.olt_ip, self.olt_name
                            cursor.execute(querygpon, listont)
            except ValueError:
                print("Кривая ONU")

            conn.commit()
            conn.close()


    def ponstatustree(self, olt_port):
        '''
        Статус и уровни с дерева (порта) ОЛТа C-data
        '''
        if "epon" in self.pontype:
            oid_state = "1.3.6.1.4.1.17409.2.3.4.1.1.8"
            oid_down_reason = "1.3.6.1.4.1.34592.1.3.100.12.3.1.1.7"
            oid_rx_onu = "1.3.6.1.4.1.17409.2.3.4.2.1.4"
            oid_rx_olt = ""
        if "gpon" in self.pontype:
            oid_state = "1.3.6.1.4.1.17409.2.8.4.1.1.7"
            oid_down_reason = "1.3.6.1.4.1.17409.2.8.4.1.1.103"
            oid_rx_onu = "1.3.6.1.4.1.17409.2.8.4.4.1.4"
            oid_rx_olt = ""

        parse_state = r'INTEGER: (?P<onustate>\d+|-\d+)'
        parse_down = r'(\d+){10}.(?P<onuid>\S+) .+INTEGER: (?P<downcose>\d+|-\d+)'
        parse_tree = r'INTEGER: (?P<level>.+)'

        # ---- Ищем порт олта
        conn = sqlite3.connect(self.pathdb)
        cursor = conn.cursor()

        portonu_out = "Не удалось определить порт"

        sqlgetallonu = f'SELECT * FROM ponports WHERE ip_address="{self.olt_ip}" AND ponport like "{olt_port}:%" AND length(portoid) > 4;'
        getallonu = cursor.execute(sqlgetallonu)

        oltportinfo = []
        for onu in getallonu:
            oltportinfo.append(
                            {
                            'ponport': onu[3],
                            'portoid': onu[4],
                            }
                        ) 
        
        db_onuinfo = []
        for o in oltportinfo:
            # Создаём список со словарями, в которых информация об ОНУ из БД
            onuid = o['ponport'].split(':')[1]
            ponport = o['ponport'].split(':')[0]
            sqlgetonu = f'''SELECT * FROM {self.pontype} WHERE oltip="{self.olt_ip}" AND portonu="{o['portoid']}";'''
            getonu = cursor.execute(sqlgetonu)

            for ol in getonu:
                db_onuinfo.append(
                            {
                            'id' :     onuid,
                            'onu':     ol[1],
                            'ponport': ponport,
                            "portoid": o['portoid'],
                            }
                        )
        conn.close()

        # ---- Получение статуса с дерева
        out_tree = []
        for oi in db_onuinfo:
            # Перебираем список и по очереди опрашиваем ОНУ
            onustateoid = f'''{oid_state}.{oi['portoid']}'''
            snmpget = SnmpWalk(self.olt_ip, self.snmp_com, onustateoid)
            onustate = snmpget.snmpget()

            status_tree = []
            for s in onustate:
                match = re.search(parse_state, s)
                if match:
                    onustatus = match.group('onustate')
                    onustatus = onustatus.replace("1", "ONLINE").replace("2", "OFFLINE").replace("-1", "OFFLINE")

                    if onustatus == "OFFLINE":
                        # ---- Получение причины отключения ONU
                        parse_down_reason = r'(?P<onudec>\d+) = STRING: \"(?P<downreason>.*)\"'

                        onudownreasonoid = f'''{oid_down_reason}.{oi['portoid']}'''
                        snmpget = SnmpWalk(self.olt_ip, self.snmp_com, onudownreasonoid)
                        onudownreason = snmpget.snmpget()
                        for l in onudownreason:
                            match = re.search(parse_down_reason, l)
                            if match:
                                onudownreason = match.group('downreason')
                                onudownreason = onudownreason.replace("losi", "LOS").replace("dying-gasp", "POWER-OFF").replace(" ", "Неизвестно")
                            else:
                                onustatus = 'Неизвестно'
                        rx_onu = 0.00
                        rx_olt = 0.00
                        
                    elif onustatus == 'ONLINE':
                        # Если ОНУ в сети, смотрим уровни сигналов
                        rxonuoid = f'''{oid_rx_onu}.{oi['portoid']}'''
                        rxoltoid = f'''{oid_rx_olt}.{oi['portoid']}'''
                        snmpget = SnmpWalk(self.olt_ip, self.snmp_com, rxonuoid)
                        rxonu = snmpget.snmpget()
                        for l in rxonu:
                            match = re.search(parse_tree, l)
                            if match:
                                level_onu = match.group('level')
                                rx_onu = int(level_onu)/100
                            else:
                                rx_onu = 0.00

#                        snmpget = SnmpWalk(self.olt_ip, self.snmp_com, rxoltoid)
#                        rxolt = snmpget.snmpget()
#                        for l in rxolt:
#                            match = re.search(parse_tree, l)
#                            if match:
#                                level_olt = match.group('level')
#                                rx_olt = int(level_olt)/100
#                            else:
#                               rx_olt = 0.00
                        rx_olt = 0.00

                else:
                    onustatus = 'Удалена, опросите ОЛТ'
                    rx_onu = 0.00
                    rx_olt = 0.00

                out_tree.append(
                            {
                            'id':         oi['id'],
                            'onu':        oi['onu'],
                            'onu_status': onustatus,
                            'rx_onu':     rx_onu,
                            'rx_olt':     rx_olt,
                            }
                        )

        return out_tree


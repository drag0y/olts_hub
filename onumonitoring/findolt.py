import sqlite3
import os
from ping3 import ping
from dotenv import load_dotenv

from onumonitoring.oltinfo import OltInfo

load_dotenv()

PF_HUAWEI = os.getenv('PF_HUAWEI')
PF_BDCOM = os.getenv('PF_BDCOM')


class FindOlt:
    """
    Класс для поиска ОЛТа, и определения состояния и параметров
    """
    def __init__(self, pathdb, olt_id):
        # ---- Подключение к базе и поиск ОЛТа
        self.pathdb = pathdb
        self.olt_id = olt_id
    
   
    def olt_info(self):     
        olt_state = ''
        unregonu = []
        conn = sqlite3.connect(self.pathdb)
        cursor = conn.cursor()
        # Поиск ОЛТа
        olt_info = cursor.execute(f'SELECT * FROM olts WHERE number="{self.olt_id}";')

        for o in olt_info:
            self.hostname = o[1]
            self.olt_ip = o[2]
            self.platform = o[3]
            self.pontype = o[4]
        # Сбор списка портов
        port_info = cursor.execute(f'SELECT * from ponports WHERE ip_address="{self.olt_ip}";')

        self.pon_ports = []
        for p in port_info:
            if ':' in p[3]:
                pass
            else:
               self.ports = p[3]
               self.pon_ports.append(self.ports)

        self.pon_ports.sort()
        # Считаем количество ОНУ на ОЛТе
        onucount = cursor.execute(f'select count(*) from {self.pontype} where oltip="{self.olt_ip}"')
        for c in onucount:
            self.countonu = c[0]

        conn.close()    
        
        oltinfo_params = {
        "pathdb": self.pathdb,
        "olt_ip": self.olt_ip,
        "olt_port": '',
        "platform": self.platform,
        "pontype": self.pontype,
        }
        # Пингуем ОЛТ
        p = ping(f'{self.olt_ip}')

        if p == None:
            olt_state = 'Не в сети'
        else:
            olt_state = 'В сети'
            # Ищем незарегистрированные ОНУ (только Huawei)
            if PF_HUAWEI in self.platform:
                oltinfo = OltInfo(**oltinfo_params)
                unregonu = oltinfo.hwunregonu()
            else:
                unregonu = []

        olt_information = {
        "oltid": self.olt_id,
        "oltname": self.hostname,
        "olt_state": olt_state,
        "ip_address": self.olt_ip,
        "platform": self.platform,
        "countonu": self.countonu,
        "ports": self.pon_ports,
        "unregonu": unregonu,
        }

        return olt_information

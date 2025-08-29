import sqlite3
import os
from ping3 import ping

from cl_db.db_cfg import Init_Cfg
from cl_olt.huawei_olts import HuaweiGetOltInfo
from cl_olt.bdcom_olts import BdcomGetOltInfo
from cl_olt.cdata_olts import CdataGetOltInfo


class FindOlt:
    """
    Класс для поиска ОЛТа, и определения состояния и параметров
    """
    def __init__(self, pathdb, olt_id, olt_port=''):
        # ---- Подключение к базе и поиск ОЛТа
        snmp_cfg = Init_Cfg(pathdb)
        cfg = snmp_cfg.getcfg()
        self.PF_HUAWEI = cfg['PL_H']
        self.PF_BDCOM = cfg['PL_B']
        self.PF_CDATA = cfg['PL_C']
        self.SNMP_READ_H = cfg['SNMP_READ_H']
        self.SNMP_READ_B = cfg['SNMP_READ_B']
        self.SNMP_READ_C = cfg['SNMP_READ_C']

        self.pathdb = pathdb
        self.olt_id = olt_id
        self.olt_port = olt_port
    
        # Поиск ОЛТа
        conn = sqlite3.connect(self.pathdb)
        cursor = conn.cursor()
        olt_info = cursor.execute(f'SELECT * FROM olts WHERE number="{self.olt_id}";')

        for o in olt_info:
            self.hostname = o[1]
            self.olt_ip = o[2]
            self.platform = o[3]
            self.pontype = o[4]

        if olt_port:
            ponport = cursor.execute(f'SELECT * FROM ponports WHERE ip_address="{self.olt_ip}" AND ponport LIKE "{self.olt_port}";')
            for p in ponport:
                self.port_oid = p[4]

        conn.close()


    def oltinfo(self):     
        olt_state = ''
        unregonu = []
        conn = sqlite3.connect(self.pathdb)
        cursor = conn.cursor()
        # Сбор списка портов
        port_info = cursor.execute(f'SELECT * from ponports WHERE ip_address="{self.olt_ip}";')
        self.pon_ports = []
        for p in port_info:
            if ':' in p[3]:
                self.ports = p[3].split(':')[0]
                self.pon_ports.append(self.ports)
            else:
               self.ports = p[3]
               self.pon_ports.append(self.ports)
        self.pon_ports_out = list(dict.fromkeys(self.pon_ports))

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
        if p == None or p == False:
            olt_state = 'Не в сети'
        else:
            olt_state = 'В сети'
            # Ищем незарегистрированные ОНУ (только Huawei)
            if self.PF_HUAWEI in self.platform:
                oltinfo = HuaweiGetOltInfo(self.hostname, self.olt_ip, self.SNMP_READ_H, self.pathdb, self.pontype)
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
        "ports": self.pon_ports_out,
        "pontype": self.pontype,
        "unregonu": unregonu,
        }
        
        return olt_information


    def ponportstatus(self):
        '''
        Уровни и статус пон дерева
        '''
        if self.PF_HUAWEI in self.platform:
            olt_info = HuaweiGetOltInfo(self.hostname, self.olt_ip, self.SNMP_READ_H, self.pathdb, self.pontype) 
            out_tree = olt_info.hwponstatustree(self.port_oid)

        elif self.PF_BDCOM in self.platform:
            olt_info = BdcomGetOltInfo(self.hostname, self.olt_ip, self.SNMP_READ_B, self.pathdb, self.pontype)
            out_tree = olt_info.bdcomponstatustree(self.port_oid) 

        elif self.PF_CDATA in self.platform:
            olt_info = CdataGetOltInfo(self.hostname, self.olt_ip, self.SNMP_READ_C, self.pathdb, self.pontype)
            out_tree = olt_info.cdataponstatustree(self.olt_port)

        return out_tree  

import sqlite3
import os

from cl_db.db_cfg import Init_Cfg
from cl_db.db_onu import DBOnuInfo
from cl_onu.bdcom_onu import BdcomGetOnuInfo
from cl_onu.huawei_onu import HuaweiGetOnuInfo
from cl_onu.cdata_onu import CdataGetOnuInfo


class FindOnu:
    """
    Класс для поиска ОНУ, и определения состояния
    """
    def __init__(self, useronu, pathdb):
        self.useronu = useronu.lower().replace(' ','').replace(':', '').replace('.', '').replace('hwtc', '48575443').replace('-', '')
        self.pathdb = pathdb
        if len(self.useronu) == 12:
            pon_type = 'epon'
        elif len(self.useronu) == 16:
            pon_type = 'gpon'
        else:
            raise TypeError('Wrong MAC or SN')

        snmp_cfg = Init_Cfg(pathdb)
        self.cfg = snmp_cfg.getcfg()
               
        onuinfo = DBOnuInfo(pathdb, self.useronu, pon_type)
        self.onulist = onuinfo.getonufromdb()
        if not self.onulist:
            raise ValueError('ONU not found')

        
    def onuinfo(self):
        '''
        Состояние ОНУ и опрос
        '''
        out_onuinfo = []
        for o in self.onulist:
            if self.cfg['PL_H'] in o['platform']:
                onu_params = {
                        "onu":      o['mac/sn'],
                        "hostname": o['oltname'],
                        "pon_type": o['pontype'],
                        "olt_ip":   o['oltip'],
                        "portoid":  o['portid'],
                        "onuid":    o['onuid'],
                        "snmp_com": self.cfg['SNMP_READ_H'],
                        "snmp_wr":  self.cfg['SNMP_CONF_H'],
                        }
                self.onuid = o['onuid']
                self.portonu_out = o['portonu']
                onu_info = HuaweiGetOnuInfo(onu_params)
                onu_state = onu_info.getonustatus()

            elif self.cfg['PL_B'] in o['platform']:

                conn = sqlite3.connect(self.pathdb)
                cursor = conn.cursor()

                self.portonu_out = o['portonu'].split(":")
                self.portolt = self.portonu_out[0]
                self.idonu = self.portonu_out[1]
                ponportolt2 = cursor.execute(f'''SELECT portoid FROM ponports WHERE ip_address="{o['oltip']}" AND ponport="{self.portolt}";''')

                if ponportolt2:
                    for portolt2 in ponportolt2:
                        portoltid = portolt2[0]
                onu_params = {
                        "onu":       o['mac/sn'],
                        "hostname":  o['oltname'],
                        "pon_type":  o['pontype'],
                        "olt_ip":    o['oltip'],
                        "portoid":   o['portid'],
                        "onuid":     o['onuid'],
                        "snmp_com":  self.cfg['SNMP_READ_B'],
                        "snmp_wr":   self.cfg['SNMP_CONF_B'],
                        "portoltid": portoltid,
                        }
                conn.close()
                onu_info = BdcomGetOnuInfo(onu_params)
                onu_state = onu_info.getonustatus()
                self.onuid = self.idonu
                self.portonu_out = self.portonu_out[0]

            elif self.cfg['PL_C'] in o['platform']:

                conn = sqlite3.connect(self.pathdb)
                cursor = conn.cursor()

                self.portonu_out = o['portonu'].split(":")
                self.portolt = self.portonu_out[0]
                self.idonu = self.portonu_out[1]
                onu_params = {
                    "onu":      o['mac/sn'],
                    "hostname": o['oltname'],
                    "pon_type": o['pontype'],
                    "olt_ip":   o['oltip'],
                    "portoid":  o['portid'],
                    "onuid":    o['onuid'],
                    "snmp_com": self.cfg['SNMP_READ_C'],
                    "snmp_wr":  self.cfg['SNMP_CONF_C'],
                    }
                conn.close()

                onu_info = CdataGetOnuInfo(onu_params)
                onu_state = onu_info.getonustatus()
                self.onuid = self.idonu
                self.portonu_out = self.portonu_out[0]

            # ---- Если ONU в сети, то для опроса вызываем следующие методы
            state_lan = '-'
            catv_state = '-'
            catv_level = -0.0
            time_up = '-'
            time_down = '-'
            reason_down = '-'
            level_onu = -0.0
            level_olt = -0.0
            lan_mac = []

            if onu_state == '1':
                onustate = "В сети"

                state_lan = onu_info.getlanstatus()
                reason_down = onu_info.getlastdown()
                time_up = onu_info.getonuuptime()
                time_down = onu_info.gettimedown()
                level_onu, level_olt = onu_info.getonulevel() # Уровень сигнала
                lan_mac = onu_info.getllidmacsearch()
                if self.cfg['PL_H'] in o['platform']:
                    catv_state, catv_level = onu_info.getcatvstate()
                elif self.cfg['PL_C'] in o['platform']:
                    catv_state, catv_level = onu_info.getcatvstate()
                else:
                    catv_state = onu_info.getcatvstate()
                    catv_level = onu_info.getcatvlevel()

            # ---- Если ONU не в сети, то вызываем следующие методы
            elif onu_state == '2':
                onustate = "Не в сети"
                time_down = onu_info.gettimedown()
                reason_down = onu_info.getlastdown()
                  
            else:
                onustate = "Не удалось определить состояние ОНУ, возможно ОЛТ не в сети или не отвечает"

            onuinformation = {
                "mac/sn": o['mac/sn'],
                "onu_state": int(onu_state),
                "oltname": o['oltname'],
                "oltip": o['oltip'],
                "olt_id": o['oltid'],
                "iface_state": onustate,
                "iface_name": self.portonu_out,
                "onuid": self.onuid,
                "lanstate": state_lan,
                "lan_mac": lan_mac,
                "catvstate": catv_state,
                "catvlevel": catv_level,
                "timeup": time_up,
                "timedown": time_down,
                "reason_offline": reason_down,
                "level_onu_rx": level_onu,
                "level_olt_rx": level_olt,
                }
            out_onuinfo.append(onuinformation)
        return out_onuinfo

#import subprocess
import sqlite3
import os
from dotenv import load_dotenv

from onumonitoring.bdcom_onu import BdcomGetOnuInfo
from onumonitoring.huawei_onu import HuaweiGetOnuInfo


load_dotenv()

SNMP_READ_H = os.getenv('SNMP_READ_H')
SNMP_READ_B = os.getenv('SNMP_READ_B')
SNMP_CONF_H = os.getenv('SNMP_CONF_H')
SNMP_CONF_B = os.getenv('SNMP_CONF_B')
PF_HUAWEI = os.getenv('PF_HUAWEI')
PF_BDCOM = os.getenv('PF_BDCOM')


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
                
        # ---- Подключение к базе и поиск ONU
        conn = sqlite3.connect(self.pathdb)
        cursor = conn.cursor()
        if pon_type == "epon":
            findonu = cursor.execute(f'select * from epon where maconu glob "{useronu}"')
        if pon_type == "gpon":
            findonu = cursor.execute(f'select * from gpon where snonu glob "{useronu}"')

        for onuinfo in findonu:
            self.portid = onuinfo[2]
            self.onuid = onuinfo[3]
            self.olt_ip = onuinfo[4]
            self.olt_name = onuinfo[5]    

        ponportonu = cursor.execute(f'SELECT * FROM ponports WHERE ip_address="{self.olt_ip}" AND portoid="{self.portid}";')
             
        self.portonu_out = "Не удалось определить порт"
        for portonu in ponportonu:
            self.portonu_out = portonu[3]
    
        platf = cursor.execute(f'SELECT * FROM olts WHERE ip_address="{self.olt_ip}";')
        
        self.onulist = []
        for platformonu in platf:
            # Если платформа Huawei
            self.olt_id = platformonu[0]
            if PF_HUAWEI in platformonu[3]:
                self.platform = "huawei"

                onu_params = {
                    "hostname": self.olt_name,
                    "pon_type": pon_type,
                    "olt_ip": self.olt_ip,
                    "portoid": self.portid,
                    "onuid": self.onuid,
                    "snmp_com": SNMP_READ_H,
                    "pathdb": self.pathdb,
                    "snmp_conf": SNMP_CONF_H,
                    }
                self.onulist.append(onu_params)
    
            if PF_BDCOM in platformonu[3]:
                # Если платформа BDCOM 
                self.platform = "bdcom"
                onumacdec = self.convert()
                self.portonu_out = self.portonu_out.split(":")
                self.portolt = self.portonu_out[0]
                self.idonu = self.portonu_out[1]
                ponportolt2 = cursor.execute(f'SELECT portoid FROM ponports WHERE ip_address="{self.olt_ip}" AND ponport="{self.portolt}";')
                if ponportolt2:
                    for portolt2 in ponportolt2:
                        portoltid = portolt2[0]
                
                self.onu_params = {
                    "hostname": self.olt_name,
                    "pon_type": pon_type,
                    "olt_ip": self.olt_ip,
                    "portoid": self.portid,
                    "onuid": self.onuid,
                    "snmp_com": SNMP_READ_B,
                    "pathdb": self.pathdb,                
                    "onumacdec": onumacdec,
                    "portoltid": portoltid,
                    }
        conn.close()

    def onuinfo(self):
        '''
        Состояние ОНУ и опрос
        '''
        out_onuinfo = []
        onustate = '-'
        state_lan = '-'
        catv_state = '-'
        catv_level = -0.0
        time_up = '-'
        time_down = '-'
        reason_down = '-'
        level_onu = -0.0
        level_olt = -0.0

        if "huawei" in self.platform:
            for o in self.onulist:
                onu_info = HuaweiGetOnuInfo(**o)
                onu_state = onu_info.getonustatus()

                # ---- Если ONU в сети, то для опроса вызываем следующие методы
                if onu_state == '1':
                    onustate = "В сети"
                    level_onu, level_olt = onu_info.getonulevel() # Уровень сигнала
                    state_lan = onu_info.getlanstatus()
                    catv_state, catv_level = onu_info.getcatvstate()
                    time_up = onu_info.getonuuptime()
                    time_down = onu_info.gettimedown()
                    reason_down = onu_info.getlastdown()

                # ---- Если ONU не в сети, то вызываем следующие методы
                elif onu_state == '2':
                    onustate = "Не в сети"
                    time_down = onu_info.gettimedown()
                    reason_down = onu_info.getlastdown()

        elif "bdcom" in self.platform:
            onu_info = BdcomGetOnuInfo(**self.onu_params)
            onu_state = onu_info.getonustatus()

            if onu_state == "1":
                onustate = "В сети"
                level_onu, level_olt = onu_info.getonulevel()
                state_lan = onu_info.getlanstatus()
                time_up = onu_info.getonuuptime()
                time_up = time_up.replace("-666 часов", "Не поддерживается")
                self.onuid = self.idonu
                self.portonu_out = self.portonu_out[0]

            if onu_state == "2":
                onustate = "Не в сети"
                reason_down = onu_info.getlastdown()
                self.onuid = self.idonu
                self.portonu_out = self.portonu_out[0]

        onuinformation = {
            "mac/sn": self.useronu,
            "onu_state": int(onu_state),
            "oltname": self.olt_name,
            "olt_id": self.olt_id,
            "iface_state": onustate,
            "iface_name": self.portonu_out,
            "onuid": self.onuid,
            "lanstate": state_lan,
            "catvstate": catv_state,
            "catvlevel": float(catv_level),
            "timeup": time_up,
            "timedown": time_down,
            "reason_offline": reason_down,
            "level_onu_rx": float(level_onu),
            "level_olt_rx": float(level_olt),
            }

        out_onuinfo.append(onuinformation)

        return out_onuinfo


    def convert(self):
    # Метод конвертирует МАК ОНУ в десятичный формат
        outmacdec = ""
        n = 2
        out = [self.useronu[i:i+n] for i in range(0, len(self.useronu), n)]
        
        for i in out:
            dece = int(i, 16)
            outmacdec = outmacdec + "." + str(dece)

        return outmacdec


    def onucatvon(self):
        # Включить CATV порт
        if "huawei" in self.platform:
            for o in self.onulist:
                onu_on = HuaweiGetOnuInfo(**o)
                outinformation = onu_on.setcatvon()

            return outinformation

        
    def onucatvoff(self):
        # Выключить CATV порт
        if "huawei" in self.platform:
            for o in self.onulist:
                onu_off = HuaweiGetOnuInfo(**o)
                outinformation = onu_off.setcatvoff()

            return outinformation


    def onureboot(self):
        '''
        Reboot ONU
        '''
        rebootonu_out = 'ERROR'
        if "bdcom" in self.platform:
            onu_reboot = BdcomGetOnuInfo(**self.onu_params)
            rebootonu_out = onu_reboot.setonureboot()
        elif "huawei" in self.platform:
            for o in self.onulist:
                onu_reboot = HuaweiGetOnuInfo(**o)
                rebootonu_out = onu_reboot.setonureboot()

        return rebootonu_out

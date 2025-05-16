import subprocess
import sqlite3
import os

from onumonitoring.bdcom_onu import BdcomGetOnuInfo
from onumonitoring.huawei_onu import HuaweiGetOnuInfo
#from config import SNMP_READ_H, SNMP_READ_B, SNMP_CONF_H, SNMP_CONF_B, PF_HUAWEI, PF_BDCOM

from dotenv import load_dotenv


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
    def __init__(self, useronu, pon_type, pathdb):

        self.useronu = useronu
        self.pon_type = pon_type
        self.pathdb = pathdb
        
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

        ponportonu = cursor.execute(f'SELECT ponport FROM ponports WHERE ip_address="{self.olt_ip}" AND portoid="{self.portid}";')
             
        self.portonu_out = "Не удалось определить порт"
        for portonu in ponportonu:
            self.portonu_out = portonu[0]
    
        platf = cursor.execute(f'SELECT platform FROM olts WHERE ip_address="{self.olt_ip}";')    
        
        for platformonu in platf:
            # Если платформа Huawei
            if PF_HUAWEI in platformonu[0]:
                self.platform = "huawei"

                self.onu_params = {
                    "hostname": self.olt_name,
                    "pon_type": self.pon_type,
                    "olt_ip": self.olt_ip,
                    "portoid": self.portid,
                    "onuid": self.onuid,
                    "snmp_com": SNMP_READ_H,
                    "pathdb": self.pathdb,
                    "snmp_conf": SNMP_CONF_H,
                    }

            if PF_BDCOM in platformonu[0]:
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
                    "pon_type": self.pon_type,
                    "olt_ip": self.olt_ip,
                    "portoid": self.portid,
                    "onuid": self.onuid,
                    "snmp_com": SNMP_READ_B,
                    "pathdb": self.pathdb,                
                    "onumacdec": onumacdec,
                    "portoltid": portoltid,
                    }

        conn.close()

    def surveyonu(self):
    # ---- Состояние ОНУ

        if "huawei" in self.platform:
            onu_info = HuaweiGetOnuInfo(**self.onu_params)
            onu_state = onu_info.getonustatus()

            # ---- Если ONU в сети, то для опроса вызываем следующие методы
            if onu_state == '1':
                onustate = "В сети"
                level_onu, level_olt = onu_info.getonulevel() # Уровень сигнала

                hostname = f"ONU найдена на OLTе:; {self.olt_name}"
                port = f"Порт: {self.portonu_out}; id: {self.onuid}"
                state_onu = f"Состояние ONU {self.useronu}:; {onustate}"
                state_lan = f"Статус LAN порта:; {onu_info.getlanstatus()}"
                catv_out, catv_level = onu_info.getcatvstate()
                state_catv = f"Статус CATV порта:; {catv_out}"
                level_catv = f"Уровень сигнала CATV:; {catv_level}"
                time_up = f"Время включения:; {onu_info.getonuuptime()}"
                time_down = f"Время последнего отключения:; {onu_info.gettimedown()}"
                reason_down = f"Причина последнего отключения:; {onu_info.getlastdown()}"
                lvl_onu = f"Уровень сигнала с ОЛТа:;  {level_onu}"
                lvl_olt = f"Уровень сигнала с ОНУ:;   {level_olt}"

                outinformation = state_onu, hostname, port, state_lan, state_catv, level_catv, time_up, time_down, reason_down, lvl_onu, lvl_olt


                # ---- Если ONU не в сети, то вызываем следующие методы
            elif onu_state == '2':
                onustate = "Не в сети"

                hostname = f"ONU найдена на OLTе:; {self.olt_name}"
                port = f"Порт: {self.portonu_out}; id: {self.onuid}"
                state_onu = f"Состояние ONU {self.useronu}:; {onustate}"
                time_down = f"Время отключения:; {onu_info.gettimedown()}"
                reason_down = f"Причина отключения:; {onu_info.getlastdown()}"

                outinformation = state_onu, hostname, port, time_down, reason_down
            # ---- Если состояние ONU определить не удалось
            else:
                outinformation = f"Состояние ONU {self.useronu}: Не удалось определить {onu_state}"

            return outinformation

        if "bdcom" in self.platform:
            onuinformation = []
            onu_info = BdcomGetOnuInfo(**self.onu_params)
            onu_state = onu_info.getonustatus()

            if onu_state == "1":
                onustate = "В сети"
                hostname = f"ONU найдена на OLTе:; {self.olt_name}"
                port = f"Порт: {self.portolt} ; id: {self.idonu}"
                state_onu = f"Состояние ONU {self.useronu}:; {onustate}"
                onu_level = f"Уровень сигнала с ОНУ:; {onu_info.getonulevel()}"
                state_lan = f"Статус LAN порта:; {onu_info.getlanstatus()}"
                up_time = f"Время в сети:; {onu_info.getonuuptime()}"
                up_time = up_time.replace("-666 часов", "Не поддерживается")

                onuinformation = state_onu, hostname, port, state_lan, up_time, onu_level

            if onu_state == "2":
                onustate = "Не в сети"
                hostname = f"ONU найдена на OLTе:; {self.olt_name}"
                state_onu = f"Состояние ONU {self.useronu}:; {onustate}"
                port = f"Порт: {self.portolt} ; id: {self.idonu}"
                reason_down = f"Причина отключения:; {onu_info.getlastdown()}"

                onuinformation = state_onu, hostname, port, reason_down

            return onuinformation


    def surveytreelevel(self):
        # Запрос уровней сигнала со всего дерева (pon порта)
        if "huawei" in self.platform:
            onu_info = HuaweiGetOnuInfo(**self.onu_params)
            outinformation = onu_info.getleveltree()
            
            return outinformation

        elif "bdcom" in self.platform:
#            outinformation = []
            onu_info = BdcomGetOnuInfo(**self.onu_params)
            outinformation = onu_info.getleveltree()
            print(outinformation)
           
            return outinformation


    def surveytree(self):
        # Запрос состояния со всего дерева (pon порта)
        if "huawei" in self.platform:
            onu_info = HuaweiGetOnuInfo(**self.onu_params)
            outinformation = onu_info.getstatustree()
            
            return outinformation

        elif "bdcom" in self.platform:
            outinformation = []
            onu_info = BdcomGetOnuInfo(**self.onu_params)
            outinformation = onu_info.getstatustree()
            
            return outinformation


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
            onu_on = HuaweiGetOnuInfo(**self.onu_params)
            outinformation = onu_on.setcatvon()

            return outinformation

        
    def onucatvoff(self):
        # Выключить CATV порт
        if "huawei" in self.platform:
            onu_off = HuaweiGetOnuInfo(**self.onu_params)
            outinformation = onu_off.setcatvoff()

            return outinformation

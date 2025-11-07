import sqlite3
import os

from cl_db.db_cfg import Init_Cfg
from cl_db.db_onu import DBOnuInfo
from cl_onu.bdcom_onu import BdcomGetOnuInfo
from cl_onu.huawei_onu import HuaweiGetOnuInfo
from cl_onu.cdata_onu import CdataGetOnuInfo


class ActionOnu:
    """
    Класс для управления ОНУ
    """
    def __init__(self, pathdb, useronu, oltid):

        self.useronu = useronu.lower().replace(' ','').replace(':', '').replace('.', '').replace('hwtc', '48575443').replace('-', '')
        self.pathdb = pathdb
        self.oltid = oltid

        if len(self.useronu) == 12:
            pon_type = 'epon'
        elif len(self.useronu) == 16:
            pon_type = 'gpon'
        else:
            raise ValueError('Wrong MAC or SN')

        snmp_cfg = Init_Cfg(pathdb)
        cfg = snmp_cfg.getcfg()

        self.cfg = cfg

        self.PF_HUAWEI = cfg['PL_H']
        self.PF_BDCOM = cfg['PL_B']
        self.PF_CDATA = cfg['PL_C']
        self.SNMP_READ_H = cfg['SNMP_READ_H']
        self.SNMP_CONF_H = cfg['SNMP_CONF_H']
        self.SNMP_READ_B = cfg['SNMP_READ_B']
        self.SNMP_CONF_B = cfg['SNMP_CONF_B']
        self.SNMP_READ_C = cfg['SNMP_READ_C']
        self.SNMP_CONF_C = cfg['SNMP_CONF_C']
            
        onuinfo = DBOnuInfo(pathdb, useronu, pon_type)
        self.onulist = onuinfo.getonufromdb()

        for o in self.onulist:
            if self.oltid == o['oltid']:
                self.platform = o['platform']
                if self.PF_HUAWEI in o['platform']:        
                    self.onu_params = {
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

                elif self.PF_BDCOM in o['platform']:

                    conn = sqlite3.connect(self.pathdb)
                    cursor = conn.cursor()

                    onumacdec = self.convert()
                    self.portonu_out = o['portonu'].split(":")
                    self.portolt = self.portonu_out[0]
                    self.idonu = self.portonu_out[1]
                    ponportolt2 = cursor.execute(f'''SELECT portoid FROM ponports WHERE ip_address="{o['oltip']}" AND ponport="{self.portolt}";''')
                    if ponportolt2:
                        for portolt2 in ponportolt2:
                            portoltid = portolt2[0]

                    self.onu_params = {
                            "onu":       o['mac/sn'],
                            "hostname":  o['oltname'],
                            "pon_type":  o['pontype'],
                            "olt_ip":    o['oltip'],
                            "portoid":   o['portid'],
                            "onuid":     o['onuid'],
                            "idonu":     self.idonu,
                            "snmp_com":  self.cfg['SNMP_READ_B'],
                            "snmp_wr":   self.cfg['SNMP_CONF_B'],
                            "portoltid": portoltid,
                            }
               
                    conn.close()

                    self.onuid = self.idonu
                    self.portonu_out = self.portonu_out[0]

                elif self.PF_CDATA in o['platform']:
                    conn = sqlite3.connect(self.pathdb)
                    cursor = conn.cursor()

                    onumacdec = self.convert()
                    self.portonu_out = o['portonu'].split(":")
                    self.portolt = self.portonu_out[0]
                    self.idonu = self.portonu_out[1]

                    self.onu_params = {
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

                    self.onuid = self.idonu
                    self.portonu_out = self.portonu_out[0]

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
        if self.PF_HUAWEI in self.platform:
            onu_on = HuaweiGetOnuInfo(self.onu_params)
            outinformation = onu_on.setcatvon()

            return outinformation

        
    def onucatvoff(self):
        # Выключить CATV порт
        if self.PF_HUAWEI in self.platform:
            onu_off = HuaweiGetOnuInfo(self.onu_params)
            outinformation = onu_off.setcatvoff()

            return outinformation


    def onureboot(self):
        '''
        Reboot ONU
        '''
        rebootonu_out = 'ERROR'
        if self.PF_BDCOM in self.platform:    
            onu_reboot = BdcomGetOnuInfo(self.onu_params)
            rebootonu_out = onu_reboot.setonureboot()
        elif self.PF_HUAWEI in self.platform:
            onu_reboot = HuaweiGetOnuInfo(self.onu_params)
            rebootonu_out = onu_reboot.setonureboot()
        elif self.PF_CDATA in self.platform:
            onu_reboot = CdataGetOnuInfo(self.onu_params)
            rebootonu_out = onu_reboot.setonureboot()

        return rebootonu_out


    def onudelete(self):
        '''
        Delete ONU
        '''
        delete_out = 'ERROR'
        if self.PF_BDCOM in self.platform:
            onu_delete = BdcomGetOnuInfo(self.onu_params)
            delete_out = onu_delete.setonudelete()
        elif self.PF_HUAWEI in self.platform:
            delete_out = 'ERROR. Функция пока доступна только для BDCOM'
        elif self.PF_CDATA in self.platform:
            delete_out = 'ERROR. Функция пока доступна только для BDCOM'

        return delete_out

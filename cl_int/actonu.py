from db_services.db_cfg import CfgServiceDb
from cl_onu.bdcom_onu import BdcomGetOnuInfo
from cl_onu.huawei_onu import HuaweiGetOnuInfo
from cl_onu.cdata_onu import CdataGetOnuInfo
from db_services.db_cfg import CfgServiceDb
from cl_onu.bdcom_onu import BdcomGetOnuInfo
from cl_onu.huawei_onu import HuaweiGetOnuInfo
from cl_onu.cdata_onu import CdataGetOnuInfo
from db_services.db_onu import OnuServiceDb
from db_services.db_ports import PortsServiceDb


class ActionOnu:
    '''
    Класс для управления ОНУ
    '''
    def __init__(self, useronu, oltid, userinfo, confonu=''):

        self.useronu = useronu.lower().replace(' ','') \
                                      .replace(':', '') \
                                      .replace('.', '') \
                                      .replace('hwtc', '48575443') \
                                      .replace('-', '')

        self.oltid = oltid
        self.confonu = confonu

        if len(self.useronu) == 12:
            pon_type = 'epon'
        elif len(self.useronu) == 16:
            pon_type = 'gpon'
        else:
            raise ValueError('Wrong MAC or SN')
            
        snmp_cfg = CfgServiceDb()
        cfg = snmp_cfg.get_cfg()

        self.cfg = cfg

        self.PF_HUAWEI = cfg['PL_H']
        self.PF_BDCOM = cfg['PL_B']
        self.PF_CDATA = cfg['PL_C']
        
        onuinfo = OnuServiceDb()
        onuall = onuinfo.get_onu(self.useronu)

        self.onulist = []
        for o in onuall:
            #Если пользователь Админ, то разрешаем все ОНУ
            if userinfo['privilage'] == 'Administrator':
                self.onulist.append(o)
            else:
                #Если не Админ, то запихиваем в список только те ОНУ с которой совпадает группа пользователя
                if userinfo['groupname'] == o.olt.group.group_name:
                    self.onulist.append(o)

        for o in self.onulist:
            if self.cfg['PL_H'] in o.olt.platform:
                if o.olt.snmp_read:
                    self.SNMP_READ = o.olt.snmp_read
                    self.SNMP_WRITE = o.olt.snmp_write
                else:
                    self.SNMP_READ = self.cfg['SNMP_READ_H']
                    self.SNMP_WRITE = self.cfg['SNMP_WRITE_H']
            
            if self.cfg['PL_B'] in o.olt.platform:
                if o.olt.snmp_read:
                    self.SNMP_READ = o.olt.snmp_read
                    self.SNMP_WRITE = o.olt.snmp_write
                else:
                    self.SNMP_READ = self.cfg['SNMP_READ_B']
                    self.SNMP_WRITE = self.cfg['SNMP_WRITE_B']
            
            if self.cfg['PL_C'] in o.olt.platform:
                if o.olt.snmp_read:
                    self.SNMP_READ = o.olt.snmp_read
                    self.SNMP_WRITE = o.olt.snmp_write
                else:
                    self.SNMP_READ = self.cfg['SNMP_READ_C']
                    self.SNMP_WRITE = self.cfg['SNMP_WRITE_C']

        for o in self.onulist:
            if self.oltid == o.olt.id:
                self.platform = o.olt.platform
                if self.PF_HUAWEI in o.olt.platform:        
                    self.onu_params = {
                        "onu":      o.onu,
                        "hostname": o.olt.hostname,
                        "pon_type": o.olt.pon_type,
                        "olt_ip":   o.olt.ip_address,
                        "portoid":  o.port_oid,
                        "onuid":    o.onu_oid,
                        "snmp_com": self.SNMP_READ,
                        "snmp_wr":  self.SNMP_WRITE,
                        }
                    self.onuid = o.port_oid
                    self.portonu_out = o.pon_port_info.pon_port

                elif self.PF_BDCOM in o.olt.platform:
                    self.portonu_out = o.pon_port_info.pon_port.split(":")
                    self.portolt = self.portonu_out[0]
                    self.idonu = self.portonu_out[1]

                    findport = PortsServiceDb()
                    f_port = findport.find_port(o.olt.id, self.portolt)
                
                    if f_port:
                        for f in f_port:
                            portoltid = f.port_oid

                    self.onu_params = {
                            "onu":       o.onu,
                            "hostname":  o.olt.hostname,
                            "pon_type":  o.olt.pon_type,
                            "olt_ip":    o.olt.ip_address,
                            "portoid":   o.port_oid,
                            "onuid":     o.onu_oid,
                            "idonu":     self.idonu,
                            "snmp_com":  self.SNMP_READ,
                            "snmp_wr":   self.SNMP_WRITE,
                            "portoltid": portoltid,
                            }

                    self.onuid = self.idonu
                    self.portonu_out = self.portonu_out[0]

                elif self.PF_CDATA in o.olt.platform:
                    self.portonu_out = o.pon_port_info.pon_port.split(":")
                    
                    self.portolt = self.portonu_out[0]
                    self.idonu = self.portonu_out[1]

                    findport = PortsServiceDb()
                    f_port = findport.find_port(o.olt.id, self.portolt)
                
                    if f_port:
                        for f in f_port:
                            portoltid = f.port_oid

                    self.onu_params = {
                            "onu":      o.onu,
                            "hostname": o.olt.hostname,
                            "pon_type": o.olt.pon_type,
                            "olt_ip":   o.olt.ip_address,
                            "portoid":  o.port_oid,
                            "onuid":    o.onu_oid,
                            "snmp_com": self.SNMP_READ,
                            "snmp_wr":  self.SNMP_WRITE,
                            }

                    self.onuid = self.idonu
                    self.portonu_out = self.portonu_out[0]


    def onucatvon(self):
        '''
        Включить CATV порт
        '''
        if self.PF_HUAWEI in self.platform:
            onu_on = HuaweiGetOnuInfo(self.onu_params)
            outinformation = onu_on.setcatvon()

            return outinformation

        
    def onucatvoff(self):
        '''
        Выключить CATV порт
        '''
        if self.PF_HUAWEI in self.platform:
            onu_off = HuaweiGetOnuInfo(self.onu_params)
            outinformation = onu_off.setcatvoff()

            return outinformation


    def onureboot(self):
        '''
        Метод перезагрузки ОНУ
        '''
        rebootonu_out = {'result': 'error', 'message': 'Ошибка. OLT не отвечает или не включен SNMP Write'}
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
        Метод удаления ОНУ с ОЛТа
        '''
        delete_out = {'result': 'error', 'message': 'Ошибка. OLT не отвечает или не включен SNMP Write'}
        if self.PF_BDCOM in self.platform:
            onu_delete = BdcomGetOnuInfo(self.onu_params)
            delete_out = onu_delete.setonudelete()
            if delete_out['result'] == 'success':
                delfrombd = OnuServiceDb().del_one_onu(self.oltid, self.useronu)
                if delfrombd['result'] == 'error':
                    delete_out = delfrombd
        elif self.PF_HUAWEI in self.platform:
            onu_delete = HuaweiGetOnuInfo(self.onu_params)
            delete_out = onu_delete.setonudelete(self.confonu)
            if delete_out['result'] == 'success':
                delfrombd = OnuServiceDb().del_one_onu(self.oltid, self.useronu)
                if delfrombd['result'] == 'error':
                    delete_out = delfrombd
        elif self.PF_CDATA in self.platform:
            delete_out = {'result': 'error', 'message': 'Ошибка. Функция доступна только для BDCOM и Huawei'}

        return delete_out

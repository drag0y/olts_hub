from db_services.db_cfg import CfgServiceDb
from cl_onu.bdcom_onu import BdcomGetOnuInfo
from cl_onu.huawei_onu import HuaweiGetOnuInfo
from cl_onu.cdata_onu import CdataGetOnuInfo
from db_services.db_onu import OnuServiceDb
from db_services.db_ports import PortsServiceDb
from db_services.db_history import HistoryServiceDb


class FindOnu:
    '''
    Класс для поиска ОНУ, и определения состояния
    '''
    def __init__(self, useronu, userinfo):
        self.useronu = useronu.lower().replace(' ','') \
                                      .replace(':', '') \
                                      .replace('.', '') \
                                      .replace('hwtc', '48575443') \
                                      .replace('-', '')
        
        if len(self.useronu) == 12:
            pon_type = 'epon'
        elif len(self.useronu) == 16:
            pon_type = 'gpon'
        else:
            raise TypeError('Wrong MAC or SN')

        snmp_cfg = CfgServiceDb()
        self.cfg = snmp_cfg.get_cfg()
        
        onuinfo = OnuServiceDb()
        onuall = onuinfo.get_onu(self.useronu)

        self.onulist = []
        '''
        Перебор списка с найденными ОНУ, 
        и создание нового списка только с теми ОНУ с короторыми совпадает Группа пользователя
        '''
        for o in onuall:
            #Если пользователь Админ или дефолтная группа, то разрешаем все ОНУ
            if userinfo['privilage'] == 'Administrator' or userinfo['groupname'] == 'default':
                self.onulist.append(o)
            else:
                #Если не Админ, то запихиваем в список только те ОНУ с которой совпадает группа пользователя
                if userinfo['groupname'] == o.olt.group.group_name:
                    self.onulist.append(o)
        
        if not self.onulist:
            raise ValueError('ONU not found')
        
        
    def onuinfo(self):
        '''
        Состояние ОНУ и опрос
        '''
        out_onuinfo = []
        for o in self.onulist:
            if self.cfg['PL_H'] in o.olt.platform:
                onu_params = {
                        "onu":      o.onu,
                        "hostname": o.olt.hostname,
                        "pon_type": o.olt.pon_type,
                        "olt_ip":   o.olt.ip_address,
                        "portoid":  o.port_oid,
                        "onuid":    o.onu_oid,
                        "snmp_com": o.olt.snmp_read if o.olt.snmp_read else self.cfg['SNMP_READ_H'],
                        "snmp_wr":  o.olt.snmp_write if o.olt.snmp_write else self.cfg['SNMP_WRITE_H'],
                        }

                self.onuid = o.onu_oid
                self.portonu_out = o.pon_port_info.pon_port
                onu_info = HuaweiGetOnuInfo(onu_params)
                onu_state = onu_info.getonustatus()

            elif self.cfg['PL_B'] in o.olt.platform:
                self.portonu_out = o.pon_port_info.pon_port.split(":")
                self.portolt = self.portonu_out[0]
                self.idonu = self.portonu_out[1]
                findport = PortsServiceDb()
                f_port = findport.find_port(o.olt.id, self.portolt)
                
                if f_port:
                    for f in f_port:
                        portoltid = f.port_oid

                onu_params = {
                        "onu":       o.onu,
                        "hostname":  o.olt.hostname,
                        "pon_type":  o.olt.pon_type,
                        "olt_ip":    o.olt.ip_address,
                        "portoid":   o.port_oid,
                        "onuid":     o.onu_oid,
                        "idonu":     self.idonu,
                        "snmp_com":  o.olt.snmp_read if o.olt.snmp_read else self.cfg['SNMP_READ_B'],
                        "snmp_wr":   o.olt.snmp_write if o.olt.snmp_write else self.cfg['SNMP_WRITE_B'],
                        "portoltid": portoltid,
                        }

                onu_info = BdcomGetOnuInfo(onu_params)
                onu_state = onu_info.getonustatus()
                self.onuid = self.idonu
                self.portonu_out = self.portonu_out[0]

            elif self.cfg['PL_C'] in o.olt.platform:

                self.portonu_out = o.pon_port_info.pon_port.split(":")
                self.portolt = self.portonu_out[0]
                self.idonu = self.portonu_out[1]
                
                onu_params = {
                    "onu":      o.onu,
                    "hostname": o.olt.hostname,
                    "pon_type": o.olt.pon_type,
                    "olt_ip":   o.olt.ip_address,
                    "portoid":  o.port_oid,
                    "onuid":    o.onu_oid,
                    "snmp_com": o.olt.snmp_read if o.olt.snmp_read else self.cfg['SNMP_READ_C'],
                    "snmp_wr":  o.olt.snmp_write if o.olt.snmp_write else self.cfg['SNMP_WRITE_C'],
                    }

                onu_info = CdataGetOnuInfo(onu_params)
                onu_state = onu_info.getonustatus()
                self.onuid = self.idonu
                self.portonu_out = self.portonu_out[0]

            # ---- Если ONU в сети, то для опроса вызываем следующие методы
            state_lan = '-'
            speed_lan = '-'
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
                speed_lan = onu_info.getlanspeed()
                reason_down = onu_info.getlastdown()
                time_up = onu_info.getonuuptime()
                time_down = onu_info.gettimedown()
                level_onu, level_olt = onu_info.getonulevel() # Уровень сигнала
                lan_mac = onu_info.getllidmacsearch()
                if self.cfg['PL_H'] in o.olt.platform:
                    catv_state, catv_level = onu_info.getcatvstate()
                elif self.cfg['PL_C'] in o.olt.platform:
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
                onustate = "ОЛТ не в сети или не отвечает"

            onuinformation = {
                "mac/sn": o.onu,
                "onu_state": int(onu_state),
                "oltname": o.olt.hostname,
                "oltip": o.olt.ip_address,
                "olt_id": o.olt.id,
                "iface_state": onustate,
                "iface_name": self.portonu_out,
                "onuid": self.onuid,
                "lanstate": state_lan,
                "lanspeed": speed_lan,
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

            HistoryServiceDb().add_history(o.onu, o.olt.id, onustate, reason_down, level_onu, level_olt)
            
        return out_onuinfo

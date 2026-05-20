from ping3 import ping

from db_services.db_cfg import CfgServiceDb
from cl_olt.huawei_olts import HuaweiGetOltInfo
from cl_olt.bdcom_olts import BdcomGetOltInfo
from cl_olt.cdata_olts import CdataGetOltInfo
from db_services.db_olt import OltServiceDb
from db_services.db_ports import PortsServiceDb
from db_services.db_onu import OnuServiceDb


class FindOlt:
    '''
    Класс для поиска ОЛТа, определения состояния и параметров
    '''
    def __init__(self, userinfo, olt_id, olt_port=''):
        snmp_cfg = CfgServiceDb()
        cfg = snmp_cfg.get_cfg()

        self.PF_HUAWEI = cfg['PL_H']
        self.PF_BDCOM = cfg['PL_B']
        self.PF_CDATA = cfg['PL_C']

        self.olt_id = olt_id
        self.olt_port = olt_port

        # Поиск ОЛТа
        getolt = OltServiceDb()
        olt_info = getolt.get_olt(olt_id)

        #Проверяем принадлежность пользователя к группе
        if userinfo['privilage'] == 'Administrator':
            #Если пользователь Админ, то разрешаем просмотр ОЛТа
            self.olt_info = olt_info
        elif userinfo['groupname'] == olt_info.group.group_name:
            #Если не Админ, то то сверяем группу
            self.olt_info = olt_info
        else:
            #Если пользователь не Админ и не состоит в группе с ОЛТом то создаётся исключение
            raise ValueError('User is not member of group')

        if olt_port:
            ponport = PortsServiceDb()
            findport = ponport.find_port(self.olt_id, olt_port)
            
            for f in findport:
                self.port_oid = f.port_oid

        if self.PF_HUAWEI in self.olt_info.platform:
            if self.olt_info.snmp_read:
                self.SNMP_READ = self.olt_info.snmp_read
            else:
                self.SNMP_READ = cfg['SNMP_READ_H']
        
        elif self.PF_BDCOM in self.olt_info.platform:
            if self.olt_info.snmp_read:
                self.SNMP_READ = self.olt_info.snmp_read
            else:
                self.SNMP_READ = cfg['SNMP_READ_B']
        
        elif self.PF_CDATA in self.olt_info.platform:
            if self.olt_info.snmp_read:
                self.SNMP_READ = self.olt_info.snmp_read
            else:
                self.SNMP_READ = cfg['SNMP_READ_C']


    def oltinfo(self):     
        olt_state = ''
        unregonu = []
        oltuptime = ''
        
        # Сбор списка портов
        ports = PortsServiceDb()
        port_info = ports.get_ports(self.olt_id)

        self.pon_ports = []
        
        for p in port_info:
            if ':' in p.pon_port:
                self.ports = p.pon_port.split(':')[0]
                self.pon_ports.append(self.ports)
            else:
               self.ports = p.pon_port
               self.pon_ports.append(self.ports)
        self.pon_ports_out = list(dict.fromkeys(self.pon_ports))

        self.pon_ports.sort()
        # Считаем количество ОНУ на ОЛТе
        onu_count = OnuServiceDb()
        self.countonu = onu_count.count_onu(self.olt_id)
         
        # Пингуем ОЛТ
        p = ping(f'{self.olt_info.ip_address}')
        if p == None or p == False:
            olt_state = 'Не в сети'
        else:
            olt_params = {
                'olt_name': self.olt_info.hostname, 
                'olt_ip':   self.olt_info.ip_address, 
                'snmp_com': self.SNMP_READ,
                'pontype' : self.olt_info.pon_type,
            }
            olt_state = 'В сети'
            # Ищем незарегистрированные ОНУ (только Huawei)
            if self.PF_HUAWEI in self.olt_info.platform:
                oltinfo = HuaweiGetOltInfo(**olt_params)
            elif self.PF_BDCOM in self.olt_info.platform:
                oltinfo = BdcomGetOltInfo(**olt_params)
            elif self.PF_CDATA in self.olt_info.platform:
                oltinfo = CdataGetOltInfo(**olt_params)
            
            unregonu = oltinfo.unregonu(self.olt_info.id)
            oltuptime = oltinfo.oltuptime()
        
        olt_information = {
                    "oltid":      self.olt_info.id,
                    "oltname":    self.olt_info.hostname,
                    "olt_state":  olt_state,
                    "olt_uptime": oltuptime,
                    "ip_address": self.olt_info.ip_address,
                    "platform":   self.olt_info.platform,
                    "countonu":   self.countonu,
                    "ports":      self.pon_ports_out,
                    "pontype":    self.olt_info.pon_type,
                    "unregonu":   unregonu,
                    "descr":      self.olt_info.descr,
                    "group":      self.olt_info.group.group_name,
                    "snmpread":   self.olt_info.snmp_read,
                    "snmpwrite":  self.olt_info.snmp_write,
                    "conntype":   self.olt_info.conn_type,
                    "connlogin":  self.olt_info.conn_login,
                    "connpsw":    self.olt_info.conn_psw,
                }

        return olt_information


    def ponportstatus(self):
        '''
        Уровни и статус пон дерева
        '''
        if self.PF_HUAWEI in self.olt_info.platform:
            olt_info = HuaweiGetOltInfo(self.olt_info.hostname, self.olt_info.ip_address, self.SNMP_READ, self.olt_info.pon_type) 

        elif self.PF_BDCOM in self.olt_info.platform:
            olt_info = BdcomGetOltInfo(self.olt_info.hostname, self.olt_info.ip_address, self.SNMP_READ, self.olt_info.pon_type)

        elif self.PF_CDATA in self.olt_info.platform:
            olt_info = CdataGetOltInfo(self.olt_info.hostname, self.olt_info.ip_address, self.SNMP_READ, self.olt_info.pon_type)
            
        out_tree = olt_info.ponstatustree(self.olt_id, self.port_oid)

        return out_tree  


    def update_olt(self):
        '''
        Метод опроса конкретного ОЛТа
        '''
        if self.olt_info:
            if self.PF_HUAWEI in self.olt_info.platform:
                olt = HuaweiGetOltInfo(
                    self.olt_info.hostname, 
                    self.olt_info.ip_address, 
                    self.SNMP_READ,
                    self.olt_info.pon_type,
                    )

            elif self.PF_BDCOM in self.olt_info.platform:
                olt = BdcomGetOltInfo(
                    self.olt_info.hostname,
                    self.olt_info.ip_address,
                    self.SNMP_READ,
                    self.olt_info.pon_type,
                    )
            
            elif self.PF_CDATA in self.olt_info.platform:
                olt = CdataGetOltInfo(
                    self.olt_info.hostname, 
                    self.olt_info.ip_address, 
                    self.SNMP_READ, 
                    self.olt_info.pon_type,
                    )
                
            ports_list = olt.getoltports()
            ports = PortsServiceDb()
            ports.del_port(self.olt_info.id)
            ports.add_port(self.olt_info.id, ports_list)

            onu_list = olt.getonulist()
            onu = OnuServiceDb()
            onu.del_onu(self.olt_info.id)
            onu.add_onu(self.olt_info.id, onu_list)
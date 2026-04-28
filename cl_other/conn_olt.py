import netmiko

from db_services.db_onu import OnuServiceDb


class ConnOLT:
    '''
    Класс для подключения к ОЛТу по SSH к Huawei и Telnet BDCOM
    '''
    def __init__(self, olt_information, useronu, conninfo):
        self.useronu = useronu.lower().replace(' ','') \
                                      .replace(':', '') \
                                      .replace('.', '') \
                                      .replace('hwtc', '48575443') \
                                      .replace('-', '')
        
        self.olt_information = olt_information
        self.conninfo = conninfo
        
        if len(self.useronu) == 12:
            pon_type = 'epon'
        elif len(self.useronu) == 16:
            pon_type = 'gpon'
#        else:
#            raise TypeError('Wrong MAC or SN')
               
        self.onulist = OnuServiceDb().get_onu(useronu)

        for o in self.onulist:
            if olt_information['ip_address'] == o.olt.ip_address:
                self.olt = {
                    'oltip': o.olt.ip_address,
                    'oltname': o.olt.hostname,
                    'portonu': o.pon_port_info.pon_port,
                    'platform': olt_information['platform'],
                    'onuid': o.onu_oid,
                    'conntype': olt_information['conntype'],
                    'connlogin': olt_information['connlogin'],
                    'connpsw': olt_information['connpsw'],
                }
        

    def confonuinfo(self):
        '''
        Метод подключения к ОЛТу и сбор конфигурации и FDB с ОНУ
        '''
        if 'BDCOM' in self.olt['platform']:
            dev_type = 'cisco_ios_telnet'
            if self.olt['connlogin'] and self.olt['connpsw']:
                BDCOM_LOGIN = self.olt['connlogin']
                BDCOM_PSW = self.olt['connpsw']
            else:
                BDCOM_LOGIN = self.conninfo['BDCOM_LOGIN']
                BDCOM_PSW = self.conninfo['BDCOM_PSW']

            if self.olt['conntype'] == 'SSH':
                dev_type = 'cisco_ios'
            with netmiko.ConnectHandler(
                        device_type=dev_type,
                        host=self.olt['oltip'],
                        username=BDCOM_LOGIN,
                        password=BDCOM_PSW,
                        ) as conn:
                conn.enable()
                outconf = conn.send_command(f'show run interface {self.olt["portonu"]}')
                outfdb = conn.send_command(f'show mac address-table interface {self.olt["portonu"]}')
                
                conf_onu = {
                    'oltip': self.olt['oltip'],
                    'oltname': self.olt['oltname'],
                    'outconf': outconf,
                    'outfdb': outfdb,
                }
                
        elif 'Huawei_OLT' in self.olt['platform']:
            if self.olt['connlogin'] and self.olt['connpsw']:
                HUAWEI_LOGIN = self.olt['connlogin']
                HUAWEI_PSW = self.olt['connpsw']
            else:
                HUAWEI_LOGIN = self.conninfo['HUAWEI_LOGIN']
                HUAWEI_PSW = self.conninfo['HUAWEI_PSW']
            with netmiko.ConnectHandler(
                        device_type='huawei_olt',
                        host=self.olt['oltip'],
                        username=HUAWEI_LOGIN,
                        password=HUAWEI_PSW,
                        disabled_algorithms=dict(pubkeys=["rsa-sha2-512", "rsa-sha2-256"]),
                        ) as ssh:
                ssh.enable()
                outconf = ssh.send_command_timing(f'display current-configuration ont {self.olt["portonu"]} {self.olt["onuid"]}')
                outfdb = ssh.send_command_timing(f'display mac-address port {self.olt["portonu"]} ont {self.olt["onuid"]}')
                
                conf_onu = {
                    'oltip': self.olt['oltip'],
                    'oltname': self.olt['oltname'],
                    'outconf': outconf,
                    'outfdb': outfdb,
                }
                
        return conf_onu
    

    def confonuhuawei(self):
        '''
        Метод подключения к ОЛТу Huawei и сбор конфигурации
        далее эта конфигурация будет парситься для определения сервис порта ОНУ
        '''
        if self.olt['connlogin'] and self.olt['connpsw']:
            HUAWEI_LOGIN = self.olt['connlogin']
            HUAWEI_PSW = self.olt['connpsw']
        else:
            HUAWEI_LOGIN = self.conninfo['HUAWEI_LOGIN']
            HUAWEI_PSW = self.conninfo['HUAWEI_PSW']
            
        with netmiko.ConnectHandler(
                    device_type='huawei_olt',
                    host=self.olt['oltip'],
                    username=HUAWEI_LOGIN,
                    password=HUAWEI_PSW,
                    disabled_algorithms=dict(pubkeys=["rsa-sha2-512", "rsa-sha2-256"]),
                    ) as ssh:
            ssh.enable()
            outconf = ssh.send_command_timing(f'display current-configuration ont {self.olt["portonu"]} {self.olt["onuid"]}')
                        
            conf_onu = {
                'oltip': self.olt['oltip'],
                'oltname': self.olt['oltname'],
                'outconf': outconf,
            }
                
        return conf_onu
                    

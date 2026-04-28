import netmiko


class ShowLogs:
    def __init__(self, oltinfo, conninfo):
        self.oltinfo = oltinfo
        self.conninfo = conninfo
               

    def showlogs(self):
        '''
        Метод просмотра логов ОЛТа
        '''
        if 'BDCOM' in self.oltinfo['platform']:
            dev_type = 'cisco_ios_telnet'
            if self.oltinfo['connlogin'] and self.oltinfo['connpsw']:
                BDCOM_LOGIN = self.oltinfo['connlogin']
                BDCOM_PSW = self.oltinfo['connpsw']
            else:
                BDCOM_LOGIN = self.conninfo['BDCOM_LOGIN']
                BDCOM_PSW = self.conninfo['BDCOM_PSW']

            if self.oltinfo['conntype'] == 'SSH':
                dev_type = 'cisco_ios'

            with netmiko.ConnectHandler(
                device_type=dev_type,
                host=self.oltinfo['ip_address'],
                username=BDCOM_LOGIN,
                password=BDCOM_PSW,
                ) as telnet:

                telnet.enable()
                telnet.send_command('terminal length 0')
                logs_olt = telnet.send_command_timing('show logging')
                
                out_logs = {
                    'oltip': self.oltinfo['ip_address'],
                    'oltname': self.oltinfo['oltname'],
                    'outlogs': logs_olt,
                }

        elif 'Huawei_OLT' in self.oltinfo['platform']:
            if self.oltinfo['connlogin'] and self.oltinfo['connpsw']:
                HUAWEI_LOGIN = self.oltinfo['connlogin']
                HUAWEI_PSW = self.oltinfo['connpsw']
            else:
                HUAWEI_LOGIN = self.conninfo['HUAWEI_LOGIN']
                HUAWEI_PSW = self.conninfo['HUAWEI_PSW']
            with netmiko.ConnectHandler(
                        device_type='huawei_olt',
                        host=self.oltinfo['ip_address'],
                        username=HUAWEI_LOGIN,
                        password=HUAWEI_PSW,
                        disabled_algorithms=dict(pubkeys=["rsa-sha2-512", "rsa-sha2-256"]),
                        ) as ssh:
                ssh.enable()
                logs_olt = ssh.send_command_timing('display logbuffer level notification size 50 | exclude cmd')
                
                out_logs = {
                    'oltip': self.oltinfo['ip_address'],
                    'oltname': self.oltinfo['oltname'],
                    'outlogs': logs_olt,
                }
        
        return out_logs
        

import os
import netmiko
from dotenv import load_dotenv

from cl_db.db_onu import DBOnuInfo

load_dotenv()

BDCOM_LOGIN = os.getenv('BDCOM_LOGIN')
BDCOM_PSW = os.getenv('BDCOM_PSW')
HUAWEI_LOGIN = os.getenv('HUAWEI_LOGIN')
HUAWEI_PSW = os.getenv('HUAWEI_PSW')
CDATA_LOGIN = os.getenv('CDATA_LOGIN')
CDATA_PSW = os.getenv('CDATA_PSW')


class ShowLogs:
    def __init__(self, oltinfo):
        self.oltinfo = oltinfo


    def showlogs(self):
        '''
        Docstring for showlogs
        
        :param self: Description
        '''
        if 'BDCOM' in self.oltinfo['platform']:
            print(f"Connect to {self.oltinfo['platform']}")
            with netmiko.ConnectHandler(
                        device_type='cisco_ios_telnet',
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
        

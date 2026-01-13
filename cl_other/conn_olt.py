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


class ConnOLT:
    def __init__(self, olt_information, useronu, pathdb):
        self.useronu = useronu.lower().replace(' ','').replace(':', '').replace('.', '').replace('hwtc', '48575443').replace('-', '')
        self.olt_information = olt_information
        self.pathdb = pathdb

        if len(self.useronu) == 12:
            pon_type = 'epon'
        elif len(self.useronu) == 16:
            pon_type = 'gpon'
#        else:
#            raise TypeError('Wrong MAC or SN')
               
        onuinfo = DBOnuInfo(pathdb, self.useronu, pon_type)
        self.onulist = onuinfo.getonufromdb()
    
        for o in self.onulist:
            if olt_information['ip_address'] == o['oltip']:
                self.olt = {
                    'oltip': olt_information['ip_address'],
                    'oltname': olt_information['oltname'],
                    'portonu': o['portonu'],
                    'platform': olt_information['platform'],
                    'onuid': o['onuid'],
                }
        

    def confonuinfo(self):
        '''
        Connect to OLT
        '''   
        if 'BDCOM' in self.olt['platform']:
            with netmiko.ConnectHandler(
                        device_type='cisco_ios_telnet',
                        host=self.olt['oltip'],
                        username=BDCOM_LOGIN,
                        password=BDCOM_PSW,
                        ) as telnet:
                telnet.enable()
                outconf = telnet.send_command(f'show run interface {self.olt['portonu']}')
                outfdb = telnet.send_command(f'show mac address-table interface {self.olt['portonu']}')
                
                conf_onu = {
                    'oltip': self.olt['oltip'],
                    'oltname': self.olt['oltname'],
                    'outconf': outconf,
                    'outfdb': outfdb,
                }
                
        elif 'Huawei_OLT' in self.olt['platform']:
            with netmiko.ConnectHandler(
                        device_type='huawei_olt',
                        host=self.olt['oltip'],
                        username=HUAWEI_LOGIN,
                        password=HUAWEI_PSW,
                        disabled_algorithms=dict(pubkeys=["rsa-sha2-512", "rsa-sha2-256"]),
                        ) as ssh:
                ssh.enable()
                outconf = ssh.send_command_timing(f'display current-configuration ont {self.olt['portonu']} {self.olt['onuid']}')
                outfdb = ssh.send_command_timing(f'display mac-address port {self.olt['portonu']} ont {self.olt['onuid']}')
                
                conf_onu = {
                    'oltip': self.olt['oltip'],
                    'oltname': self.olt['oltname'],
                    'outconf': outconf,
                    'outfdb': outfdb,
                }
                
        return conf_onu
                    

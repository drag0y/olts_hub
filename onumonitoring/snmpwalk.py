import subprocess


class SnmpWalk:
    '''
    Класс для работы с SNMP
    '''
    def __init__(self, host_ip, snmp_community, oid):
        
        self.host_ip = host_ip
        self.snmp_community = snmp_community
        self.oid = oid


    def snmpget(self):
        '''
        Метод для получения данных по SNMP через snmpwalk
        '''
        snmpget_out = []
        
        snmpget_cmd = f'snmpwalk -c {self.snmp_community} -v2c {self.host_ip} {self.oid}'
        cmd = snmpget_cmd.split()
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE)

        while True:
            output = process.stdout.readline()

            if output == b'' and process.poll() is not None:
                break

            if output:
                outline = output.decode('utf-8')
                snmpget_out.append(outline)

        return snmpget_out


    def snmpset(self):
        '''
        Метод для конфигурации устройства по SNMP
        '''
        snmpset_out = []

        snmpset_cmd = f'snmpset -c {self.snmp_community} -v2c {self.host_ip} {self.oid}'
        cmd = snmpset_cmd.split()
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE)

        while True:
            output = process.stdout.readline()

            if output == b'' and process.poll() is not None:
                break

            if output:
                outline = output.decode('utf-8')
                snmpset_out.append(outline)

        return snmpset_out

class GetOnuInfoBase:
    ''' 
    Класс шаблон для работы с ОНУ 
    '''
    def __init__(self, dbonuinfo):
        self.dbonuinfo = isinstance(dbonuinfo, dict)
        self.onu = dbonuinfo['onu']
        self.hostname = dbonuinfo['hostname']
        self.pon_type = dbonuinfo['pon_type']
        self.olt_ip = dbonuinfo['olt_ip']
        self.portoid = dbonuinfo['portoid']
        self.onuid = dbonuinfo['onuid']
        self.snmp_com = dbonuinfo['snmp_com']
        self.snmp_wr = dbonuinfo['snmp_wr']
        self.portoltid = dbonuinfo['portoltid']
        self.dbinfo = dbonuinfo

    
    def getonustatus(self):
        ''' 
        Определение статуса ОНУ (В сети/Не в сети)
        '''
        onu_state_out = 'Не поддерживается'
        return onu_state_out


    def getlanstatus(self):
        ''' 
        Метод определяет статус LAN порта
        '''
        lan_out = 'Не поддерживается'
        return lan_out


    def getlanspeed(self):
        ''' 
        Метод определяет скорость подключения LAN порта
        '''
        lan_speed_out = ''
        return lan_speed_out


    def getcatvstate(self):
        ''' 
        Метод определяет статус CATV порта
        '''
        catv_state = 'Не поддерживается'
        return catv_state

    
    def getcatvlevel(self):
        ''' 
        Метод для получения уровня сигнала CATV порта 
        '''
        level_catv = 'Не поддерживается'
        return level_catv


    def getlastdown(self):
        ''' 
        Метод определяет причину последнего отключения ОНУ
        '''
        lastdownonu = 'Не поддерживается'
        return lastdownonu


    def getonuuptime(self):
        ''' 
        Метод определяет время включения ОНУ
        '''
        onu_uptime = 'Не поддерживается'
        return onu_uptime


    def gettimedown(self):
        # Метод определяет время последнего отключения
        onu_downtime = 'Не поддерживается'
        return onu_downtime


    def getonulevel(self):
        ''' 
        Метод определяет уровни сигнала ОНУ
        '''
        level_onu = 'Не поддерживается'
        level_olt = 'Не поддерживается'
        return level_onu, level_olt


    def setcatvon(self):
        '''
        Включить CATV
        '''
        catv_out = 'Не поддерживается'
        return catv_out


    def setcatvoff(self):
        '''
        Выключить CATV
        '''
        catv_out = 'Не поддерживается'
        return catv_out


    def setonureboot(self):
        '''
        Метод для ребута ОНУ
        '''
        setreboot_out = 'Ошибка. Не удалось перезагрузить ОНУ'
        return setreboot_out


    def setonudelete(self):
        '''
        Удалить ОНУ
        '''
        setdelete_out = 'Ошибка. Не удалось удалить ОНУ'
        return setdelete_out


    def getllidmacsearch(self):
        '''
        Получить мак адреса с LAN порта
        '''
        fdb_list = ['Не поддерживается']
        return fdb_list

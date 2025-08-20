class GetOnuInfoBase:
    ''' 
    Класс шаблон для работы с ОНУ 
    '''
    def __init__(self, hostname, pon_type, olt_ip, portoid, onuid, snmp_com, pathdb, snmp_wr):
        self.hostname = hostname
        self.pon_type = pon_type
        self.olt_ip = olt_ip
        self.portoid = portoid
        self.onuid = onuid
        self.snmp_com = snmp_com
        self.pathdb = pathdb
        self.snmp_wr = snmp_wr


    def getonustatus(self):
        ''' 
        Определение статуса ОНУ (В сети/Не в сети)
        '''
        onu_state_out = 'Не удалось определить'
        return onu_state_out


    def getlanstatus(self):
        ''' 
        Метод определяет статус LAN порта
        '''
        lan_out = 'Не удалось определить'
        return lan_out


    def getcatvstate(self):
        ''' 
        Метод определяет статус CATV порта
        '''
        catv_state = 'Не поддерживается'
        level_catv = -0.0
        return catv_state, level_catv

    
    def getcatvlevel(self):
        ''' 
        Метод для получения уровня сигнала CATV порта 
        '''
        level_catv = -0.0
        return level_catv


    def getlastdown(self):
        ''' 
        Метод определяет причину последнего отключения ОНУ
        '''
        lastdownonu = 'Неизвестно'
        return lastdownonu


    def getonuuptime(self):
        ''' 
        Метод определяет время включения ОНУ
        '''
        onu_uptime = 'Нет времени включения'
        return onu_uptime


    def gettimedown(self):
        # Метод определяет время последнего отключения
        onu_downtime = 'Нет времени отключения'
        return onu_downtime


    def getonulevel(self):
        ''' 
        Метод определяет уровни сигнала ОНУ
        '''
        level_onu = 0
        level_olt = 0
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

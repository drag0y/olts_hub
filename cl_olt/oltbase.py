class GetOltInfoBase:
    '''
    Класс шаблон для работы с OLT
    '''
    def __init__(self, dboltinfo, pathdb, snmp_com):
        self.dboltinfo = isinstance(dboltinfo, dict)
        self.olt_name = dboltinfo['hostname']
        self.olt_ip = dboltinfo['ip_address']
        self.pontype = dboltinfo['pontype']
        self.pathdb = pathdb
        self.snmp_com = snmp_com

    def getoltports(self):
        '''
        Запрос портов с ОЛТа
        '''


    def getonulist(self):
        ''' 
        Функция для запроса списка зареганых ONU и парсинг
        '''


    def ponstatustree(self, port_oid):
        '''
        Статус и уровни с дерева (порта)
        '''
        status_tree = {}
        return status_tree

    def unregonu(self):
        '''
        Метод проверяет есть ли на ОЛТе не зарегистрированные ОНУ
        '''

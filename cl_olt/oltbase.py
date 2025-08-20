class GetOltInfoBase:
    '''
    Класс шаблон для работы с OLT
    '''
    def __init__(self, olt_name, olt_ip, snmp_com, pathdb, pontype):
        self.olt_name = olt_name
        self.olt_ip = olt_ip
        self.snmp_com = snmp_com
        self.pathdb = pathdb
        self.pontype = pontype


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

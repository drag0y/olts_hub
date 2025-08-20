import sqlite3


class InitMenuCfg:
    '''
    Класс для работы с конфигурациями
    '''
    def __init__(self, pathdb):
        self.pathdb = pathdb


    def getmenucfg(self, privilage):
        '''
        Получить словарь для меню настроек
        '''
        menu = []
        conn = sqlite3.connect(self.pathdb)
        cursor = conn.cursor()
        
        if privilage == 'Administrator':   
            menu_values = cursor.execute('SELECT * FROM menu_cfg;')
            for m in menu_values:
                values = {
                    'menuname': m[1],
                    'url': m[2],
                    'privilage': m[3],
                }
                menu.append(values)
        elif privilage == 'Operator':    
            menu_values = cursor.execute('SELECT * FROM menu_cfg WHERE privilage = "Operator";')
            for m in menu_values:
                values = {
                    'menuname': m[1],
                    'url': m[2],
                    'privilage': m[3],
                }
                menu.append(values)

        conn.close()

        return menu

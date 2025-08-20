import sqlite3


class DBOnuInfo:
    '''
    Сбор из базы всеё информации об ОНУ
    '''
    def __init__(self, pathdb, useronu, pon_type):
        self.pathdb = pathdb
        self.useronu = useronu
        self.pon_type = pon_type


    def getonufromdb(self):
        '''
        Подключение к базе и поиск ONU
        '''
        conn = sqlite3.connect(self.pathdb)
        cursor = conn.cursor()
        if self.pon_type == "epon":
            findonu = cursor.execute(f'select * from epon where maconu glob "{self.useronu}"')
        if self.pon_type == "gpon":
            findonu = cursor.execute(f'select * from gpon where snonu glob "{self.useronu}"')

        onu_list_tmp1 = []
        for o in findonu:
            onuinfo = {
                'mac/sn': o[1],
                'portid': o[2],
                'onuid': o[3],
                'oltip': o[4],
                'oltname': o[5],
                'pontype': self.pon_type,
                }
            onu_list_tmp1.append(onuinfo)

        onu_list_tmp2 = []
        for t1 in onu_list_tmp1:
            ponportonu = cursor.execute(f'''SELECT * FROM ponports WHERE ip_address="{t1['oltip']}" AND portoid="{t1['portid']}";''')

            self.portonu_out = "Не удалось определить порт"
            for portonu in ponportonu:
                portinfo = {'portonu': portonu[3]}
                onulist2 = {**t1, **portinfo}
            onu_list_tmp2.append(onulist2)

        onu_list = []
        for t2 in onu_list_tmp2:
            platf = cursor.execute(f'''SELECT * FROM olts WHERE ip_address="{t2['oltip']}";''')
            for p in platf:
                platform = {'oltid': p[0], 'platform': p[3]}
                onulist3 = {**t2, **platform}
            onu_list.append(onulist3)

        return onu_list

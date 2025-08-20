import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash


class Users_Cfg:
    '''
    Класс для работы с пользователями
    '''
    def __init__(self, pathdb):
        self.pathdb = pathdb


    def getusers(self):
        '''
        Получить список со всеми пользователями
        '''
        users_list = []
        conn = sqlite3.connect(self.pathdb)
        cursor = conn.cursor()

        db_values = cursor.execute('SELECT * FROM users;')
        
        for v in db_values:
            values = {
                'user': v[1], 
                'privilage': v[3],
            }
            users_list.append(values)

        conn.close()

        return users_list


    def changepsw(self, user_id, psw):
        '''
        Смена пароля пользователя
        '''
        if len(psw) < 8:
            return 'Ошибка. Короткий пароль.'
        psw_hash = generate_password_hash(psw)
        conn = sqlite3.connect(self.pathdb)
        cursor = conn.cursor()
        cursor.execute(f"UPDATE users SET password = '{psw_hash}' WHERE id = {user_id}")

        conn.commit()
        conn.close()

        return 'Пароль успешно изменён'


    def deluser(self, username):
        '''
        Удалить пользователя
        '''
        conn = sqlite3.connect(self.pathdb)
        cursor = conn.cursor()
        cursor.execute(f"DELETE FROM users WHERE login='{username}'")

        conn.commit()
        conn.close()


    def adduser(self, username, psw, privilage):
        '''
        Добавить пользователя
        '''
        get_user = ''
        if not username or not psw or not privilage:
            return 'Ошибка. Заполните все поля'
        if len(psw) < 8:
            return 'Ошибка. Короткий пароль.'
        if privilage != 'Administrator' and privilage != 'Operator':
            return 'Ошибка. Не выбраны права пользователя.'
        psw_hash = generate_password_hash(psw)
        user = [username, psw_hash, privilage]
        query_user = "INSERT into users(login, password, privilage) values (?, ?, ?)"

        conn = sqlite3.connect(self.pathdb)
        cursor = conn.cursor()

        getuser = cursor.execute(f"SELECT login FROM users WHERE login LIKE '{username}'")
        for u in getuser:
            get_user = u[0]
        conn.close()
        if get_user.lower() == username.lower():
            return 'Ошибка. Такой пользователь уже есть'
        else:
            conn = sqlite3.connect(self.pathdb)
            cursor = conn.cursor()
            cursor.execute(query_user, user)

            conn.commit()
            conn.close()
            return 'Пользователь добавлен'


class UserInfo():
    def __init__(self, pathdb):
        self.pathdb = pathdb


    def getUser(self, user_id):
        '''
        Получить данные о пользователе по user_id
        '''
        conn = sqlite3.connect(self.pathdb)
        cursor = conn.cursor()

        db_values = cursor.execute(f'SELECT * FROM users where id = {user_id} LIMIT 1;')
        user_info = {}
        for v in db_values:
            user_info = {
                'id': v[0],
                'username': v[1],
                'privilage': v[3],
            }
        if not user_info:
            return False
        
        return user_info
                

    def getUserByName(self, username):
        '''
        Получить данные о пользователе по username
        '''
        conn = sqlite3.connect(self.pathdb)
        cursor = conn.cursor()

        db_values = cursor.execute(f'SELECT * FROM users where login="{username}" LIMIT 1;')
        user_info = {'user_id': 0, 'username': ''}
        for v in db_values:
            user_info = {
                'id': v[0],
                'username': v[1],
                'psw': v[2],
                'privilage': v[3],
            }

        if user_info['username'] == username:
            return user_info
        else:
            return False

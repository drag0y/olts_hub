from sqlalchemy import select, or_, func
from sqlalchemy.orm import joinedload
from werkzeug.security import generate_password_hash

from models.base import db
from models.models import Users


class UsersServiceDb:
    '''
    Класс для работы с пользователями
    '''
    def get_users(self):
        '''
        Метод получения списка пользователей из БД
        '''
        stmt = (
            select(Users)
            .options(joinedload(Users.group))
        )
        
        result = db.session.scalars(stmt).all()

        userslist = []
        for r in result:
            userslist.append(
                {
                    'id': r.id,
                    'username': r.username,
                    'groupname': r.group.group_name,
                    'privilage': r.privilage,
                }
            )
        
        return userslist


    def add_user(self, userinfo):
        '''
        Метод добавления пользователя
        '''
        #Смотрим, есть ли в базе такой пользователь
        stmt = select(Users).where(
            or_(
                Users.username == userinfo['username'],
            )
        )
        finduser = db.session.execute(stmt).scalars().all()
        
        if finduser:
            return {'result': 'error', 'message': 'Ошибка. Такой пользователь уже есть!',}

        #Если пользователя нет, то проверяем данные и добавляем в БД
        if not userinfo['username'] or not userinfo['psw'] or not userinfo['privilage']:
            return {'result': 'error', 'message': 'Ошибка. Заполните все поля!',}
        elif len(userinfo['psw']) < 8:
            return {'result': 'error', 'message': 'Ошибка. Короткий пароль!',}
        elif 'None' in userinfo['group_id']:
            return {'result': 'error', 'message': 'Ошибка. Не выбрана группа!',}
        elif 'None' in userinfo['privilage']:
            return {'result': 'error', 'message': 'Ошибка. Не выбраны права пользователя!',}
        
        psw_hash = generate_password_hash(userinfo['psw'])
        user = Users(
                username=userinfo['username'],
                password=psw_hash,
                privilage=userinfo['privilage'],
                group_id=userinfo['group_id'],
                )

        db.session.add(user)
        db.session.commit()
            
        return {
            'result': 'success',
            'message': f'Пользователь {userinfo["username"]} добавлен!',
        }


    def edit_user(self, userinfo):
        '''
        Метод редактирования пользователя
        '''
        #Смотрим, есть ли в базе пользователь с таким же именем
        stmt = select(Users).where(
            Users.id != userinfo['id'],
            or_(
                Users.username == userinfo['username'],
            )
        )
        finduser = db.session.execute(stmt).scalars().all()

        if finduser:
            return {'result': 'error', 'message': f'Ошибка. Пользователь с таким именем ({userinfo["username"]}) уже есть!',}

        user = db.session.get(Users, userinfo['id'])

        if user.id == 1:
            return {'result': 'error', 'message': f'Ошибка. Нельзя редактировать дефолтного пользователя!',}

        #Если пользователя с таким же именем нет, то проверяем данные и добавляем в БД
        if not userinfo['username']:
            return {'result': 'error', 'message': 'Ошибка. Имя пользователя не может быть пустым!',}
        elif userinfo['group_id'] != 'None':
            user.group_id = userinfo['group_id']
        elif userinfo['privilage'] != 'None':
            user.privilage = userinfo['privilage']

        user.username = userinfo['username']

        db.session.commit()
            
        return {
            'result': 'success',
            'message': f'Пользователь {userinfo["username"]} отредактирован!',
        }


    def del_user(self, user_id):
        '''
        Удалить пользователя
        '''
        user = db.session.get(Users, user_id)

        if user:
            if user.id == 1:
                return {
                    'result': 'error',
                    'message': 'Ошибка. Нельзя удалить дефолтного пользователя!',
                }
        
            db.session.delete(user)
            
        else:
            return {'result': 'error', 'message': 'Нет такого пользователя!',}

        db.session.commit()

        return {'result': 'success', 'message': f'Пользователь {user.username} удалён!',}


    def changepsw(self, user_id, psw):
        '''
        Метод для смены пароля пользователя
        '''
        if len(psw) < 8:
            return {
                'result': 'error',
                'message': 'Ошибка. Короткий пароль!',
            }
        
        psw_hash = generate_password_hash(psw)

        user_psw = db.session.get(Users, user_id)
        user_psw.password = psw_hash
        db.session.commit()

        return {
                'result': 'success',
                'message': 'Пароль успешно изменён!',
            }


    def get_user(self, user_id):
        '''
        Метод для получения данных о пользователе по user_id
        '''
        stmt = (
            select(Users)
            .options(joinedload(Users.group))
            .where(Users.id == user_id)
        )
        
        user_info = db.session.scalar(stmt)
        result = {
            'id':        user_info.id,
            'username':  user_info.username,
            'groupname': user_info.group.group_name,
            'privilage': user_info.privilage,
        }

        return result


    def get_user_by_name(self, username):
        '''
        Метод для получения данных о пользователе по user_id
        '''
        stmt = (
            select(Users)
            .options(joinedload(Users.group))
            .where(Users.username == username)
        )
        
        user_info = db.session.scalar(stmt)
        if user_info:
            result = {
                'id':        user_info.id,
                'username':  user_info.username,
                'psw':       user_info.password,
                'groupname': user_info.group.group_name,
                'privilage': user_info.privilage,
            }

            return result
        else:
            False
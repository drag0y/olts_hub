from flask import request, g
from flask_restful import abort
from flask_login import current_user
from functools import wraps

from db_services.db_tokens import ApiTokensServiceDb
from db_services.db_users import UsersServiceDb


def token_required(f):
    '''
    Декоратор для проверки токенов перед API запросом
    '''
    @wraps(f)
    def decorated(*args, **kwargs):
        # Если пользователь зашёл через браузер
        if current_user.is_authenticated:
            userid = current_user.get_id()
            g.userinfo = g.userbase.get_user(userid)
        else:
            # Иначе проверяем наличие токена у пользователей
            token = request.headers.get('Authorization')
            find_user = UsersServiceDb().get_user_by_token(token)

            if find_user:
                g.userinfo = g.userbase.get_user(find_user['id'])

            else:
                # Ищем токен в таблице токенов
                find_token = ApiTokensServiceDb().get_token(token)

                if find_token['result'] == 'error':
                    # Если ничего не нашли, то возвращаем ошибку 401
                    abort(401, message=find_token['result'])
                else:
                    g.userinfo = g.userbase.get_user(find_token['userid'])

        return f(*args, **kwargs)
        
    return decorated
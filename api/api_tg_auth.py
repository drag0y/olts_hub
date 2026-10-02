from flask import g
from flask_restful import Api, Resource
from flask import Blueprint
from flask import request

from services.logger import log_write
from db_services.db_users import UsersServiceDb


api_tg_auth_bp = Blueprint('api/telegram', __name__, url_prefix='/api/telegram')
api = Api(api_tg_auth_bp)


class ApiTgAuth(Resource):
    def post(self):
        '''
        Метод аутентификации пользователя телеграм
        '''
        data = request.get_json(silent=True)
        get_user = UsersServiceDb().get_user_by_name_tgid(username=data['login'], telegram_id=data['telegram_id'])
        if get_user:
            log_write(f'User: {data["login"]} ({data["telegram_id"]}); Action: TG_AUTH; Message: Получил новый токен')

            return {'result': 'success', 'token': get_user['token']}
        
        return {'result': 'error', 'message': 'Неверный логин или telegram_id'}


api.add_resource(ApiTgAuth, "/auth")
from flask import g
from flask_restful import Api, Resource
from flask import Blueprint
from flask import request

from services.logger import log_write
from db_services.db_users import UsersServiceDb


api_max_auth_bp = Blueprint('api/max', __name__, url_prefix='/api/max')
api = Api(api_max_auth_bp)


class ApiMaxAuth(Resource):
    def post(self):
        '''
        Метод аутентификации пользователя телеграм
        '''
        data = request.get_json(silent=True)
        get_user = UsersServiceDb().get_user_by_name_maxid(username=data['login'], max_id=data['max_id'])
        if get_user:
            log_write(f'User: {data["login"]} ({data["max_id"]}); Action: MAX_AUTH; Message: Получил новый токен')

            return {'result': 'success', 'token': get_user['token']}
        
        return {'result': 'error', 'message': 'Неверный логин или max_id'}


api.add_resource(ApiMaxAuth, "/auth")
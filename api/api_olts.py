from flask import g
from flask_restful import Api, Resource
from flask import Blueprint

from db_services.db_olt import OltServiceDb
from cl_int.findolt import FindOlt
from services.logger import log_write
from decorators.token_auth import token_required


api_oltsupdate_bp = Blueprint('api/olts', __name__, url_prefix='/api/olts')

api = Api(api_oltsupdate_bp)

@api_oltsupdate_bp.before_request
def login_required_for_all_routes():
    pass


class ApiOltsUpdate(Resource):
    @token_required
    def get(self):
        '''
        Опросить ВСЕ ОЛТы
        '''
        userinfo = g.userinfo
        if userinfo['privilage'] == 'Administrator':
            olts_list = OltServiceDb.get_olts()
            for o in olts_list:
                olt_find = FindOlt(userinfo, o['id'])
                olt_find.update_olt()

            log_write(f"User: {userinfo['username']}; Action: UPDATE_ALL_OLTS; Message: Опрошены все ОЛТы из базы")
            result = {'result': 'success', 'message': 'Опрос ОЛТов завершён'}

            return result
        else:
            return {
                'result': 'error',
            }


class ApiOltUpdate(Resource):
    @token_required
    def get(self, olt_id):
        '''
        Опросить ОЛТ
        '''
        userinfo = g.userinfo
        if userinfo['privilage'] == 'Administrator':
            olt_find = FindOlt(userinfo, olt_id)
            olt_find.update_olt()

            result = {'result': 'success', 'message': 'Опрос ОЛТа завершён'}

            return result
        else:
            return {
                'result': 'error',
            }


api.add_resource(ApiOltsUpdate, "/oltsupdate")
api.add_resource(ApiOltUpdate, "/oltupdate/<int:olt_id>")
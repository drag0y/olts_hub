from flask import g
from flask_restful import Api, Resource
from flask import Blueprint

from db_services.db_olt import OltServiceDb
from cl_int.findolt import FindOlt
from services.logger import log_write
from decorators.token_auth import token_required


api_oltinfo_bp = Blueprint('api/oltinfo', __name__, url_prefix='/api/oltinfo')

api = Api(api_oltinfo_bp)


class ApiOltInfo(Resource):
    @token_required
    def get(self, olt_id):
        '''
        Информация об ОЛТе
        '''
        userinfo = g.userinfo
        olt_info = FindOlt(userinfo, olt_id=olt_id).oltinfo()

        result = {
            'id':         olt_info['oltid'],
            'hostname':   olt_info['oltname'],
            'descr':      olt_info['descr'],
            'group':      olt_info['group'],
            'olt_state':  olt_info['olt_state'],
            'olt_uptime': olt_info['olt_uptime'],
            'ip_address': olt_info['ip_address'],
            'platform':   olt_info['platform'],
            'countonu':   olt_info['countonu'],
            'ports':      olt_info['ports'],
            'unregonu':   olt_info['unregonu'],
        }

        return result

class ApiOltsList(Resource):
    @token_required
    def get(self):
        '''
        Список ОЛТов
        '''
        userinfo = g.userinfo
        olts_list = OltServiceDb.get_olts()

        if userinfo['privilage'] == 'Administrator' or userinfo['groupname'] == 'default':    
            return olts_list
        else:
            oltslist = []
            for i in olts_list:
                if i['group'] == userinfo['groupname']:
                    oltslist.append(
                        {
                            'id': i['id'],
                            'hostname': i['hostname'],
                            'descr': i['descr'],
                            'ip_address': i['ip_address'],
                        }
                    )

            return oltslist


api.add_resource(ApiOltInfo, "/<int:olt_id>")
api.add_resource(ApiOltsList, "/oltslist")
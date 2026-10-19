from flask import g
from flask_restful import Api, Resource
from flask import Blueprint

from cl_int.findolt import FindOlt
from decorators.token_auth import token_required


api_portinfo_bp = Blueprint('api/oltinfo/port', __name__, url_prefix='/api/oltinfo/port')

api = Api(api_portinfo_bp)


class ApiPortInfo(Resource):
    @token_required
    def get(self, olt_id, port):
        '''
        Страница просмотра дерева
        '''
        olt_port = port.replace(".", "/")
        userinfo = g.userinfo
        try:
            olt_information = FindOlt(userinfo, olt_id, olt_port)
            olt_info = olt_information.oltinfo()
            pon_status = olt_information.ponportstatus()
            
            result = {
                'result': 'success',
                'oltname': olt_info['oltname'],
                'port_status': {'count': len(pon_status), 'onu': pon_status}
            }

            return result
    
        except KeyError:
            return {'resulr': 'error', 'message': 'База устарела, опросите ОЛТ'}
        except ValueError:
            return {'result': 'error', 'message': 'Forbidden'}


api.add_resource(ApiPortInfo, "/<int:olt_id>/<string:port>")

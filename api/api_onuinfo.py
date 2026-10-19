from flask import g
from flask_restful import Api, Resource
from flask import Blueprint

from cl_int.findonu import FindOnu
from decorators.token_auth import token_required


api_onuinfo_bp = Blueprint('api/onuinfo', __name__, url_prefix='/api/onuinfo')

api = Api(api_onuinfo_bp)


class ApiOnuInfo(Resource):
    @token_required
    def get(self, onu):
        try:
            onurequest = FindOnu(onu, g.userinfo)
            onu_info = onurequest.onuinfo()
            result = {
                'result': 'success',
                'onu':    onu_info,
            }
            return result
        
        except ValueError as e:
            result = {
                'result': 'error',
                'message': str(e),
            }
            return result
        
        except TypeError as e:
            result = {
                'result': 'error',
                'message': str(e),
            }
            return result


api.add_resource(ApiOnuInfo, "/<string:onu>")

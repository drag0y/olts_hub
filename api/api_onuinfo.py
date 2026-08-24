from flask import g
from flask_restful import Api, Resource
from flask import Blueprint

from cl_int.findonu import FindOnu
from decorators.token_auth import token_required


api_onuinfo_bp = Blueprint('api', __name__, url_prefix='/api')

api = Api(api_onuinfo_bp)

@api_onuinfo_bp.before_request
def login_required_for_all_routes():
    pass


class ApiOnuinfo(Resource):
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


api.add_resource(ApiOnuinfo, "/onuinfo/<string:onu>")

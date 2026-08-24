from flask import request, g
from flask_restful import abort
from flask_login import current_user
from functools import wraps

from db_services.db_tokens import ApiTokensServiceDb


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if current_user.is_authenticated:
            userid = current_user.get_id()
            g.userinfo = g.userbase.get_user(userid)
        else:
            token = request.headers.get('Authorization')
            find_token = ApiTokensServiceDb().get_token(token.replace('Bearer ', ''))
            
            if find_token['result'] == 'error':
                abort(401, message=find_token['message'])
            else:
                g.userinfo = g.userbase.get_user(find_token['userid'])

        return f(*args, **kwargs)
        
    return decorated
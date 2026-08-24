from sqlalchemy import select, and_
from sqlalchemy.orm import joinedload


from models.base import db
from models.models import ApiTokens


class ApiTokensServiceDb():
    '''
    Класс для работы с API токенами
    '''
    def get_tokens():
        '''
        Метод получения всех токенов из базы
        '''
        stmt = (
            select(ApiTokens)
            .options(
            joinedload(ApiTokens.user))
        )
        
        result = db.session.scalars(stmt).all()

        tokens = []
        for r in result:
            key = r.token
            tokens.append(
                {
                    'id':    r.id,
                    'token': 15*'*' + key[-5:],
                    'user':  r.user.username,
                    'date':  r.created_date,
                }
            )
        
        return tokens


    def get_token(self, token):
        '''
        Метод получения конкретного токена из базы
        '''
        stmt = (
            select(ApiTokens)
            .options(joinedload(ApiTokens.user))
            .where(ApiTokens.token == token)
        )
        
        find_token = db.session.scalar(stmt)
        if find_token:
            result = {
                'result':    'success',
                'id':        int(find_token.id),
                'token':     find_token.token,
                'userid':    find_token.user.id,
            }
        else:
            result = {
                'result':  'error', 
                'message': 'Неавторизованный доступ: неверный токен'
                }

        return result


    def create_token(user_id, token, created_date):
        '''
        Метод создания токена
        '''
        token_add = ApiTokens(
                user_id=user_id,
                token=token,
                created_date=created_date,
                )

        db.session.add(token_add)
        db.session.commit()

        return {'result': 'success', 'message': f'Создан токен: {token}'}


    def del_token(token_id):
        '''
        Метод удаления токена из базы
        '''
        token = db.session.get(ApiTokens, token_id)
        
        db.session.delete(token)
        db.session.commit()

        return {'result': 'success', 'message': 'Токен удалён!',}
from sqlalchemy import select, or_, func
from sqlalchemy.orm import joinedload

from models.base import db
from models.models import Groups, Users, OLTs


class GroupsServiceDb:
    '''
    Класс для работы с группами
    '''
    def get_groups(self):
        '''
        Метод получения списка групп из БД
        '''
        groups = []
        results = db.session.execute(db.select(Groups)).scalars()
        
        for r in results:
            group = {
                'id': r.id,
                'group_name': r.group_name,
            }
            groups.append(group)

        return groups
    

    def add_group(self, groupname):
        '''
        Метод добавления группы в БД
        '''
        if groupname:

            stmt = select(Groups).where(Groups.group_name == groupname)
            findgroup = db.session.execute(stmt).scalars().all()

            if findgroup:
                return {
                    'result': 'error',
                    'message': f'Ошибка. Группа с таких именем ({groupname}) уже есть',
                }
            
            group = Groups(
                group_name=groupname,
                )

            db.session.add(group)
            db.session.commit()
            
            return {
                'result': 'success',
                'message': f'Группа {groupname} добавлена',
            } 
        else:
            return {'result': 'error', 'message': 'Ошибка. Заполните все поля',}
    

    def del_group(self, group_id):
        '''
        Метод удаления группы
        '''
        group = db.session.get(Groups, group_id)
        olts = db.session.execute(select(OLTs).where(OLTs.group_id == group_id)).scalars().all()
        users = db.session.execute(select(Users).where(Users.group_id == group_id)).scalars().all()

        if group:
            if group.id == 1:
                return {
                    'result': 'error',
                    'message': 'Ошибка. Нельзя удалить дефолтную группу',
                    'group': group.group_name,
                }
            
            elif olts:
                return {
                    'result': 'error',
                    'message': 'Ошибка. В данной группе есть ОЛТы',
                    'group': group.group_name,
                }

            elif users:
                return {
                    'result': 'error',
                    'message': 'Ошибка. В данной группе есть пользователи',
                    'group': group.group_name,
                }
            
            db.session.delete(group)

        else:
            return {'result': 'error', 'message': 'Нет такой группы в БД'}

        db.session.commit()
        
        return {
            'result': 'success',
            'message': f'Группа {group.group_name} удалена из базы',
            'group': group.group_name,
            }
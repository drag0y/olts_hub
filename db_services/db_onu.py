from sqlalchemy import select, or_, and_, func
from sqlalchemy.orm import joinedload

from models.base import db
from models.models import Onu


class OnuServiceDb:
    '''
    Класс для работы с ОНУ
    '''
    def get_onu(self, onu):
        '''
        Метод получения всей информации об ОНУ из БД
        '''
        stmt = (
            select(Onu)
            .options(
            joinedload(Onu.olt),
            joinedload(Onu.pon_port_info)
            )
            .where(Onu.onu == onu)
        )
        onuout = db.session.execute(stmt).scalars().all()

        return onuout


    def add_onu(self, olt_id, onu_list):
        '''
        Метод добавления ОНУ в БД
        '''
        for o in onu_list:
            onu = Onu(
                onu=o['onu'],
                port_oid=o['port_oid'],
                onu_oid=o['onu_oid'],
                olt_id=olt_id,
                )
            #Проверяем нет ли точно такой же ОНУ в базе
            stmt = select(Onu).where(
                and_(
                    Onu.onu == o['onu'],
                    Onu.port_oid == o['port_oid'],
                    Onu.onu_oid == o['onu_oid'],
                    Onu.olt_id == olt_id,
                )
            )
            findonu = db.session.execute(stmt).scalars().all()

            if findonu:
                pass
            else:
                db.session.add(onu)

        db.session.commit()

        return f'ОНУ добавлены'


    def count_onu(self, oltid):
        '''
        Метод считает количество ОНУ, зарегистрированные на ОЛТе
        '''
        return db.session.query(Onu).filter(Onu.olt_id == oltid).count()
        

    def del_onu(self, oltid):
        '''
        Метод удаляет все ОНУ конкретного ОЛТа из БД
        '''
        stmt = select(Onu).where(Onu.olt_id == oltid)
        onu = db.session.execute(stmt).scalars().all()
        
        if onu:
            for o in onu:
                db.session.delete(o)
        else:
            return (f'Нет ОНУ для данного ОЛТа {oltid}')
        
        db.session.commit()

        return f'ОНУ ОЛТа {oltid} удалены из базы'


    def del_one_onu(self, oltid, onu):
        '''
        Метод удаляет одну ОНУ конкретного ОЛТа из БД
        '''
        stmt = select(Onu).where(
            and_(
                Onu.olt_id == oltid,
                Onu.onu == onu,
                )
            )
        onu = db.session.execute(stmt).scalars().all()
        
        if onu:
            for o in onu:
                db.session.delete(o)
        else:
            return {'result': 'error', 'message': f'ОНУ {onu} не найдена'}
        
        db.session.commit()

        return {'result': 'success', 'message': f'ОНУ {onu} удалена'}
    

    def find_onu_on_port(self, oltid, port_oid):
        '''
        Метод собирает данные из базы обо всех ОНУ на конкретном порту ОЛТа
        '''
        stmt = select(Onu).where(
            and_(
                Onu.olt_id == oltid,
                Onu.port_oid == port_oid,
            )
        )
        findonu = db.session.execute(stmt).scalars().all()
        db_onuinfo = []
        for f in findonu:
            db_onuinfo.append(
                {
                'id': str(f.onu_oid),
                'onu': f.onu,
                'portoid': f.port_oid,
                }
            )

        return db_onuinfo

    
    def get_double_onu(self, userinfo):
        '''
        Метод получения дублирующихся ОНУ
        '''
        stmt = (
            select(Onu.onu, func.count(Onu.onu))
            .group_by(Onu.onu)
            .having(func.count(Onu.onu) > 1)
        )
        doubleonu = db.session.execute(stmt).scalars().all()

        doublemac = []
        doublesn = []
        for o in doubleonu:
            stmt = (
                select(Onu)
                .options(
                joinedload(Onu.olt),
                joinedload(Onu.pon_port_info)
                )
                .where(Onu.onu == o)
            )
            result = db.session.execute(stmt).scalars().all()
            for onu in result:
                if len(onu.onu) == 12:
                    onuinfo = {
                        'onu': onu.onu,
                        'group': onu.olt.group.group_name,
                        'olt_ip': onu.olt.ip_address,
                    }
                    doublemac.append(onuinfo)
                elif len(onu.onu) == 16:
                    onuinfo = {
                        'onu': onu.onu,
                        'group': onu.olt.group.group_name,
                        'olt_ip': onu.olt.ip_address,
                    }
                    doublesn.append(onuinfo)

        return doublemac, doublesn
from sqlalchemy import select, or_
from sqlalchemy.orm import joinedload
import ipaddress

from models.base import db
from models.models import OLTs, PonPorts, Onu

class OltServiceDb:
    '''
    Класс для работы с ОЛТами в БД
    '''
    def create_olt(self, addolt):
        '''
        Метод создаёт новый ОЛТ в БД
        '''
        #Смотрим, есть ли в базе такой ОЛТ
        stmt = select(OLTs).where(
            or_(
                OLTs.hostname == addolt['hostname'],
                OLTs.ip_address == addolt['ip_address'],
            )
        )
        findout = db.session.execute(stmt).scalars().all()
        
        if findout:
            return {'result': 'error', 'message': 'Ошибка. ОЛТ с таких именем или ip адресом уже есть',}
        
        else:
            try:
                ipv4 = ipaddress.ip_address(addolt['ip_address'])
            except:
                return "Ошибка. Некорректный IP адресс"
            
            if not addolt['hostname']:
                return {'result': 'error', 'message': 'Ошибка. Пустое имя ОЛТа',}
            elif "Выберите" in addolt['group_id']:
                return {'result': 'error', 'message': 'Ошибка. Вы не выбрали группу',}
            elif "Выберите" in addolt['platform']:
                return {'result': 'error', 'message': 'Ошибка. Вы не выбрали платформу',}
            elif "Выберите" in addolt['pon_type']:
                return {'result': 'error', 'message': 'Ошибка. Вы не выбрали тип портов',}
            elif "Выберите" in addolt['conn_type']:
                addolt['conn_type'] = 'not'

            olt = OLTs(
                hostname=addolt['hostname'],
                descr=addolt['descr'],
                ip_address=addolt['ip_address'],
                group_id=addolt['group_id'],
                platform=addolt['platform'],
                pon_type=addolt['pon_type'],
                snmp_read=addolt['snmp_read'],
                snmp_write=addolt['snmp_write'],
                conn_type=addolt['conn_type'],
                conn_login=addolt['conn_login'],
                conn_psw=addolt['conn_psw'],
                )

            db.session.add(olt)
            db.session.commit()
            
            return {'result': 'success', 'message': f'OLT {addolt["hostname"]} добавлен в базу',}
        

    def create_olt_nb(self, addolt):
        '''
        Метод создаёт новый ОЛТ в БД полученный из NetBox
        '''
        #Смотрим, есть ли в базе такой ОЛТ
        stmt = select(OLTs).where(
            or_(
                OLTs.hostname == addolt['hostname'],
                OLTs.ip_address == addolt['ip_address'],
            )
        )
        findout = db.session.execute(stmt).scalars().all()
        
        if findout:
            return {'result': 'error', 'message': 'Ошибка. ОЛТ с таких именем или ip адресом уже есть',}
        
        else:
            try:
                ipv4 = ipaddress.ip_address(addolt['ip_address'])
            except:
                return {'result': 'error', 'message': 'Ошибка. Некорректный IP адресс',}

            olt = OLTs(
                hostname=addolt['hostname'],
                descr=addolt['descr'],
                ip_address=addolt['ip_address'],
                group_id=addolt['group_id'],
                platform=addolt['platform'],
                pon_type=addolt['pon_type'],
                snmp_read=addolt['snmp_read'],
                snmp_write=addolt['snmp_write'],
                conn_type=addolt['conn_type'],
                conn_login=addolt['conn_login'],
                conn_psw=addolt['conn_psw'],
                )

            db.session.add(olt)
            db.session.commit()
            
            return {'result': 'success', 'message': f'OLT {addolt["hostname"]} добавлен в базу',}


    def delete_olt(self, oltid):
        '''
        Метод удаляет ОЛТ из БД
        '''
        olt = db.session.get(OLTs, oltid)
        onu = db.session.execute(select(Onu).where(Onu.olt_id == oltid)).scalars().all()
        ponports = db.session.execute(select(PonPorts).where(PonPorts.olt_id == oltid)).scalars().all()
        
        if onu:
            for o in onu:
                db.session.delete(o)
        if ponports:
            for p in ponports:
                db.session.delete(p)
        if olt:
            db.session.delete(olt)
        else:
            return {'result': 'success', 'message': 'Нет такого ОЛТа в БД',}

        db.session.commit()

        return {'result': 'success', 'message': f'ОЛТ {olt.hostname} удалён из базы',}
    

    def get_olt(self, oltid):      
        '''
        Получение информации об ОЛТе из БД
        '''
        stmt = (
            select(OLTs)
            .options(joinedload(OLTs.group))
            .where(OLTs.id == oltid)
        )

        return db.session.scalar(stmt)
    

    def get_olts():      
        '''
        Получение информации об ОЛТах из БД
        '''
        stmt = (
            select(OLTs)
            .options(joinedload(OLTs.group))
        )
        
        olts_list = db.session.scalars(stmt).all()

        oltslist = []
        for i in olts_list:       
            oltslist.append(
                {
                    'id': i.id,
                    'hostname': i.hostname,
                    'group': i.group.group_name,
                    'descr': i.descr,
                    'ip_address': i.ip_address,
                }
            )

        return oltslist
    

    def edit_olt(self, oltinfo):
        '''
        Редактирование ОЛТа
        '''
        # Проверяем нет ОЛТа с таким же именем и ip, что бы не было дубликатов
        stmt = select(OLTs).where(
            OLTs.id != oltinfo['id'],
            or_(
                OLTs.hostname == oltinfo['hostname'],
                OLTs.ip_address == oltinfo['ip_address'],
            )
        )
        findout = db.session.execute(stmt).scalars().all()
        
        if findout:
            return {
                'result': 'error',
                'message': 'Ошибка. ОЛТ с таких именем или ip адресом уже есть'
            }
        
        # Берём из базы инфу об ОЛТе
        olt = db.session.get(OLTs, oltinfo['id'])

        # Проверяем данные на правильность, и если всё Ок, то обновляем базу
        if len(oltinfo['hostname']) > 2:
            olt.hostname = oltinfo['hostname']
        else:
            return {
                'result': 'error',
                'message': 'Bad hostname'
            }
        
        olt.descr = oltinfo['descr']

        if oltinfo['ip_address']:
            try:
                ipv4 = ipaddress.ip_address(oltinfo['ip_address'])
            except:
                return {
                    'result': 'error',
                    'message': 'Ошибка. Некорректный IP адресс'
                    }
            olt.ip_address = oltinfo['ip_address']
        else:
            return {
                'result': 'error',
                'message': 'Ошибка. Некорректный IP адресс'
            }
        
        if oltinfo['group_id'] != 'None':
            olt.group_id = oltinfo['group_id']
        
        if oltinfo['platform'] != 'None':
            olt.platform = oltinfo['platform']

        if oltinfo['pon_type'] != 'None':
            olt.pon_type = oltinfo['pon_type']

        olt.snmp_read = oltinfo['snmp_read']
        olt.snmp_write = oltinfo['snmp_write']
        
        if oltinfo['conn_type'] != 'None':
            olt.conn_type = oltinfo['conn_type']

        olt.conn_login = oltinfo['conn_login']
        
        if oltinfo['conn_psw'] != 'None':
            olt.conn_psw = oltinfo['conn_psw']
            
        db.session.commit()
        
        return {
            'result': 'success',
            'message': f'ОЛТ {oltinfo["hostname"]} отредактирован'
        }
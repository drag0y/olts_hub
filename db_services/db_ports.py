from sqlalchemy import select, or_, and_
from models.base import db
from models.models import PonPorts


class PortsServiceDb:
    '''
    Класс для работы с портами
    '''
    def get_ports(self, oltid):
        '''
        Метод получения списка портов ОЛТа из БД
        '''
        stmt = select(PonPorts).where(
            or_(
                PonPorts.olt_id == oltid,
            )
        )
        result = db.session.execute(stmt).scalars().all()

        return result
    

    def find_port(self, oltid, ponport):
        '''
        Метод ищет порт в БД, по id ОЛТа и названию порта
        '''
        stmt = select(PonPorts).where(
            and_(
                PonPorts.olt_id == oltid,
                PonPorts.pon_port.like(ponport),
            )
        )
        result = db.session.execute(stmt).scalars().all()
        
        return result


    def find_port_by_oid(self, oltid, port_oid):
        '''
        Метод ищет порт в БД, по id ОЛТа и OID порта
        '''
        stmt = select(PonPorts).where(
            and_(
                PonPorts.olt_id == oltid,
                PonPorts.port_oid == port_oid,
            )
        )
        result = db.session.execute(stmt).scalars().all()

        return result
    

    def add_port(self, olt_id, ports):
        '''
        Метод добавления портов ОЛТа в БД
        '''
        for p in ports:
            port = PonPorts(
                pon_port=p['pon_port'],
                port_oid=p['port_oid'],
                olt_id=olt_id,
                )
            #Проверяем нет ли точно такого же порта в базе
            stmt = select(PonPorts).where(
                and_(
                    PonPorts.pon_port == p['pon_port'],
                    PonPorts.port_oid == p['port_oid'],
                    PonPorts.olt_id == olt_id,
                )
            )
            findport = db.session.execute(stmt).scalars().all()

            if findport:
                pass
            else:
                db.session.add(port)
                
            db.session.commit()

        return f'Порты добавлены'


    def del_port(self, oltid):
        '''
        Метод удаляет порты конкретного ОЛТа из БД
        '''
        stmt = select(PonPorts).where(PonPorts.olt_id == oltid)
        ponports = db.session.execute(stmt).scalars().all()
    
        if ponports:
            for p in ponports:
                db.session.delete(p)
        else:

            return (f'Нет портов для данного ОЛТа {oltid}')
        db.session.commit()

        return f'Порты ОЛТа {oltid} удалены из базы'
    
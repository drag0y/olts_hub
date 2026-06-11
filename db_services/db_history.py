from sqlalchemy import select, and_
import datetime

from models.base import db
from models.models import History


class HistoryServiceDb:
    '''
    Класс для работы с историей сигналов
    '''
    def get_history(self, oltid, onu):
        '''
        Метод получения истории опросов ОНУ
        '''
        history = []
        stmt = select(History).where(
            and_(
                History.onu == onu,
                History.olt_id == oltid,
            )
        )
        results = db.session.execute(stmt).scalars().all()
        
        for r in results:
            onu_status = {
                'date':   r.date,
                'status': r.status,
                'descr':  r.descr,
                'rxonu':  float(r.rx_onu),
                'rxolt':  float(r.rx_olt),
            }
            
            history.insert(0, onu_status)
        
        return history
    

    def add_history(self, onu, oltid, status, reason_down, rxonu, rxolt):
        '''
        Метод добавления статуса и сигнала ОНУ
        '''
        now = datetime.datetime.now()
        formatted_date = now.strftime("%Y.%m.%d %H:%M:%S")

        onu_status = History(
                onu=onu,
                olt_id=oltid,
                date=formatted_date,
                status=status,
                descr=reason_down,
                rx_onu=rxonu,
                rx_olt=rxolt,
                )
            
        db.session.add(onu_status)

        db.session.commit()

        return {'result': 'success', 'message': 'ONU status was added in DB'}
    

    def delete_history(self, oltid, onu):
        '''
        Метод удаляет историю опросов
        '''
        stmt = select(History).where(
            and_(
                History.onu == onu,
                History.olt_id == oltid,
            )
        )
        findonu = db.session.execute(stmt).scalars().all()
        
        if findonu:
            for o in findonu:
                db.session.delete(o)
        else:
            return {'result': 'error', 'message': f'У ОНУ {onu} нет истории сигналов'}
        
        db.session.commit()

        return {'result': 'success', 'message': f'История сигналов {onu} очищена'}
    

    def get_all_history(self):
        '''
        Метод получения истории опросов ОНУ
        '''
        results = db.session.execute(db.select(History)).scalars().all()
        
        history_count = len(results)
        
        return {'history_count': history_count}
    

    def delete_all_history(self):
        '''
        Метод удаляет историю опросов
        '''
        del_history = db.session.execute(db.select(History)).scalars().all()
        
        if del_history:
            for o in del_history:
                db.session.delete(o)
        else:
            return {'result': 'error', 'message': 'Нет истории сигналов'}
        
        db.session.commit()

        return {'result': 'success', 'message': 'История сигналов очищена'}
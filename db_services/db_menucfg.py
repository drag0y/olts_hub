from sqlalchemy import select, or_

from models.base import db
from models.models import MenuCfg


class MenuServiceDb:
    '''
    Класс для работы с меню конфигурациями
    '''
    def getmenucfg(self, privilage):
        '''
        Получить словарь с меню настроек
        '''
        menu = []
        if privilage == 'Administrator':
            results = db.session.execute(db.select(MenuCfg)).scalars()
            for m in results:
                menu.append(
                    {
                        'menuname': m.menuname,
                        'url': m.url,
                        'privilage': m.privilage,
                    }
                )
        elif privilage == 'Operator':
            stmt = select(MenuCfg).where(
                or_(
                    MenuCfg.privilage == privilage,
                )
            )
            results = db.session.execute(stmt).scalars().all()
            for m in results:
                menu.append(
                    {
                        'menuname': m.menuname,
                        'url': m.url,
                        'privilage': m.privilage,
                    }
                )
        
        return menu
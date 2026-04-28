import sqlite3
from sqlalchemy import select, or_, func
from models.base import db
from models.models import Cfg


class CfgServiceDb:
    '''
    Класс для работы с конфигурациями
    '''
    def get_cfg(self):
        '''
        Получить словарь со всеми настройками
        '''
        configs = {}
        results = db.session.execute(db.select(Cfg)).scalars()
        
        for r in results:
            config = {
                r.key: r.value,
            }
            configs.update(config)
        
        return configs


    def insertcfgnb(self, nb_conf):
        '''
        Редактирование конфигурации NetBox
        '''
        #api_key, epon_tag, gpon_tag, urlnb, pl_h, pl_b, pl_c
        
        if nb_conf['api_key']:
            stmt = select(Cfg).where(Cfg.key == 'API_KEY')
            result = db.session.execute(stmt).scalars().all()
            for r in result:
                r.value = nb_conf['api_key']

        if nb_conf['epon_tag']:
            stmt = select(Cfg).where(Cfg.key == 'EPON_TAG')
            result = db.session.execute(stmt).scalars().all()
            for r in result:
                r.value = nb_conf['epon_tag']

        if nb_conf['gpon_tag']:
            stmt = select(Cfg).where(Cfg.key == 'GPON_TAG')
            result = db.session.execute(stmt).scalars().all()
            for r in result:
                r.value = nb_conf['gpon_tag']

        if nb_conf['urlnb']:
            stmt = select(Cfg).where(Cfg.key == 'URLNB')
            result = db.session.execute(stmt).scalars().all()
            for r in result:
                r.value = nb_conf['urlnb']

        if nb_conf['pl_h']:
            stmt = select(Cfg).where(Cfg.key == 'PL_H')
            result = db.session.execute(stmt).scalars().all()
            for r in result:
                r.value = nb_conf['pl_h']

        if nb_conf['pl_b']:
            stmt = select(Cfg).where(Cfg.key == 'PL_B')
            result = db.session.execute(stmt).scalars().all()
            for r in result:
                r.value = nb_conf['pl_b']

        if nb_conf['pl_c']:
            stmt = select(Cfg).where(Cfg.key == 'PL_C')
            result = db.session.execute(stmt).scalars().all()
            for r in result:
                r.value = nb_conf['pl_c']

        db.session.commit()

        return {'result': 'success', 'message': 'Настройки отредактированы!'}


    def insert_cfg_snmp(self, snmp_cfg):
        '''
        Редактирование конфигурации SNMP
        '''        
        if snmp_cfg['snmp_read_h']:
            stmt = select(Cfg).where(Cfg.key == 'SNMP_READ_H')
            result = db.session.execute(stmt).scalars().all()
            for r in result:
                r.value = snmp_cfg['snmp_read_h']
                
        if snmp_cfg['snmp_write_h']:
            stmt = select(Cfg).where(Cfg.key == 'SNMP_WRITE_H')
            result = db.session.execute(stmt).scalars().all()
            for r in result:
                r.value = snmp_cfg['snmp_write_h']

        if snmp_cfg['snmp_read_b']:
            stmt = select(Cfg).where(Cfg.key == 'SNMP_READ_B')
            result = db.session.execute(stmt).scalars().all()
            for r in result:
                r.value = snmp_cfg['snmp_read_b']

        if snmp_cfg['snmp_write_b']:
            stmt = select(Cfg).where(Cfg.key == 'SNMP_WRITE_B')
            result = db.session.execute(stmt).scalars().all()
            for r in result:
                r.value = snmp_cfg['snmp_write_b']
                
        if snmp_cfg['snmp_read_c']:
            stmt = select(Cfg).where(Cfg.key == 'SNMP_READ_C')
            result = db.session.execute(stmt).scalars().all()
            for r in result:
                r.value = snmp_cfg['snmp_read_c']
            
        if snmp_cfg['snmp_write_c']:
            stmt = select(Cfg).where(Cfg.key == 'SNMP_WRITE_C')
            result = db.session.execute(stmt).scalars().all()
            for r in result:
                r.value = snmp_cfg['snmp_write_c']

        db.session.commit()

        return {'result': 'success', 'message': 'Настройки отредактированы!'}


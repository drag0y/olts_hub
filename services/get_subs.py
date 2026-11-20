import requests
import json

from db_services.db_cfg import CfgServiceDb
from services.logger import log_write


def get_subscriber(onu):
    '''
    Функция опрашивает биллинг MikBill по серийнику или маку ОНУ,
    и вытягивает информацию об абоненте
    '''
    onu = onu.replace(' ','') \
                     .replace(':', '') \
                     .replace('.', '') \
                     .replace('hwtc', '48575443') \
                     .replace('-', '')

    nbcfg = CfgServiceDb()
    cfg = nbcfg.get_cfg()
    MIKBILL_KEY = cfg['MIKBILL_KEY']
    MIKBILL_URL = cfg['MIKBILL_URL']

    uid = '-'
    state = '-'
    online = '-'
    address = '-'

    if 'None' in MIKBILL_KEY or 'None' in MIKBILL_URL:
        return {
            'uid': uid,
            'state': state,
            'online': online,
            'address': address,
            'sub_url': '-',
        }

    if len(onu) == 12:
        GET_URL = f"/json/index/usermanager?key={MIKBILL_KEY}&request=get_user_by_onu&mac={onu}"
    elif len(onu) == 16:
        GET_URL = f"/json/index/usermanager?key={MIKBILL_KEY}&request=get_user_by_onu&serial={onu}"
    else:
        raise TypeError('Wrong MAC or SN')

    HEADERS = {"Authorization": MIKBILL_KEY}

    try:
        response = requests.get(MIKBILL_URL+GET_URL, headers=HEADERS, verify=False)
        subscribers = json.loads(json.dumps(response.json(), indent=4))

    except requests.exceptions.ConnectionError as e:
        state = f'Ошибка подключения к биллингу'
        subscribers = {
            'result': 'error',
        }
        log_write(f'User: ; Action: Bill Connect; Msg: Ошибка подключения к биллингу {e}')
    except requests.exceptions.InvalidURL:
        subscribers = {
                    'result': 'error',
                }
        log_write(f'User: ; Action: Bill Connect; Msg: Некоректный URL биллинга')

    state_id = {
        1: 'Активен',
        2: 'Заблокирован',
        3: 'Заморожен',
        4: 'Удалён',
    }

    online_id = {
        0: 'Offline',
        1: 'Online',
    }

    if subscribers['result'] == 'ok':
        for s in subscribers['users']:
            uid = s['uid']
            state = state_id[s['state_id']]
            online = online_id[s['online']]
            address = s['address']

    result = {
        'uid': uid,
        'state': state,
        'online': online,
        'address': address,
        'sub_url': f'{MIKBILL_URL}/#clientcard/{uid}',
    }

    return result
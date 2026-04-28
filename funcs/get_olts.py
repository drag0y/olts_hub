import requests
import json
import ipaddress

from db_services.db_cfg import CfgServiceDb
from db_services.db_olt import OltServiceDb


def get_netbox_olt_list():
    '''
    Функция опрашивает NetBox по тегам, добавляет ОЛТы в БД.
    И дальше передаёт данные об ОЛТе в другие функции для опроса.
    '''
    nbcfg = CfgServiceDb()
    cfg = nbcfg.get_cfg()
    TOKEN_API = cfg['API_KEY']
    URLNB = cfg['URLNB']
    EPON_TAG = cfg['EPON_TAG']
    GPON_TAG = cfg['GPON_TAG']

    HEADERS = {"Authorization": TOKEN_API}
    #
    URLGETEPON = f"{URLNB}/api/dcim/devices/?q=&tag={EPON_TAG}"
    URLGETGPON = f"{URLNB}/api/dcim/devices/?q=&tag={GPON_TAG}"
  
    # --- Получениие списка Epon ОЛТов, если такие есть, то передаём их в функцию snmpgetonu 
    if EPON_TAG:
        response = requests.get(URLGETEPON, headers=HEADERS, verify=False)
        olts_list = json.loads(json.dumps(response.json(), indent=4))
        if 'results' in olts_list:
            added_olt = []
            for o in olts_list["results"]:
                olt_addr = ipaddress.ip_interface(o["primary_ip4"]["address"])
                olt_ip = str(olt_addr.ip)
                
                oltadd = OltServiceDb()

                olt = {
                'hostname': o["name"],
                'descr': o["description"],
                'group_id': 1,
                'ip_address': olt_ip,
                'platform': o["platform"]["name"],
                'pon_type': 'epon',
                'snmp_read': '',
                'snmp_write': '',
                'conn_type': '',
                'conn_login': '',
                'conn_psw': '',
                }

                addolt = oltadd.create_olt_nb(olt)

                added_olt.append(addolt)


    # --- Получение списка Gpon ОЛТов, если такие есть, то передаём их в функцию snmpgetonu 
    if GPON_TAG:
        response = requests.get(URLGETGPON, headers=HEADERS, verify=False)
        olts_list = json.loads(json.dumps(response.json(), indent=4))

        if 'results' in olts_list:
            added_olt = []
            for o in olts_list["results"]:
                olt_addr = ipaddress.ip_interface(o["primary_ip4"]["address"])
                olt_ip = str(olt_addr.ip)
                
                oltadd = OltServiceDb()

                olt = {
                'hostname': o["name"],
                'descr': o["description"],
                'group_id': 1,
                'ip_address': olt_ip,
                'platform': o["platform"]["name"],
                'pon_type': 'gpon',
                'snmp_read': '',
                'snmp_write': '',
                'conn_type': '',
                'conn_login': '',
                'conn_psw': '',
                }

                addolt = oltadd.create_olt_nb(olt)

                added_olt.append(addolt)
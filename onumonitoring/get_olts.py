import requests
import json
import ipaddress
import sqlite3

from onumonitoring.bdcom_olts import BdcomGetOltInfo
from onumonitoring.huawei_olts import HuaweiGetOltInfo
from onumonitoring.work_db import WorkDB, WorkingDB
from config import URLGETEPON, URLGETGPON, GPON_TAG, EPON_TAG, HEADERS, PATHDB, SNMP_READ_H, SNMP_READ_B, PF_HUAWEI, PF_BDCOM


def get_netbox_olt_list():
# --- Функция опрашивает NetBox по тегам, создаёт БД, обнуляя старую если есть.
# --- И дальше передаёт данные об ОЛТе в другие функции для опроса

    out_epon_olts = []
    out_gpon_olts = []

    epon = "epon"
    gpon = "gpon"

    # --- Создание таблицы с ОЛТами, если существует, то старая удаляется
    db = WorkDB(PATHDB)
    db.createnewtableolts()

    # --- Получениие списка Epon ОЛТов, если такие есть, то передаём их в функцию snmpgetonu 
    if EPON_TAG:
        response = requests.get(URLGETEPON, headers=HEADERS, verify=False)
        olts_list = json.loads(json.dumps(response.json(), indent=4))

        conn = sqlite3.connect(PATHDB)
        cursor = conn.cursor()
        query_ports = "INSERT into olts(hostname, ip_address, platform, pon) values (?, ?, ?, ?)"

        for parse_olts_list in olts_list["results"]:
            olt_name = []
            olt_addr = []
            olt_name = parse_olts_list["description"]
            olt_addr = ipaddress.ip_interface(parse_olts_list["primary_ip4"]["address"])
            olt_ip = str(olt_addr.ip)
            platform = parse_olts_list["platform"]["name"]

            out_epon_olts.append(olt_name + " " + olt_ip)

            oltlist = olt_name, olt_ip, platform, "epon"
            cursor.execute(query_ports, oltlist)

        conn.commit()
        conn.close()

    # --- Получение списка Gpon ОЛТов, если такие есть, то передаём их в функцию snmpgetonu 
    if GPON_TAG:
        response = requests.get(URLGETGPON, headers=HEADERS, verify=False)
        olts2_list = json.loads(json.dumps(response.json(), indent=4))

        conn = sqlite3.connect(PATHDB)
        cursor = conn.cursor()
        query_ports = "INSERT into olts(hostname, ip_address, platform, pon) values (?, ?, ?, ?)"

        for parse_olts_list in olts2_list["results"]:
            olt_name = []
            olt_addr = []
            olt_name = parse_olts_list["description"]
            olt_addr = ipaddress.ip_interface(parse_olts_list["primary_ip4"]["address"])
            olt_ip = str(olt_addr.ip)
            platform = parse_olts_list["platform"]["name"]
            
            out_gpon_olts.append(olt_name + " " + olt_ip)
            
            oltlist = olt_name, olt_ip, platform, "gpon"
            cursor.execute(query_ports, oltlist)
            
        conn.commit()
        conn.close()


def olts_update(pathdb):
    # Функция запускает процесс опроса ОЛТов
    conn = sqlite3.connect(pathdb)
    cursor = conn.cursor()
    olts = []
    oltslist = cursor.execute('SELECT * FROM olts')
    for olts_list in oltslist:
        olts.append(olts_list)

    db = WorkDB(pathdb)
    db.createnewtableponports()
    db.createnewtableepon()
    db.createnewtablegpon()

    conn.close()

    if olts:
        for olt in olts:
            hostname = olt[1]
            ip_address = olt[2]
            platform = olt[3]
            pon_type = olt[4]

            if PF_HUAWEI in platform:
                olt = HuaweiGetOltInfo(hostname, ip_address, SNMP_READ_H, PATHDB, pon_type)
                olt.getoltports()
                olt.getonulist()

            elif PF_BDCOM in platform:
                olt = BdcomGetOltInfo(hostname, ip_address, SNMP_READ_B, PATHDB, pon_type)
                olt.getoltports()
                olt.getonulist()


def update_olt(pathdb, number):
    # Функция опроса конкретного ОЛТа
    conn = sqlite3.connect(pathdb)
    cursor = conn.cursor()
    findolt = cursor.execute(f'SELECT ip_address FROM olts WHERE number GLOB "{number}"')
    
    for oltinfo in findolt:
        ip_address = oltinfo[0]
        
    db = WorkingDB(pathdb, ip_address)
    db.drop_olt()
    db.olt_update()
    
    conn.close()


# Конфигурация сервера
IP_SRV = "0.0.0.0"
PORT_SRV = "5000"
#
# Конфигурация для работы с NetBox
NETBOX = "1" # 1 - работаем через НетБокс, 2 - добавляем ОЛТы в ручную, без НетБокса
HEADERS = {"Authorization": "Token "} 
EPON_TAG = "epon" 
GPON_TAG = "gpon"
URLNB = "https://" 
URLGETEPON = f"{URLNB}/api/dcim/devices/?q=&tag={EPON_TAG}"
URLGETGPON = f"{URLNB}/api/dcim/devices/?q=&tag={GPON_TAG}"
#
# Платформы, такие слова должны быть в названии платформы у ОЛТа в НетБоксе,
# Либо в таблице, если ОЛТы создаются вручную
PF_HUAWEI = "Huawei_OLT"
PF_BDCOM = "BDCOM"
#
# Имя базы и путь до неё, папка должна быть instance, иначе не будет работать
NAMEDB = "onulist.db"
PATHDB = f"instance/{NAMEDB}"
#
# Параметры SNMP community
# На чтение
SNMP_READ_H = "public" # Huawei
SNMP_READ_B = "public" # BDCOM
#
# На запись
SNMP_CONF_H = "" # Huawei
SNMP_CONF_B = "" # BDCOM

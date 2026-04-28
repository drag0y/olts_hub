import sqlite3


if __name__ == "__main__":
    conn = sqlite3.connect("instance/backup.db")
    cursor = conn.cursor()

    getusers = cursor.execute(f'select * from users')

    users = []
    olts = []

    for u in getusers:
        user = [     
            u[1],
            u[2],
            u[3],
            1,
        ]
        
        users.append(user)

    getolts = cursor.execute(f'select * from olts')

    for o in getolts:
        olt = [
            o[1],
            '',
            1,
            o[2],
            o[3],
            o[4],
            '',
            '',
            '',
            '',
            '',
        ]
        olts.append(olt)

    conn.close()

    conn = sqlite3.connect("instance/onulist.db")
    cursor = conn.cursor()

    query_user = "INSERT into users(username, password, privilage, group_id) values (?, ?, ?, ?)"

    for u in users:
        if u[0] == 'root':
            cursor.execute(f"UPDATE users SET password = '{u[1]}' WHERE id = 1")
        else:
            cursor.execute(query_user, u)

    conn.commit()
    
    query_olt = "INSERT into olts \
        (hostname, descr, group_id, ip_address, platform, pon_type, snmp_read, snmp_write, conn_type, conn_login, conn_psw) \
        values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"

    for o in olts:
        cursor.execute(query_olt, o)

    conn.commit()
    conn.close()

    print("Выполнен перенос данных")

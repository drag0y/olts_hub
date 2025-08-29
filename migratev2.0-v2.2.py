from cl_db.db_migrate import MigrateDB


# Имя базы и путь до неё, папка должна быть instance, иначе не будет работать
NAMEDB = "onulist.db"
PATHDB = f"instance/{NAMEDB}"


if __name__ == "__main__":
    newdb = MigrateDB(PATHDB)
    newdb.updatev2v22()
    print('Миграция базы с версии 2, в версию 2.2, прошла успешно.')

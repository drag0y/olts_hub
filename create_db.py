from config import PATHDB
from onumonitoring.work_db import WorkDB

if __name__ == "__main__":
    newdb = WorkDB(PATHDB)
    newdb.createnewdb()
    print(f"Создана новая база данных: {PATHDB}")

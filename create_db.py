#from config import PATHDB
from onumonitoring.work_db import WorkDB

from dotenv import load_dotenv


load_dotenv()

# Имя базы и путь до неё, папка должна быть instance, иначе не будет работать
NAMEDB = "onulist.db"
PATHDB = f"instance/{NAMEDB}"


if __name__ == "__main__":
    newdb = WorkDB(PATHDB)
    newdb.createnewdb()
    print(f"Создана новая база данных: {PATHDB}")

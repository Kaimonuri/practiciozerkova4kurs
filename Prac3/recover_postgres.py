from getpass import getpass
from pathlib import Path
import shutil

import psycopg
from psycopg import sql

from setup_db import main as setup_project


HBA = Path(r"C:\Program Files\PostgreSQL\18\data\pg_hba.conf")
BACKUP = HBA.with_name("pg_hba.conf.codex-backup")
TEMP_RULE = b"host postgres postgres 127.0.0.1/32 trust\n"


def main():
    if BACKUP.exists():
        raise RuntimeError(f"Найдена предыдущая резервная копия: {BACKUP}. Проверьте её вручную.")
    if not HBA.exists():
        raise RuntimeError(f"Файл не найден: {HBA}")

    new_password = getpass("Новый пароль postgres: ")
    repeated = getpass("Повторите новый пароль: ")
    if new_password != repeated or len(new_password) < 12:
        raise ValueError("Пароли не совпадают или короче 12 символов")

    original = HBA.read_bytes()
    shutil.copy2(HBA, BACKUP)
    restored = False
    try:
        HBA.write_bytes(TEMP_RULE + original)
        with psycopg.connect(
            host="127.0.0.1", port=5432, dbname="postgres",
            user="postgres", autocommit=True,
        ) as conn:
            conn.execute(sql.SQL("ALTER ROLE postgres PASSWORD {}").format(
                sql.Literal(new_password)
            ))
    finally:
        shutil.copy2(BACKUP, HBA)
        restored = True

    with psycopg.connect(
        host="127.0.0.1", port=5432, dbname="postgres",
        user="postgres", password=new_password,
    ) as conn:
        conn.execute("SELECT 1")

    if restored:
        BACKUP.unlink()
    setup_project(new_password)
    print("Пароль postgres изменён, прежняя защита восстановлена.")


if __name__ == "__main__":
    main()

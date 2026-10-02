from getpass import getpass
from pathlib import Path
import secrets

import psycopg
from psycopg import sql


ROOT = Path(__file__).resolve().parent


def main(postgres_password=None):
    if postgres_password is None:
        postgres_password = getpass("Пароль пользователя postgres: ")
    with psycopg.connect(
        host="127.0.0.1",
        port=5432,
        dbname="postgres",
        user="postgres",
        password=postgres_password,
        autocommit=True,
    ) as conn:
        with conn.cursor() as cur:
            role_password = secrets.token_hex(24)
            admin_password = secrets.token_hex(16)

            cur.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", ("cleaning_app",))
            if cur.fetchone():
                cur.execute(sql.SQL("ALTER ROLE cleaning_app PASSWORD {}").format(
                    sql.Literal(role_password)
                ))
            else:
                cur.execute(sql.SQL("CREATE ROLE cleaning_app LOGIN PASSWORD {}").format(
                    sql.Literal(role_password)
                ))

            cur.execute("SELECT 1 FROM pg_database WHERE datname = %s", ("cleaning",))
            if cur.fetchone():
                with psycopg.connect(
                    host="127.0.0.1", port=5432, dbname="cleaning",
                    user="postgres", password=postgres_password, autocommit=True,
                ) as cleaning_conn:
                    cleaning_conn.execute(
                        "GRANT USAGE, CREATE ON SCHEMA public TO cleaning_app"
                    )
            else:
                cur.execute("CREATE DATABASE cleaning OWNER cleaning_app")

    env_path = ROOT / ".env"
    env_path.write_text(
        "\n".join([
            f"DATABASE_URL=postgresql://cleaning_app:{role_password}@127.0.0.1:5432/cleaning",
            "ADMIN_LOGIN=Admin",
            f"ADMIN_PASSWORD={admin_password}",
            "",
        ]),
        encoding="utf-8",
    )

    from server import init_db
    init_db()
    print("База cleaning, таблицы и администратор готовы.")
    print("Логин администратора: Admin. Пароль сохранён в .env.")
    print("Теперь выполните: python server.py")


if __name__ == "__main__":
    main()

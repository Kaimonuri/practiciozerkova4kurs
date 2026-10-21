#!/bin/sh
# Подготавливаем роль приложения и права на базу при первом запуске PostgreSQL.
# cleaning — администратор БД в Docker, cleaning_app — роль сайта.
# Пользователь и администратор сайта различаются полем users.is_admin.
set -eu

# Пароль подставляем через psql и %L, чтобы он правильно экранировался.
# Создаём пользователя сайта без прав суперпользователя.
# Создание таблиц пока разрешаем: они создаются при запуске сайта.
psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -v ON_ERROR_STOP=1 -v app_password="$APP_DB_PASSWORD" <<'SQL'
SELECT format('CREATE ROLE cleaning_app LOGIN PASSWORD %L', :'app_password')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cleaning_app') \gexec
SELECT format('ALTER ROLE cleaning_app PASSWORD %L', :'app_password') \gexec
GRANT CONNECT ON DATABASE cleaning TO cleaning_app;
GRANT USAGE, CREATE ON SCHEMA public TO cleaning_app;
SELECT format('ALTER TABLE public.%I OWNER TO cleaning_app', tablename)
FROM pg_tables WHERE schemaname = 'public' AND tablename IN ('users', 'sessions', 'orders') \gexec
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO cleaning_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO cleaning_app;
ALTER DEFAULT PRIVILEGES FOR ROLE cleaning IN SCHEMA public
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO cleaning_app;
ALTER DEFAULT PRIVILEGES FOR ROLE cleaning IN SCHEMA public
GRANT USAGE, SELECT ON SEQUENCES TO cleaning_app;
SQL

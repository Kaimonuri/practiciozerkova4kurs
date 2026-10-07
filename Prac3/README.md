# ЧистоДома

Учебный сайт клининговой компании с регистрацией, входом, заявками и PostgreSQL.

## Запуск в Docker

Откройте PowerShell в папке `Prac3`:

```powershell
Copy-Item .env.docker.example .env.docker
```

Откройте `.env.docker` и замените оба примера паролей на разные длинные значения. Затем выполните:

```powershell
docker compose --env-file .env.docker up -d --build
docker compose --env-file .env.docker ps
```

Сайт: <http://127.0.0.1:8000>. В списке контейнеров службы `web` и `postgres` должны быть в состоянии `healthy`.

При первом запуске сайт создаёт таблицы и администратора. Логин администратора и пароль берутся из `.env.docker`. Пароль не выводится в README и не загружается в GitHub.

PostgreSQL доступен внутри сети Compose под именем `postgres`; для pgAdmin на компьютере можно использовать `127.0.0.1:5433`, базу `cleaning`, пользователя `cleaning` и пароль из `POSTGRES_PASSWORD`.

```powershell
docker compose --env-file .env.docker logs --tail=50 web
docker compose --env-file .env.docker down
```

Команда `down` останавливает контейнеры, но сохраняет базу в Docker volume. Для следующего запуска используйте тот же `.env.docker`.

## Отдельный запуск без Docker

Существующий файл `.env` и сценарий `setup_db.py` предназначены для PostgreSQL, установленного на Windows. Docker использует отдельный `.env.docker` и собственный volume, поэтому данные двух запусков не смешиваются.

## Безопасность

Сессионная cookie имеет параметры `HttpOnly` и `SameSite=Lax`; `Secure` добавляется при HTTPS. Сервер отправляет CSP и другие защитные заголовки. Локальный адрес Docker использует HTTP, поэтому для публичного размещения потребуется HTTPS перед сайтом.

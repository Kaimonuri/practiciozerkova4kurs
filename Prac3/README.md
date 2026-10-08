# ЧистоДома

Учебный сайт клининговой компании с регистрацией, входом, заявками и PostgreSQL.

## Запуск в Docker

Откройте PowerShell в папке `Prac3`:

```powershell
Copy-Item .env.docker.example .env.docker
```

Откройте `.env.docker` и замените три примера паролей на разные длинные значения. Ключ шифрования создайте в PowerShell:

```powershell
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Если пакет ещё не установлен локально, выполните `python -m pip install cryptography`. Результат вставьте в `DATA_ENCRYPTION_KEY`. Сохраните этот ключ: без него зашифрованные ФИО, адреса и телефоны нельзя прочитать. Затем выполните:

```powershell
docker compose --env-file .env.docker up -d --build
docker compose --env-file .env.docker ps
```

Сайт: <https://127.0.0.1:8443>. Адрес <http://127.0.0.1:8000> перенаправляет на HTTPS. При первом открытии браузер предупредит о локальном самоподписанном сертификате: для учебного запуска подтвердите переход. Сертификат создаётся заново при запуске контейнера; для публичного сайта нужен сертификат доверенного центра. В списке контейнеров службы `web` и `postgres` должны быть в состоянии `healthy`.

При первом запуске PostgreSQL создаёт роль `cleaning_app` с правами только для базы `cleaning`. Сайт подключается под этой ролью и создаёт таблицы и администратора. Логин администратора и пароль берутся из `.env.docker`. Секреты не загружаются в GitHub.

Если том `postgres_data` был создан предыдущей версией проекта, сначала обновите только PostgreSQL, затем выполните SQL-инициализатор внутри него и запустите сайт:

```powershell
docker compose --env-file .env.docker up -d postgres
docker compose --env-file .env.docker exec postgres sh /docker-entrypoint-initdb.d/01-roles.sh
docker compose --env-file .env.docker up -d --build web
```

Инициализатор сохраняет существующие записи и передаёт таблицы роли приложения. При запуске сайта открытые персональные поля прежней базы шифруются на месте. Перед сменой ключа сделайте резервную копию базы и сохраните прежний ключ.

PostgreSQL доступен внутри сети Compose под именем `postgres`; для pgAdmin на компьютере можно использовать `127.0.0.1:5433`, базу `cleaning`, пользователя `cleaning` и пароль из `POSTGRES_PASSWORD`.

```powershell
docker compose --env-file .env.docker logs --tail=50 web
docker compose --env-file .env.docker down
```

Команда `down` останавливает контейнеры, но сохраняет базу в Docker volume. Для следующего запуска используйте тот же `.env.docker`.

## Отдельный запуск без Docker

Существующий файл `.env` и сценарий `setup_db.py` предназначены для PostgreSQL, установленного на Windows. Docker использует отдельный `.env.docker` и собственный volume, поэтому данные двух запусков не смешиваются.

## Безопасность

Сессионная cookie имеет параметры `HttpOnly`, `SameSite=Lax` и `Secure`. Сервер отправляет CSP и другие защитные заголовки. Пароли хранятся как хеш с солью; ФИО, адреса и телефоны шифруются ключом из переменной окружения. Запросы к БД параметризованы, а роль сайта не является суперпользователем. Формы входа и регистрации в Docker доступны через HTTPS.

Контейнер сайта работает от пользователя `appuser`, с файловой системой только для чтения, отключёнными Linux capabilities и запретом повышения привилегий. Контейнеры разделены сетью Compose и собственными пространствами имён; доступ с компьютера открыт только через `127.0.0.1`. Ограничены память, CPU и число процессов.

Проверка после запуска:

```powershell
docker compose --env-file .env.docker ps
docker compose --env-file .env.docker exec web id
docker inspect (docker compose --env-file .env.docker ps -q web) --format '{{.HostConfig.Memory}} {{.HostConfig.NanoCpus}} {{.HostConfig.PidsLimit}} {{.HostConfig.ReadonlyRootfs}}'
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy:latest image --severity HIGH,CRITICAL --exit-code 0 prac3-web
```

Название контейнера может отличаться. Команда Trivy выводит найденные уязвимости образа для анализа; она не исправляет их автоматически.

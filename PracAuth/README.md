# Практическая работа по аутентификации и авторизации

**Студент:** Аньшин Сергей  
**Группа:** ИСП-406

Проект содержит рабочие примеры регистрации и семи способов аутентификации: подписанная cookie, серверная сессия, одноразовая ссылка по электронной почте, JWT access, одноразовый JWT refresh, OAuth2 Authorization Code и PASETO v4.local.

## Запуск

```powershell
Copy-Item .env.example .env
docker compose up -d
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe app.py
```

Открыть `http://127.0.0.1:8001`.

Для проверки в другом окне PowerShell выполните `.\.venv\Scripts\python.exe test_auth.py`. Значения пароля в `.env.example` предназначены только для локальной демонстрации; для собственного запуска задайте отдельный пароль одновременно в `POSTGRES_PASSWORD` и `DATABASE_URL` до создания контейнера.

Тестовый пользователь:

- логин: `demo`
- пароль: `Demo12345`
- электронная почта: `demo@example.ru`

## Реализованные методы

| Метод | Маршруты | Особенности |
|---|---|---|
| Регистрация | `POST /register` | Пароль хранится в виде стойкого хеша |
| Подписанная cookie | `POST /auth/cookie/login`, `GET /auth/cookie/profile` | `HttpOnly`, `SameSite=Lax`, подпись и срок действия |
| Серверная сессия | `POST /auth/session/login`, `GET /auth/session/profile` | В cookie находится случайный идентификатор, сессия хранится в PostgreSQL |
| Беспарольный вход | `POST /auth/passwordless/request`, `GET /auth/passwordless/verify` | Ссылка действует 10 минут и используется один раз; при заданном `SMTP_HOST` отправляется письмом |
| JWT access | `POST /auth/jwt/login`, `GET /auth/jwt/profile` | Access-токен действует 15 минут и допускает повторные запросы |
| JWT refresh | `POST /auth/jwt/refresh` | Каждый refresh-токен используется один раз и заменяется новым |
| OAuth2 | `GET /oauth/start` | Учебная локальная единая точка входа с проверкой пароля, `state` и одноразовым code |
| PASETO | `POST /auth/paseto/login`, `GET /auth/paseto/profile` | `v4.local`, содержимое токена зашифровано и аутентифицировано |

## Проверка

```powershell
python test_auth.py
```

Сценарий регистрирует временного пользователя, проверяет все способы входа и подтверждает, что magic link, refresh-токен и OAuth-код нельзя использовать повторно.

Без настроенного SMTP ссылка для беспарольного входа возвращается в поле `demo_magic_link` для демонстрации. Для отправки реального письма задайте `SMTP_HOST`, `SMTP_PORT`, `SMTP_FROM`, `SMTP_USER`, `SMTP_PASSWORD` в `.env` и передайте их приложению при запуске.

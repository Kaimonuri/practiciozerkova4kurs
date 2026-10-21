# Практические работы
### Безопасность веб-приложений · 4 курс

Учебные проекты и отчёты по разработке и защите веб-приложений.

**Аньшин Сергей · ИСП-406**

![Python](https://img.shields.io/badge/Python-3776AB?style=flat-square&logo=python&logoColor=white)
![JavaScript](https://img.shields.io/badge/JavaScript-F7DF1E?style=flat-square&logo=javascript&logoColor=222)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-4169E1?style=flat-square&logo=postgresql&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-2496ED?style=flat-square&logo=docker&logoColor=white)

[Итоговый сайт](#итоговый-сайт) · [Практические проекты](#практические-проекты) · [Отчёты](#отчёты) · [Запуск](#запуск) · [Код защиты](#где-посмотреть-защиту)

---

## Итоговый сайт

### ЧистоДома

Сайт клининговой компании: выбор услуги, регистрация, вход, оформление заявки и личный кабинет. Администратор просматривает заявки и меняет их статусы.

**[Открыть итоговую практику →](PracFinal)** · [Инструкция запуска](PracFinal/README.md)

| Возможности | Реализация |
| :--- | :--- |
| Интерфейс | HTML, CSS, JavaScript; адаптивные формы и простой дизайн |
| Сервер | Python и API для пользователей и заявок |
| Данные | PostgreSQL: `users`, `sessions`, `orders` |
| Авторизация | Серверные сессии и случайные токены |
| Защита данных | PBKDF2 с солью для паролей; Fernet для ФИО, адресов и телефонов |
| Запуск | Docker Compose, локальный HTTPS |
| Пояснения | Подробные комментарии к реализации защиты |

> Итоговая версия находится в **PracFinal**. Папка **Prac3** сохраняет предыдущую версию практики.

## Практические проекты

| Раздел | Содержание | Материалы |
| :--- | :--- | :--- |
| **Итоговая практика** | ЧистоДома с обновлённым интерфейсом и комментариями по защите | [Исходники](PracFinal) · [Запуск](PracFinal/README.md) |
| **CSP и cookie** | Предыдущая версия сайта, защитные заголовки и сессии | [Исходники](Prac3) · [Инструкция](Prac3/README.md) |
| **Методы HTTP** | Проверка методов и запрет неиспользуемых операций | [Описание](Prac3/PROTOCOLS.md) · [Сканер](Prac3/method_scanner.py) |
| **CORS** | Три приложения для проверки межсайтового доступа | [Исходники](PracCORS/cors-practice) · [Инструкция](PracCORS/cors-practice/README.md) |
| **Аутентификация** | Сравнение способов входа и авторизации | [Исходники](PracAuth) · [Инструкция](PracAuth/README.md) |

## Отчёты

Отчёты сгруппированы по темам. Номера практик сохранены из существующего перечня репозитория.

### Исследование уязвимостей

| № | Тема | Открыть |
| :---: | :--- | :---: |
| 3.1 | Security Misconfiguration и IDOR | [PDF](Отчёты/Отчет_практика_Misconfiguration_IDOR_расширенный.pdf) |
| 3.2 | Command Injection и PHP Injection | [PDF](Отчёты/Отчёт_CMD_PHP_Injection_исправленный.pdf) |
| 3.3 | XML External Entity — XXE | [PDF](Отчёты/Отчет_XXE_Аньшин_Сергей_ИСП_406_исправленный.pdf) |
| 3.4 | Клиентские атаки XSS и CSRF | [PDF](Отчёты/Отчёт_XSS_CSRF_исправленный.pdf) |
| 3.5 | Server-Side Template Injection — SSTI | [PDF](Отчёты/Отчёт_по_практике_SSTI_Аньшин_Сергей.pdf) |

### Разработка и настройка защиты

| № | Тема | Открыть |
| :---: | :--- | :---: |
| 4 | CSP, безопасность cookie и прототип ЧистоДома | [PDF](Отчёты/Отчет_Практическая_работа_3_Аньшин_Сергей.pdf) |
| 5 | Настройка CORS в трёх приложениях | [PDF](<Отчёты/Отчёт CORS Аньшин Сергей 406.pdf>) |
| 6 | Техническое задание ЧистоДома | [PDF](Отчёты/Техническое_задание_ЧистоДома_Аньшин_Сергей.pdf) |
| 7 | Исследование и ограничение методов HTTP | [PDF](Отчёты/Отчет_Методы_HTTP_Аньшин_Сергей.pdf) |
| 8 | Аутентификация и авторизация | [PDF](Отчёты/Отчет_Практическая_работа_8_Аутентификация_Аньшин_Сергей.pdf) |

### Тестирование безопасности

| № | Тема | Открыть |
| :---: | :--- | :---: |
| 9 | Проверки ЧистоДома с Trivy, Nikto, OWASP ZAP и Nmap | [PDF](Отчёты/Отчёт_Тестирование_безопасности_Аньшин_Сергей.pdf) |

**[Все отчёты →](Отчёты)**

## Запуск

Для итогового сайта понадобятся Git, Docker и Docker Compose.

```bash
git clone https://github.com/Kaimonuri/practiciozerkova4kurs.git
cd practiciozerkova4kurs/PracFinal
cp .env.docker.example .env.docker
```

Заполните `.env.docker`: задайте разные пароли и ключ шифрования. Команда генерации ключа приведена в [инструкции](PracFinal/README.md#запуск).

```bash
docker compose --env-file .env.docker up -d --build
docker compose --env-file .env.docker ps
```

| Адрес | Назначение |
| :--- | :--- |
| **https://127.0.0.1:8443/** | Сайт ЧистоДома |
| http://127.0.0.1:8000/ | Перенаправление на HTTPS |
| `127.0.0.1:5433` | PostgreSQL для терминала и редактора; не веб-страница |

В Docker Desktop для Linux при необходимости используйте `docker --context desktop-linux`. Команды с `sudo` могут обращаться к другому Docker Engine.

> Сертификат локальный и самоподписанный. Prac3 и PracFinal используют одинаковые порты: запускайте их по очереди. У каждой папки собственный том базы данных.

<details>
<summary><strong>Просмотр таблиц через терминал</strong></summary>

Из папки `PracFinal`:

```bash
docker compose --env-file .env.docker exec postgres psql -U cleaning -d cleaning
```

```sql
\dt
SELECT id, login, is_admin FROM users;
SELECT * FROM orders;
\q
```

</details>

<details>
<summary><strong>Логи и остановка</strong></summary>

```bash
docker compose --env-file .env.docker logs --tail=50 web
docker compose --env-file .env.docker down
```

Команда `down` сохраняет том базы. Ключ `-v` удалит том и данные — не добавляйте его, если базу нужно сохранить.

</details>

Другие проекты: [CORS](PracCORS/cors-practice/README.md) · [Аутентификация](PracAuth/README.md).

## Где посмотреть защиту

| Что изучить | Файл | Функция или элемент |
| :--- | :--- | :--- |
| Хеширование паролей с солью | [server.py](PracFinal/server.py) | `password_hash`, `password_valid` |
| Шифрование персональных данных | [server.py](PracFinal/server.py) | `encrypt`, `decrypt` |
| Cookie и проверка сессии | [server.py](PracFinal/server.py) | `cookie_value`, `start_session`, `user` |
| Защитные HTTP-заголовки | [server.py](PracFinal/server.py) | `headers_common` |
| Проверка данных и прав | [server.py](PracFinal/server.py) | `register`, `create_order`, `set_status` |
| Проверка источника запроса | [server.py](PracFinal/server.py) | `do_POST` |
| Безопасный вывод и уведомление cookie | [app.js](PracFinal/app.js) | `textContent`, `initCookieNotice` |
| Проверки полей в браузере | [index.html](PracFinal/index.html) | `required`, `pattern`, ограничения длины |
| Ограничения контейнеров | [compose.yaml](PracFinal/compose.yaml) · [Dockerfile](PracFinal/Dockerfile) | Локальные порты, ресурсы и привилегии |
| Права роли PostgreSQL | [01-roles.sh](PracFinal/db-init/01-roles.sh) | `cleaning_app` и выдача прав |

## Структура репозитория

```text
practiciozerkova4kurs/
├── PracFinal/           Итоговый сайт ЧистоДома
├── Prac3/               Предыдущая версия и работа с HTTP-методами
├── PracCORS/
│   └── cors-practice/   Практика CORS
├── PracAuth/            Аутентификация и авторизация
├── Отчёты/              PDF по практическим работам
└── README.md            Навигация по материалам
```

## Границы учебного проекта

В итоговом сайте реализованы основные меры защиты, но это не подтверждение готовности к публичной эксплуатации. Ограничение попыток входа, двухфакторная аутентификация и автоматическое резервное копирование пока не добавлены. Прохождение официальных HTML/CSS-валидаторов отдельно не подтверждено.

Реальные пароли, ключи и локальные данные базы в репозиторий не включаются. Для настройки используются только файлы-примеры.

---

**Автор:** Аньшин Сергей · **Группа:** ИСП-406 · **Год:** 2026

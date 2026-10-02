# Практика по методам HTTP

## Файлы

- `http_methods_app.py` — отправляет GET, POST, PUT и DELETE и показывает ответы.
- `method_scanner.py` — проверяет GET, POST, HEAD, PUT, PATCH, DELETE, OPTIONS, TRACE и CONNECT.
- `server.py` — разрешает методы GET и POST. Остальные методы возвращают `405 Method Not Allowed` и заголовок `Allow: GET, POST`.

## Запуск проверки

Сначала запустите сайт:

```powershell
python server.py
```

В другом терминале выполните:

```powershell
python http_methods_app.py
python method_scanner.py
```

Ожидаемый результат: GET возвращает `200`, POST обрабатывается сервером, а HEAD, PUT, PATCH, DELETE, OPTIONS, TRACE и CONNECT возвращают `405`. Код `404` для POST на `/api/method-check` означает, что метод разрешён, но тестовый маршрут не существует.

Для изменения адреса сканера используйте параметры:

```powershell
python method_scanner.py --host 127.0.0.1 --port 8000
```

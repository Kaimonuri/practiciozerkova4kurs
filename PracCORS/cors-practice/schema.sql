CREATE TABLE IF NOT EXISTS primer1 (id INTEGER PRIMARY KEY, name TEXT NOT NULL, description TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS primer2 (id INTEGER PRIMARY KEY, name TEXT NOT NULL, description TEXT NOT NULL);
INSERT OR IGNORE INTO primer1 VALUES
 (1, 'HTML', 'Структура веб-страницы'),
 (2, 'CSS', 'Оформление веб-страницы'),
 (3, 'JavaScript', 'Запросы из браузера');
INSERT OR IGNORE INTO primer2 VALUES
 (1, 'CORS', 'Разрешения для чтения ответов из другого origin'),
 (2, 'CSP', 'Ограничение источников ресурсов страницы'),
 (3, 'SQLite', 'Локальная база данных практической работы');

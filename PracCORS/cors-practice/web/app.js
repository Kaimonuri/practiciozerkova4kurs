'use strict';
const app = Number(location.port) - 8080;
const el = id => document.getElementById(id);
el('title').textContent = `Приложение ${app} · localhost:${location.port}`;
fetch('/api/status').then(r => r.json()).then(s => {
  el('status').textContent = `CORS на этом сервере: ${s.cors ? 'включён' : 'выключен'}. Origin страницы: ${location.origin}`;
});
async function request(url, preflight = false, opaque = false) {
  el('result').textContent = 'Запрос выполняется…'; el('data').textContent = '';
  try {
    const response = await fetch(url, {credentials: 'omit', mode: opaque ? 'no-cors' : 'cors',
      headers: preflight ? {'X-Lab-Demo': 'preflight'} : {}});
    if (response.type === 'opaque') {
      el('result').textContent = 'OPAQUE: запрос выполнен, но JavaScript не может прочитать ответ. status = 0.';
      return;
    }
    const data = await response.json();
    el('result').textContent = `${response.ok ? 'УСПЕХ' : 'HTTP ОШИБКА'}: HTTP ${response.status} · ${url}`;
    el('data').textContent = JSON.stringify(data, null, 2);
  } catch (error) {
    el('result').textContent = `ОШИБКА: браузер не предоставил ответ (${error.message}). Причину смотрите в Console / Network.`;
  }
}
function button(label, url, preflight = false, opaque = false) {
  const b = document.createElement('button'); b.textContent = label;
  b.addEventListener('click', () => request(url, preflight, opaque)); el('actions').append(b);
}
if (app === 1 || app === 2) {
  const own = `http://localhost:8083/api/primer${app}`;
  el('intro').textContent = `Приложение ${app} запрашивает таблицу primer${app} напрямую у приложения 3. До CORS чтение блокируется, после — разрешено.`;
  button('1. Получить свою таблицу (GET)', own);
  button('2. Своя таблица + preflight', own, true);
  button('3. Чужая таблица (должна блокироваться)', `http://localhost:8083/api/primer${3-app}`);
  button('4. Проверить no-cors', own, false, true);
  if (app === 2) button('5. Запрос к приложению 1', 'http://localhost:8081/api/info');
} else {
  el('intro').textContent = 'Это сервер базы данных. Ниже проверка собственных ресурсов без пересечения origin: она работает на обоих этапах.';
  button('Проверить primer1 на сервере', '/api/primer1');
  button('Проверить primer2 на сервере', '/api/primer2');
}

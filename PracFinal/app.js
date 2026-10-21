// Интерфейс ЧистоДома: формы, поиск, cookie и показ заявок.
// Защиту доступа проверяет сервер, а здесь показываем результат пользователю.
// Короткая запись для поиска элемента на странице.
const $ = selector => document.querySelector(selector);

// Плашка видна сразу. Скрываем её только если пользователь уже нажимал «Понятно».
// В приватном режиме хранилище отдельное. Если оно недоступно, плашка всё равно работает.
const cookieNoticeKey = 'cleaningCookieNotice:v1';
const cookieBanner = $('#cookie-banner');

// УВЕДОМЛЕНИЕ О COOKIE
// При первом посещении отметки seen нет, поэтому показываем плашку.
// После кнопки «Понятно» сохраняем только факт закрытия в localStorage.
// В новом приватном сеансе отдельное хранилище, поэтому уведомление появляется снова.
// Приватные окна одного сеанса могут делить хранилище; для нового сеанса закрывают все такие окна.
// Если браузер запретил localStorage, ошибка перехватывается и плашка остаётся видимой.
// Это уведомление, а не сессия входа. Сессионную HttpOnly-cookie создаёт сервер после входа.
function initCookieNotice() {
  try {
    cookieBanner.hidden = localStorage.getItem(cookieNoticeKey) === 'seen';
  } catch {
    // Браузер может запретить хранилище, поэтому оставляем уведомление видимым.
    cookieBanner.hidden = false;
  }
}

initCookieNotice();
$('#cookie-ok').addEventListener('click', () => {
  try {
    // Сохраняем только закрытие уведомления, без паролей и токена сессии.
    localStorage.setItem(cookieNoticeKey, 'seen');
  } catch {
    // Если сохранить отметку нельзя, при следующем открытии плашка появится снова.
  }
  cookieBanner.hidden = true;
});

const dialog = $('#search-dialog');
$('.search-open').addEventListener('click', () => {
  dialog.showModal();
  $('#search-input').focus();
});
const searchPages = [
  { words: 'поддерживающая уборка регулярно пыль полы', title: 'Поддерживающая уборка', link: '#services' },
  { words: 'генеральная уборка тщательная', title: 'Генеральная уборка', link: '#services' },
  { words: 'после ремонта строительная пыль', title: 'Уборка после ремонта', link: '#services' },
  { words: 'заявка заказ дата адрес телефон', title: 'Оставить заявку', link: '#request' },
  { words: 'регистрация личный кабинет', title: 'Регистрация', link: '#account' },
  { words: 'cookie согласие персональные данные', title: 'Данные и cookie', link: '#consent' }
];
$('#search-input').addEventListener('input', (event) => {
  const query = event.target.value.trim().toLocaleLowerCase('ru');
  const result = $('#search-result');
  result.replaceChildren();
  if (!query) {
    result.textContent = 'Введите слово для поиска по разделам сайта.';
    return;
  }
  const matches = searchPages.filter(page => page.words.includes(query));
  if (!matches.length) {
    result.textContent = 'Ничего не найдено.';
    return;
  }
  // Вставляем результат как текст, чтобы браузер не выполнил HTML из строки.
  matches.forEach(page => {
    const a = document.createElement('a');
    a.href = page.link;
    a.textContent = page.title;
    a.className = 'search-result';
    a.addEventListener('click', () => dialog.close());
    result.append(a);
  });
});


document.querySelectorAll('[data-service]').forEach(link => {
  link.addEventListener('click', () => {
    $('#service').value = link.dataset.service;
  });
});

const dateInput = document.querySelector('[name="date"]');
dateInput.min = new Date().toISOString().slice(0, 10);

// Запросы отправляем на свой сайт. Cookie браузер добавит сам.
// Прочитать сессионную cookie из JavaScript нельзя, у неё стоит HttpOnly.
// ОБМЕН С СЕРВЕРОМ
// Данные отправляем JSON-запросом на относительный адрес нашего сайта.
// credentials same-origin разрешает браузеру отправить cookie своему серверу.
// Токен не читаем и не добавляем вручную: cookie имеет HttpOnly.
// При открытии сайта по HTTPS тело запроса шифруется TLS.
async function api(path, method = 'GET', body = null) {
  const response = await fetch(path, {
    method,
    headers: { 'Content-Type': 'application/json' },
    credentials: 'same-origin',
    body: body === null ? null : JSON.stringify(body)
  });
  const result = await response.json();
  if (!response.ok) {
    throw new Error(result.error || 'Ошибка сервера');
  }
  return result;
}

let currentUser = null;

// Узнаём у сервера, кто вошёл, и обновляем личный кабинет.
// ПРОВЕРКА ВХОДА В ИНТЕРФЕЙСЕ
// Спрашиваем /api/me, кто сейчас вошёл. Ответ сервера определяет вид личного кабинета.
// currentUser не является доказательством прав: сервер заново проверяет сессию на защищённых маршрутах.
async function updateAccount() {
  const result = await api('/api/me');
  currentUser = result.user;
  $('#dashboard').hidden = !currentUser;
  $('#login-section').hidden = Boolean(currentUser);
  $('#register-form').hidden = Boolean(currentUser);
  if (currentUser) {
    $('#welcome').textContent = `${currentUser.firstname}, ваши заявки`;
    await loadOrders();
  }
}

// Загружаем доступные пользователю заявки и создаём карточки.
// ЗАЯВКИ И ЗАЩИТА ОТ XSS
// Сервер отдаёт только те заявки, которые пользователю разрешено видеть.
// Значения вставляем через textContent, а не innerHTML.
// Например, строка с тегом script в адресе будет показана как текст, а не выполнена.
// CSP на сервере добавляет ещё один слой ограничений, но не заменяет безопасный вывод.
// Кнопки администратора показываем по is_admin; реальные права проверяет set_status на сервере.
async function loadOrders() {
  const result = await api('/api/orders');
  const list = $('#orders-list');
  list.replaceChildren();
  $('#orders-message').textContent = result.orders.length
    ? ''
    : 'Заявок пока нет.';

  // Данные заявок выводим через textContent, чтобы введённые теги остались обычным текстом.
  result.orders.forEach(order => {
    const card = document.createElement('article');
    card.className = 'order-card';
    const heading = document.createElement('h4');
    heading.textContent = `Заявка №${order.id}: ${order.service}`;
    const details = document.createElement('p');
    details.textContent = `${order.date} · ${order.address} · ${order.phone}`;
    const status = document.createElement('p');
    status.textContent = `Статус: ${order.status}`;
    card.append(heading, details, status);

    // Здесь только показываем кнопку. Право менять статус отдельно проверяет сервер.
    if (currentUser.is_admin) {
      const owner = document.createElement('p');
      owner.textContent = `Пользователь: ${order.login}`;
      const select = document.createElement('select');
      ['Новая', 'В работе', 'Выполнена', 'Отменена'].forEach(value => {
        const option = new Option(value, value);
        select.add(option);
      });
      select.value = order.status;
      select.addEventListener('change', async () => {
        try {
          await api('/api/orders/status', 'POST', {
            id: order.id,
            status: select.value
          });
          await loadOrders();
        } catch (error) {
          alert(error.message);
        }
      });
      card.append(owner, select);
    }
    list.append(card);
  });
}

// required у чекбокса останавливает обычную отправку без согласия.
// На сервере consent дополнительно проверяется, браузерной проверке не доверяем.
$('#register-form').addEventListener('submit', async event => {
  event.preventDefault();
  const form = event.currentTarget;
  const data = Object.fromEntries(new FormData(form));
  data.consent = form.elements.consent.checked;
  const message = $('#register-message');
  try {
    await api('/api/register', 'POST', data);
    message.textContent = 'Регистрация прошла успешно.';
    form.reset();
    await updateAccount();
  } catch (error) {
    message.textContent = error.message;
  }
});

// Ошибку входа берём из ответа сервера и выводим рядом с формой.
$('#login-form').addEventListener('submit', async event => {
  event.preventDefault();
  const form = event.currentTarget;
  const message = $('#login-message');
  try {
    await api('/api/login', 'POST', Object.fromEntries(new FormData(form)));
    message.textContent = '';
    form.reset();
    await updateAccount();
  } catch (error) {
    message.textContent = error.message;
  }
});

// Просим сервер завершить сессию, затем обновляем страницу кабинета.
$('#logout').addEventListener('click', async () => {
  await api('/api/logout', 'POST', {});
  await updateAccount();
});

// Собираем поля заявки. Окончательно проверяет их сервер.
$('#request-form').addEventListener('submit', async event => {
  event.preventDefault();
  const message = $('#request-message');
  try {
    const data = Object.fromEntries(new FormData(event.currentTarget));
    const result = await api('/api/orders', 'POST', data);
    message.textContent = `Заявка №${result.id} сохранена.`;
    event.currentTarget.reset();
    await loadOrders();
  } catch (error) {
    message.textContent = error.message;
  }
});

updateAccount().catch(() => {
  $('#login-message').textContent = 'Не удалось подключиться к серверу.';
});

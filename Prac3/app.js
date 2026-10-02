const $ = selector => document.querySelector(selector);

if (!localStorage.getItem('cookieNoticeSeen')) {
  $('#cookie-banner').hidden = false;
}
$('#cookie-ok').addEventListener('click', () => {
  localStorage.setItem('cookieNoticeSeen', 'yes');
  $('#cookie-banner').hidden = true;
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
  matches.forEach(page => {
    const a = document.createElement('a');
    a.href = page.link;
    a.textContent = page.title;
    a.style.display = 'block';
    a.style.margin = '10px 0';
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

async function loadOrders() {
  const result = await api('/api/orders');
  const list = $('#orders-list');
  list.replaceChildren();
  $('#orders-message').textContent = result.orders.length
    ? ''
    : 'Заявок пока нет.';

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

$('#logout').addEventListener('click', async () => {
  await api('/api/logout', 'POST', {});
  await updateAccount();
});

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

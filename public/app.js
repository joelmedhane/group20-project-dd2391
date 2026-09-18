const statusBox = document.getElementById('status');
const authSection = document.getElementById('auth');
const appSection = document.getElementById('app');
const currentUser = document.getElementById('currentUser');

function showStatus(value) {
  statusBox.textContent = typeof value === 'string' ? value : JSON.stringify(value, null, 2);
}

async function api(url, options = {}) {
  const response = await fetch(url, {
    headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
    ...options
  });
  const data = await response.json();
  if (!response.ok) throw data;
  return data;
}

async function updateSession() {
  const me = await api('/api/me');
  if (me.loggedIn) {
    authSection.classList.add('hidden');
    appSection.classList.remove('hidden');
    currentUser.textContent = me.user.username;
    loadFriends();
  } else {
    authSection.classList.remove('hidden');
    appSection.classList.add('hidden');
  }
}

document.getElementById('registerForm').addEventListener('submit', async (event) => {
  event.preventDefault();
  try {
    const data = await api('/api/register', {
      method: 'POST',
      body: JSON.stringify({
        username: document.getElementById('registerUsername').value,
        password: document.getElementById('registerPassword').value
      })
    });
    showStatus(data);
  } catch (err) {
    showStatus(err);
  }
});

document.getElementById('loginForm').addEventListener('submit', async (event) => {
  event.preventDefault();
  try {
    const data = await api('/api/login', {
      method: 'POST',
      body: JSON.stringify({
        username: document.getElementById('loginUsername').value,
        password: document.getElementById('loginPassword').value
      })
    });
    showStatus(data);
    await updateSession();
  } catch (err) {
    showStatus(err);
  }
});

document.getElementById('logoutButton').addEventListener('click', async () => {
  showStatus(await api('/api/logout', { method: 'POST' }));
  await updateSession();
});

document.getElementById('searchForm').addEventListener('submit', async (event) => {
  event.preventDefault();
  const query = document.getElementById('searchInput').value;
  const results = document.getElementById('searchResults');
  results.innerHTML = '';

  try {
    const users = await api('/api/users/search?q=' + encodeURIComponent(query));
    for (const user of users) {
      const li = document.createElement('li');
      li.textContent = `${user.username} (id ${user.id}) `;

      const button = document.createElement('button');
      button.textContent = 'Add friend';
      button.addEventListener('click', async () => {
        try {
          showStatus(await api('/api/friends/' + user.id, { method: 'POST' }));
          loadFriends();
        } catch (err) {
          showStatus(err);
        }
      });

      li.appendChild(button);
      results.appendChild(li);
    }
  } catch (err) {
    showStatus(err);
  }
});

async function loadFriends() {
  const list = document.getElementById('friends');
  list.innerHTML = '';
  try {
    const friends = await api('/api/friends');
    for (const friend of friends) {
      const li = document.createElement('li');
      li.textContent = `${friend.username} (id ${friend.id})`;
      list.appendChild(li);
    }
  } catch (err) {
    showStatus(err);
  }
}

document.getElementById('refreshFriends').addEventListener('click', loadFriends);
updateSession().catch(showStatus);

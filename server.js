const express = require('express');
const session = require('express-session');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const app = express();
const PORT = 3000;
const db = new sqlite3.Database(path.join(__dirname, 'app.db'));

app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(
  session({
    secret: 'demo-only-secret',
    resave: false,
    saveUninitialized: false
  })
);
app.use(express.static(path.join(__dirname, 'public')));

// Local coursework demo only.
// The queries marked VULNERABLE intentionally concatenate user input.
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS friends (
    user_id INTEGER,
    friend_id INTEGER,
    UNIQUE(user_id, friend_id)
  )`);

  db.run("INSERT OR IGNORE INTO users (username, password) VALUES ('alice', 'alice123')");
  db.run("INSERT OR IGNORE INTO users (username, password) VALUES ('bob', 'bob123')");
  db.run("INSERT OR IGNORE INTO users (username, password) VALUES ('charlie', 'charlie123')");
});

function requireLogin(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Not logged in' });
  }
  next();
}

app.post('/api/register', (req, res) => {
  const username = req.body.username || '';
  const password = req.body.password || '';

  // INTENTIONALLY VULNERABLE TO SQL INJECTION.
  const sql = `INSERT INTO users (username, password) VALUES ('${username}', '${password}')`;

  db.run(sql, function (err) {
    if (err) return res.status(400).json({ error: err.message, sql });
    res.json({ message: 'Account created', userId: this.lastID });
  });
});

app.post('/api/login', (req, res) => {
  const username = req.body.username || '';
  const password = req.body.password || '';

  // INTENTIONALLY VULNERABLE TO SQL INJECTION.
  const sql = `SELECT id, username FROM users WHERE username = '${username}' AND password = '${password}'`;

  db.get(sql, (err, row) => {
    if (err) return res.status(400).json({ error: err.message, sql });
    if (!row) return res.status(401).json({ error: 'Invalid username or password' });

    req.session.userId = row.id;
    req.session.username = row.username;
    res.json({ message: 'Logged in', user: row });
  });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => res.json({ message: 'Logged out' }));
});

app.get('/api/me', (req, res) => {
  if (!req.session.userId) return res.json({ loggedIn: false });
  res.json({
    loggedIn: true,
    user: { id: req.session.userId, username: req.session.username }
  });
});

app.get('/api/users/search', requireLogin, (req, res) => {
  const q = req.query.q || '';

  // INTENTIONALLY VULNERABLE TO SQL INJECTION.
  const sql = `SELECT id, username FROM users WHERE username LIKE '%${q}%' AND id != ${req.session.userId}`;

  db.all(sql, (err, rows) => {
    if (err) return res.status(400).json({ error: err.message, sql });
    res.json(rows);
  });
});

app.post('/api/friends/:friendId', requireLogin, (req, res) => {
  const friendId = Number(req.params.friendId);
  if (!Number.isInteger(friendId)) {
    return res.status(400).json({ error: 'Invalid friend id' });
  }

  db.get('SELECT id, username FROM users WHERE id = ?', [friendId], (err, user) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (friendId === req.session.userId) return res.status(400).json({ error: 'Cannot add yourself' });

    db.run(
      'INSERT OR IGNORE INTO friends (user_id, friend_id) VALUES (?, ?)',
      [req.session.userId, friendId],
      function (insertErr) {
        if (insertErr) return res.status(500).json({ error: insertErr.message });
        res.json({ message: `Added ${user.username} as friend` });
      }
    );
  });
});

app.get('/api/friends', requireLogin, (req, res) => {
  db.all(
    `SELECT users.id, users.username
     FROM friends
     JOIN users ON users.id = friends.friend_id
     WHERE friends.user_id = ?
     ORDER BY users.username`,
    [req.session.userId],
    (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(rows);
    }
  );
});



app.listen(PORT, '0.0.0.0', () => {
  console.log(`Vulnerable SQLi demo running at http://0.0.0.0:${PORT}`);
  console.log('For local coursework/lab use only. Do not expose this app to the Internet.');
});

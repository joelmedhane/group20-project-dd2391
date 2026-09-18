# Vulnerable SQLi Demo

A deliberately insecure local Node.js/Express/SQLite application for coursework involving SQL-injection filtering/firewall/WAF experiments.

## Important

This application is **intentionally vulnerable**. It binds only to `127.0.0.1` by default. Do not expose it to the Internet or use it with real credentials/data.

## Features

- Create account
- Log in / log out
- Search users
- Add friends
- View friends
- Local SQLite database (`app.db`)
- Deliberate SQL injection vulnerabilities in:
  - account creation
  - login
  - user search

The project uses the `sqlite3` npm package, **not** `better-sqlite3`.

## Run

```bash
npm install
npm start
```

Then open:

```text
http://127.0.0.1:3000
```

The database file is created automatically on first run.

## Reset database

Stop the server and delete:

```bash
rm app.db
```

Then run `npm start` again.

## Demo accounts

- `alice` / `alice123`
- `bob` / `bob123`
- `charlie` / `charlie123`

## Where the deliberate vulnerabilities are

See `server.js` and search for:

```text
INTENTIONALLY VULNERABLE TO SQL INJECTION
```

The vulnerable routes construct SQL statements by directly concatenating user-controlled strings. The friend-related routes use parameterized queries so the project has a simple contrast between unsafe and safer SQL handling.

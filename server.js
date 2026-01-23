// server.js
// Simple Express backend with SQLite to manage posts, news, visits and an admin user.
//
// Note: For production secure the session secret and admin password via ENV vars,
// run behind HTTPS, rate-limit login attempts, and harden DB/inputs.

const express = require('express');
const path = require('path');
const bodyParser = require('body-parser');
const session = require('express-session');
const bcrypt = require('bcrypt');
const Database = require('better-sqlite3');
const helmet = require('helmet');
const morgan = require('morgan');

const PORT = process.env.PORT || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET || 'change-this-secret';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'adminpass'; // change in prod

const app = express();

// Middlewares
app.use(helmet());
app.use(morgan('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false } // set true under HTTPS
}));

// Static files
app.use('/public', express.static(path.join(__dirname, 'public')));
app.use('/', express.static(path.join(__dirname, '/')));

// Initialize DB
const db = new Database(path.join(__dirname, 'edward.db'));

// Create tables if not exist
db.exec(`
CREATE TABLE IF NOT EXISTS admin (
  id INTEGER PRIMARY KEY,
  username TEXT UNIQUE,
  password_hash TEXT
);
CREATE TABLE IF NOT EXISTS posts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT,
  content TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS news (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  text TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS visits (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  path TEXT,
  ua TEXT,
  ip TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
`);

// Ensure admin exists (first-run)
const adminRow = db.prepare('SELECT * FROM admin WHERE username = ?').get('admin');
(async () => {
  if (!adminRow) {
    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash(ADMIN_PASSWORD, salt);
    db.prepare('INSERT INTO admin (username, password_hash) VALUES (?, ?)').run('admin', hash);
    console.log('Default admin user created: username=admin (change ADMIN_PASSWORD env in production!)');
  }
})();

// Helper: auth middleware
function requireAuth(req, res, next) {
  if (req.session && req.session.admin) return next();
  return res.status(401).json({ error: 'Unauthorized' });
}

// API: record visit (clients call this)
app.post('/api/visit', (req, res) => {
  const pathVisited = req.body.path || req.headers.referer || '/';
  const ua = req.get('User-Agent') || '';
  const ip = req.ip || req.connection.remoteAddress || '';
  db.prepare('INSERT INTO visits (path, ua, ip) VALUES (?, ?, ?)').run(pathVisited, ua, ip);
  res.json({ ok: true });
});

// API: public endpoints
app.get('/api/posts', (req, res) => {
  const rows = db.prepare('SELECT id, title, content, created_at, updated_at FROM posts ORDER BY created_at DESC LIMIT 10').all();
  res.json(rows);
});
app.get('/api/news', (req, res) => {
  const rows = db.prepare('SELECT id, text, created_at FROM news ORDER BY created_at DESC LIMIT 10').all();
  res.json(rows);
});

// Admin auth
app.post('/admin/login', async (req, res) => {
  const { username, password } = req.body;
  const row = db.prepare('SELECT * FROM admin WHERE username = ?').get(username);
  if (!row) return res.status(401).json({ error: 'Invalid credentials' });
  const ok = await bcrypt.compare(password, row.password_hash);
  if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
  req.session.admin = { username: row.username };
  res.json({ ok: true });
});
app.post('/admin/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

// Admin API (protected)
app.get('/admin/stats', requireAuth, (req, res) => {
  const visits = db.prepare('SELECT COUNT(*) AS total FROM visits').get().total;
  const recent = db.prepare('SELECT path, ip, ua, created_at FROM visits ORDER BY created_at DESC LIMIT 20').all();
  res.json({ visits, recent });
});

// Posts CRUD
app.get('/admin/posts', requireAuth, (req, res) => {
  const rows = db.prepare('SELECT * FROM posts ORDER BY created_at DESC').all();
  res.json(rows);
});
app.post('/admin/posts', requireAuth, (req, res) => {
  const { title, content } = req.body;
  const info = db.prepare('INSERT INTO posts (title, content) VALUES (?, ?)').run(title, content);
  res.json({ id: info.lastInsertRowid });
});
app.put('/admin/posts/:id', requireAuth, (req, res) => {
  const { title, content } = req.body;
  const id = Number(req.params.id);
  db.prepare('UPDATE posts SET title = ?, content = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(title, content, id);
  res.json({ ok: true });
});
app.delete('/admin/posts/:id', requireAuth, (req, res) => {
  const id = Number(req.params.id);
  db.prepare('DELETE FROM posts WHERE id = ?').run(id);
  res.json({ ok: true });
});

// News CRUD
app.get('/admin/news', requireAuth, (req, res) => {
  const rows = db.prepare('SELECT * FROM news ORDER BY created_at DESC').all();
  res.json(rows);
});
app.post('/admin/news', requireAuth, (req, res) => {
  const { text } = req.body;
  const info = db.prepare('INSERT INTO news (text) VALUES (?)').run(text);
  res.json({ id: info.lastInsertRowid });
});
app.put('/admin/news/:id', requireAuth, (req, res) => {
  const { text } = req.body;
  const id = Number(req.params.id);
  db.prepare('UPDATE news SET text = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(text, id);
  res.json({ ok: true });
});
app.delete('/admin/news/:id', requireAuth, (req, res) => {
  const id = Number(req.params.id);
  db.prepare('DELETE FROM news WHERE id = ?').run(id);
  res.json({ ok: true });
});

// Serve admin page (simple)
app.get('/admin.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'admin.html'));
});

// Fallback
app.use((req, res) => {
  res.status(404).send('Not found');
});

// Start
app.listen(PORT, () => {
  console.log(`Server listening on http://localhost:${PORT}`);
});

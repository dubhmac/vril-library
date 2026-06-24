require('dotenv').config();
const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
const db = new Database('database.sqlite');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE,
    password TEXT,
    role TEXT DEFAULT 'admin'
  );
  CREATE TABLE IF NOT EXISTS books (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT,
    cover TEXT,
    pdf TEXT
  );
`);

const adminEmail = process.env.ADMIN_EMAIL || 'admin@vril.world';
const adminPassword = process.env.ADMIN_PASSWORD || 'admin123';
const existingAdmin = db.prepare('SELECT * FROM users WHERE email = ?').get(adminEmail);
if (!existingAdmin) {
  const hash = bcrypt.hashSync(adminPassword, 10);
  db.prepare('INSERT INTO users (email, password, role) VALUES (?, ?, ?)').run(adminEmail, hash, 'admin');
}

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  store: new SQLiteStore({ db: 'sessions.db' }),
  secret: process.env.SESSION_SECRET || 'fallback-secret-change-me',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 7 * 24 * 60 * 60 * 1000 }
}));

app.use(express.static('public'));
app.use('/uploads', express.static('uploads'));

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const dir = 'uploads';
    if (!fs.existsSync(dir)) fs.mkdirSync(dir);
    cb(null, dir);
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + '-' + file.originalname);
  }
});
const upload = multer({ storage });

function requireAuth(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });
  next();
}

app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  req.session.user = { id: user.id, email: user.email, role: user.role };
  res.json({ success: true });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

app.get('/api/me', (req, res) => {
  res.json(req.session.user || null);
});

app.get('/api/books', (req, res) => {
  const books = db.prepare('SELECT * FROM books ORDER BY id ASC').all();
  res.json(books);
});

app.post('/api/admin/books', requireAuth, upload.fields([{ name: 'cover' }, { name: 'pdf' }]), (req, res) => {
  const { title } = req.body;
  if (!title || !req.files?.cover?.[0] || !req.files?.pdf?.[0]) {
    return res.status(400).json({ error: 'Title, cover image, and PDF are required' });
  }
  const coverPath = '/uploads/' + req.files.cover[0].filename;
  const pdfPath = '/uploads/' + req.files.pdf[0].filename;
  db.prepare('INSERT INTO books (title, cover, pdf) VALUES (?, ?, ?)').run(title, coverPath, pdfPath);
  res.json({ success: true });
});

app.delete('/api/admin/books/:id', requireAuth, (req, res) => {
  db.prepare('DELETE FROM books WHERE id = ?').run(req.params.id);
  res.json({ success: true });
});

app.get('/api/admin/users', requireAuth, (req, res) => {
  const users = db.prepare('SELECT id, email, role FROM users').all();
  res.json(users);
});

app.post('/api/admin/users', requireAuth, (req, res) => {
  const { email, password, role } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Missing fields' });
  const hash = bcrypt.hashSync(password, 10);
  try {
    db.prepare('INSERT INTO users (email, password, role) VALUES (?, ?, ?)').run(email, hash, role || 'admin');
    res.json({ success: true });
  } catch (e) {
    res.status(400).json({ error: 'Email already exists' });
  }
});

app.delete('/api/admin/users/:id', requireAuth, (req, res) => {
  db.prepare('DELETE FROM users WHERE id = ?').run(req.params.id);
  res.json({ success: true });
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Library running on http://localhost:${PORT}`));
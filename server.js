/**
 * Boreal — Backend Server
 *
 * Provee:
 *  - Autenticación JWT (register / login / logout)
 *  - Persistencia de datos por usuario en SQLite
 *  - Proxy seguro a la API de Anthropic (la key nunca llega al browser)
 */

require('dotenv').config();

const express  = require('express');
const path     = require('path');
const Database = require('better-sqlite3');
const bcrypt   = require('bcryptjs');
const jwt      = require('jsonwebtoken');

// ─── Configuración ────────────────────────────────────────────────────────────

const PORT       = parseInt(process.env.PORT || '3000', 10);
const JWT_SECRET = process.env.JWT_SECRET;
const ANTHROPIC_KEY = process.env.ANTHROPIC_API_KEY;
const DB_PATH    = process.env.DB_PATH || path.join(__dirname, 'boreal.db');

if (!JWT_SECRET) {
  console.error('[boreal] ERROR: JWT_SECRET no está definido en .env');
  process.exit(1);
}

// ─── Base de datos ────────────────────────────────────────────────────────────

const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    email      TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    password   TEXT    NOT NULL,
    created_at TEXT    NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS user_data (
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key        TEXT    NOT NULL,
    value      TEXT    NOT NULL,
    updated_at TEXT    NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (user_id, key)
  );
`);

// Statements reutilizables
const stmts = {
  findUserByEmail:  db.prepare('SELECT * FROM users WHERE email = ?'),
  findUserById:     db.prepare('SELECT id, email, created_at FROM users WHERE id = ?'),
  insertUser:       db.prepare('INSERT INTO users (email, password) VALUES (?, ?)'),
  getUserData:      db.prepare('SELECT value FROM user_data WHERE user_id = ? AND key = ?'),
  upsertUserData:   db.prepare(`
    INSERT INTO user_data (user_id, key, value, updated_at)
    VALUES (?, ?, ?, datetime('now'))
    ON CONFLICT(user_id, key) DO UPDATE SET
      value      = excluded.value,
      updated_at = excluded.updated_at
  `),
  deleteUserData:   db.prepare('DELETE FROM user_data WHERE user_id = ? AND key = ?'),
};

// ─── App Express ──────────────────────────────────────────────────────────────

const app = express();
app.use(express.json({ limit: '10mb' }));

// Servir el frontend
app.use(express.static(path.join(__dirname)));

// ─── Middleware de autenticación ──────────────────────────────────────────────

function requireAuth(req, res, next) {
  const header = req.headers['authorization'];
  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'No autenticado' });
  }
  const token = header.slice(7);
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Token inválido o expirado' });
  }
}

// ─── Rutas de autenticación ───────────────────────────────────────────────────

// POST /auth/register
app.post('/auth/register', async (req, res) => {
  const { email, password } = req.body || {};

  if (!email || !password) {
    return res.status(400).json({ error: 'Email y contraseña son requeridos' });
  }
  if (password.length < 8) {
    return res.status(400).json({ error: 'La contraseña debe tener al menos 8 caracteres' });
  }
  const emailRe = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRe.test(email)) {
    return res.status(400).json({ error: 'Email inválido' });
  }

  if (stmts.findUserByEmail.get(email)) {
    return res.status(409).json({ error: 'Ya existe una cuenta con ese email' });
  }

  const hashed = await bcrypt.hash(password, 12);
  const { lastInsertRowid } = stmts.insertUser.run(email, hashed);

  const token = jwt.sign({ id: lastInsertRowid, email }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, user: { id: lastInsertRowid, email } });
});

// POST /auth/login
app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body || {};

  if (!email || !password) {
    return res.status(400).json({ error: 'Email y contraseña son requeridos' });
  }

  const user = stmts.findUserByEmail.get(email);
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ error: 'Email o contraseña incorrectos' });
  }

  const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, user: { id: user.id, email: user.email } });
});

// GET /auth/me
app.get('/auth/me', requireAuth, (req, res) => {
  const user = stmts.findUserById.get(req.user.id);
  if (!user) return res.status(404).json({ error: 'Usuario no encontrado' });
  res.json({ user });
});

// ─── Rutas de datos de usuario ────────────────────────────────────────────────

// GET /data/:key — recuperar un valor persistido
app.get('/data/:key', requireAuth, (req, res) => {
  const row = stmts.getUserData.get(req.user.id, req.params.key);
  if (!row) return res.json({ value: null });
  try {
    res.json({ value: JSON.parse(row.value) });
  } catch {
    res.json({ value: row.value });
  }
});

// PUT /data/:key — guardar un valor
app.put('/data/:key', requireAuth, (req, res) => {
  const { value } = req.body;
  if (value === undefined) {
    return res.status(400).json({ error: 'Falta el campo "value"' });
  }
  const serialized = typeof value === 'string' ? value : JSON.stringify(value);
  stmts.upsertUserData.run(req.user.id, req.params.key, serialized);
  res.json({ ok: true });
});

// DELETE /data/:key — borrar un valor
app.delete('/data/:key', requireAuth, (req, res) => {
  stmts.deleteUserData.run(req.user.id, req.params.key);
  res.json({ ok: true });
});

// ─── Proxy a Anthropic ────────────────────────────────────────────────────────

app.post('/api/:endpoint', requireAuth, async (req, res) => {
  if (!ANTHROPIC_KEY) {
    return res.status(503).json({ error: 'API de IA no configurada en el servidor' });
  }

  const endpoint = req.params.endpoint;
  const allowed  = ['messages'];
  if (!allowed.includes(endpoint)) {
    return res.status(400).json({ error: 'Endpoint no permitido' });
  }

  let bodyStr;
  try {
    bodyStr = JSON.stringify(req.body);
  } catch {
    return res.status(400).json({ error: 'Body inválido' });
  }

  try {
    const upstream = await fetch(`https://api.anthropic.com/v1/${endpoint}`, {
      method:  'POST',
      headers: {
        'Content-Type':      'application/json',
        'x-api-key':         ANTHROPIC_KEY,
        'anthropic-version': '2023-06-01',
      },
      body: bodyStr,
    });

    const data = await upstream.json();

    if (!upstream.ok) {
      return res.status(upstream.status).json({ error: data.error?.message || 'Error de API' });
    }

    res.json(data);
  } catch (err) {
    console.error('[boreal] Error al llamar a Anthropic:', err.message);
    res.status(502).json({ error: 'No se pudo contactar la API de IA' });
  }
});

// ─── Health check ─────────────────────────────────────────────────────────────

app.get('/health', (_req, res) => {
  res.json({
    ok:  true,
    ai:  !!ANTHROPIC_KEY,
    db:  DB_PATH,
    ts:  new Date().toISOString(),
  });
});

// ─── Catch-all → frontend ─────────────────────────────────────────────────────

app.get('*', (_req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// ─── Arrancar ─────────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`[boreal] Servidor corriendo en http://localhost:${PORT}`);
  console.log(`[boreal] Base de datos: ${DB_PATH}`);
  console.log(`[boreal] IA proxy: ${ANTHROPIC_KEY ? 'activa' : 'DESACTIVADA (falta ANTHROPIC_API_KEY)'}`);
});

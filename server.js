/**
 * Boreal — Backend Server
 *
 * Provee:
 *  - Autenticación JWT (register / login / logout)
 *  - Persistencia de datos por usuario en archivo JSON (sin dependencias nativas)
 *  - Proxy seguro a la API de Anthropic (la key nunca llega al browser)
 */

require('dotenv').config();

const express = require('express');
const path    = require('path');
const fs      = require('fs');
const bcrypt  = require('bcryptjs');
const jwt     = require('jsonwebtoken');

// ─── Configuración ────────────────────────────────────────────────────────────

const PORT          = parseInt(process.env.PORT || '3000', 10);
const JWT_SECRET    = process.env.JWT_SECRET;
const ANTHROPIC_KEY = process.env.ANTHROPIC_API_KEY;
const DB_PATH       = process.env.DB_PATH || path.join(__dirname, 'boreal-db.json');

if (!JWT_SECRET) {
  console.error('[boreal] ERROR: JWT_SECRET no está definido en .env');
  process.exit(1);
}

// ─── Base de datos JSON ───────────────────────────────────────────────────────
// Estructura: { users: [{id, email, password, created_at}], data: {userId: {key: value}} }

function loadDB() {
  try {
    if (fs.existsSync(DB_PATH)) {
      return JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
    }
  } catch (e) {
    console.warn('[boreal] No se pudo leer la DB, arrancando vacía:', e.message);
  }
  return { users: [], data: {} };
}

function saveDB(db) {
  try {
    fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2), 'utf8');
  } catch (e) {
    console.error('[boreal] Error al guardar DB:', e.message);
  }
}

let DB = loadDB();

function nextUserId() {
  return DB.users.length === 0 ? 1 : Math.max(...DB.users.map(u => u.id)) + 1;
}

// ─── App Express ──────────────────────────────────────────────────────────────

const app = express();
app.use(express.json({ limit: '10mb' }));
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

app.post('/auth/register', async (req, res) => {
  const { email, password } = req.body || {};

  if (!email || !password)         return res.status(400).json({ error: 'Email y contraseña son requeridos' });
  if (password.length < 8)         return res.status(400).json({ error: 'La contraseña debe tener al menos 8 caracteres' });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: 'Email inválido' });
  if (DB.users.find(u => u.email.toLowerCase() === email.toLowerCase()))
    return res.status(409).json({ error: 'Ya existe una cuenta con ese email' });

  const hashed = await bcrypt.hash(password, 12);
  const id     = nextUserId();
  DB.users.push({ id, email, password: hashed, created_at: new Date().toISOString() });
  saveDB(DB);

  const token = jwt.sign({ id, email }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, user: { id, email } });
});

app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Email y contraseña son requeridos' });

  const user = DB.users.find(u => u.email.toLowerCase() === email.toLowerCase());
  if (!user || !(await bcrypt.compare(password, user.password)))
    return res.status(401).json({ error: 'Email o contraseña incorrectos' });

  const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, user: { id: user.id, email: user.email } });
});

app.get('/auth/me', requireAuth, (req, res) => {
  const user = DB.users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: 'Usuario no encontrado' });
  res.json({ user: { id: user.id, email: user.email, created_at: user.created_at } });
});

// ─── Rutas de datos de usuario ────────────────────────────────────────────────

app.get('/data/:key', requireAuth, (req, res) => {
  const uid   = String(req.user.id);
  const value = DB.data[uid]?.[req.params.key] ?? null;
  res.json({ value });
});

app.put('/data/:key', requireAuth, (req, res) => {
  const { value } = req.body;
  if (value === undefined) return res.status(400).json({ error: 'Falta el campo "value"' });
  const uid = String(req.user.id);
  if (!DB.data[uid]) DB.data[uid] = {};
  DB.data[uid][req.params.key] = value;
  saveDB(DB);
  res.json({ ok: true });
});

app.delete('/data/:key', requireAuth, (req, res) => {
  const uid = String(req.user.id);
  if (DB.data[uid]) delete DB.data[uid][req.params.key];
  saveDB(DB);
  res.json({ ok: true });
});

// ─── Proxy a Anthropic ────────────────────────────────────────────────────────

app.post('/api/:endpoint', requireAuth, async (req, res) => {
  if (!ANTHROPIC_KEY) return res.status(503).json({ error: 'API de IA no configurada en el servidor' });

  const endpoint = req.params.endpoint;
  if (!['messages'].includes(endpoint)) return res.status(400).json({ error: 'Endpoint no permitido' });

  try {
    const upstream = await fetch(`https://api.anthropic.com/v1/${endpoint}`, {
      method:  'POST',
      headers: {
        'Content-Type':      'application/json',
        'x-api-key':         ANTHROPIC_KEY,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify(req.body),
    });
    const data = await upstream.json();
    if (!upstream.ok) return res.status(upstream.status).json({ error: data.error?.message || 'Error de API' });
    res.json(data);
  } catch (err) {
    console.error('[boreal] Error Anthropic:', err.message);
    res.status(502).json({ error: 'No se pudo contactar la API de IA' });
  }
});

// ─── Health check ─────────────────────────────────────────────────────────────

app.get('/health', (_req, res) => {
  res.json({ ok: true, ai: !!ANTHROPIC_KEY, db: DB_PATH, ts: new Date().toISOString() });
});

app.get('*', (_req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// ─── Arrancar ─────────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`[boreal] Servidor corriendo en http://localhost:${PORT}`);
  console.log(`[boreal] Base de datos: ${DB_PATH}`);
  console.log(`[boreal] IA proxy: ${ANTHROPIC_KEY ? 'activa' : 'DESACTIVADA (falta ANTHROPIC_API_KEY)'}`);
});

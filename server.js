import 'dotenv/config';
import express from 'express';
import cookieParser from 'cookie-parser';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import db from './db.js';

const app = express();
const port = Number(process.env.PORT || 3000);
const secret = process.env.SESSION_SECRET || 'macaw-super-secret-key';
const __dirname = path.dirname(fileURLToPath(import.meta.url));

app.use(express.json({ limit: '64kb' }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

const jsonError = (res, status, error) => res.status(status).json({ ok: false, error });
const tokenFor = (type, id) => jwt.sign({ type, id }, secret, { expiresIn: '7d' });

function auth(req, res, next) {
  try {
    const token = req.cookies.macaw_session;
    if (!token) return jsonError(res, 401, 'Inicia sesión.');
    req.actor = jwt.verify(token, secret);
    next();
  } catch {
    return jsonError(res, 401, 'Sesión inválida.');
  }
}

// LOGIN / REGISTRO UNIFICADO DE USUARIOS
app.post('/api/auth/login', (req, res) => {
  const { email, password, name } = req.body || {};
  const cleanEmail = String(email || '').trim().toLowerCase();

  if (!cleanEmail || !password) return jsonError(res, 400, 'Correo y contraseña obligatorios.');

  let user = db.prepare('SELECT * FROM users WHERE email = ?').get(cleanEmail);
  if (!user) {
    if (!name) return res.json({ ok: false, needsRegister: true, error: 'Cuenta no encontrada. Regístrate abajo.' });
    if (password.length < 6) return jsonError(res, 400, 'La contraseña debe tener al menos 6 caracteres.');
    const hash = bcrypt.hashSync(password, 10);
    const info = db.prepare('INSERT INTO users(name, email, password_hash) VALUES (?, ?, ?)').run(String(name).trim(), cleanEmail, hash);
    user = { id: info.lastInsertRowid };
  } else {
    if (!bcrypt.compareSync(password, user.password_hash)) return jsonError(res, 401, 'Contraseña incorrecta.');
  }

  res.cookie('macaw_session', tokenFor('user', user.id), { httpOnly: true, sameSite: 'lax', maxAge: 7 * 86400000 });
  res.json({ ok: true });
});

// LOGIN SECRETO DE ADMINISTRADOR
app.post('/api/auth/admin-login', (req, res) => {
  const { email, password } = req.body || {};
  const cleanEmail = String(email || '').trim().toLowerCase();

  let admin = db.prepare('SELECT * FROM admins WHERE email = ?').get(cleanEmail);
  if (!admin) {
    const hash = bcrypt.hashSync(password, 10);
    const info = db.prepare('INSERT INTO admins(email, password_hash) VALUES (?, ?)').run(cleanEmail, hash);
    admin = { id: info.lastInsertRowid };
  } else if (!bcrypt.compareSync(password, admin.password_hash)) {
    return jsonError(res, 401, 'Clave de administrador incorrecta.');
  }

  res.cookie('macaw_session', tokenFor('admin', admin.id), { httpOnly: true, sameSite: 'lax', maxAge: 7 * 86400000 });
  res.json({ ok: true, isAdmin: true });
});

// DATOS GENERALES DE LA SESIÓN
app.get('/api/me', auth, (req, res) => {
  const settingsRows = db.prepare('SELECT * FROM settings').all();
  const settings = {};
  settingsRows.forEach(r => settings[r.key] = r.value);

  if (req.actor.type === 'admin') {
    const users = db.prepare('SELECT id, name, email, coins, created_at FROM users ORDER BY id DESC').all();
    const platforms = db.prepare('SELECT * FROM platforms ORDER BY slot').all();
    const wheelPrizes = db.prepare('SELECT * FROM wheel_prizes ORDER BY position').all();
    return res.json({ ok: true, isAdmin: true, users, platforms, wheelPrizes, settings });
  }

  const user = db.prepare('SELECT id, name, email, coins FROM users WHERE id = ?').get(req.actor.id);
  const platforms = db.prepare('SELECT slot, name, logo_url, link FROM platforms WHERE active = 1 ORDER BY slot').all();
  const wheelPrizes = db.prepare('SELECT position, label, coins, color FROM wheel_prizes ORDER BY position').all();

  res.json({ ok: true, isAdmin: false, user, platforms, wheelPrizes, settings });
});

// ACCIONES DE ADMIN: EDITAR PLATAFORMAS
app.post('/api/admin/platforms', auth, (req, res) => {
  if (req.actor.type !== 'admin') return jsonError(res, 403, 'No autorizado');
  const { slot, name, logo_url, link, active } = req.body;
  db.prepare('UPDATE platforms SET name=?, logo_url=?, link=?, active=? WHERE slot=?')
    .run(name, logo_url, link, active ? 1 : 0, slot);
  res.json({ ok: true });
});

// ACCIONES DE ADMIN: EDITAR RULETA
app.post('/api/admin/wheel', auth, (req, res) => {
  if (req.actor.type !== 'admin') return jsonError(res, 403, 'No autorizado');
  const { prizes } = req.body;
  const updateStmt = db.prepare('UPDATE wheel_prizes SET label=?, coins=?, color=? WHERE position=?');
  db.transaction((items) => {
    for (const p of items) {
      updateStmt.run(p.label, Number(p.coins), p.color, p.position);
    }
  })(prizes);
  res.json({ ok: true });
});

// ACCIONES DE ADMIN: CONFIGURACIÓN
app.post('/api/admin/settings', auth, (req, res) => {
  if (req.actor.type !== 'admin') return jsonError(res, 403, 'No autorizado');
  const { coins_per_dollar, admob_banner, admob_interstitial, admob_rewarded } = req.body;
  db.prepare('INSERT OR REPLACE INTO settings(key, value) VALUES (?, ?)').run('coins_per_dollar', String(coins_per_dollar || 5000));
  db.prepare('INSERT OR REPLACE INTO settings(key, value) VALUES (?, ?)').run('admob_banner', String(admob_banner || ''));
  db.prepare('INSERT OR REPLACE INTO settings(key, value) VALUES (?, ?)').run('admob_interstitial', String(admob_interstitial || ''));
  db.prepare('INSERT OR REPLACE INTO settings(key, value) VALUES (?, ?)').run('admob_rewarded', String(admob_rewarded || ''));
  res.json({ ok: true });
});

// ACCIÓN USUARIO: RULETA
app.post('/api/user/spin', auth, (req, res) => {
  if (req.actor.type !== 'user') return jsonError(res, 403, 'No autorizado');
  const prizes = db.prepare('SELECT * FROM wheel_prizes ORDER BY position').all();
  if (prizes.length === 0) return jsonError(res, 400, 'No hay premios configurados.');

  const won = prizes[Math.floor(Math.random() * prizes.length)];
  db.prepare('UPDATE users SET coins = coins + ? WHERE id = ?').run(won.coins, req.actor.id);
  res.json({ ok: true, prize: won });
});

// ACCIÓN USUARIO: COMPLETAR NIVEL
app.post('/api/user/complete-level', auth, (req, res) => {
  if (req.actor.type !== 'user') return jsonError(res, 403, 'No autorizado');
  const reward = 2;
  db.prepare('UPDATE users SET coins = coins + ? WHERE id = ?').run(reward, req.actor.id);
  res.json({ ok: true, reward });
});

// RETIRO DE MONEDAS
app.post('/api/user/redeem', auth, (req, res) => {
  if (req.actor.type !== 'user') return jsonError(res, 403, 'No autorizado');
  const { amount_coins } = req.body;
  const user = db.prepare('SELECT coins FROM users WHERE id = ?').get(req.actor.id);
  if (user.coins < amount_coins) return jsonError(res, 400, 'No tienes suficientes monedas.');

  db.prepare('UPDATE users SET coins = coins - ? WHERE id = ?').run(amount_coins, req.actor.id);
  res.json({ ok: true, message: '¡Retiro solicitado con éxito!' });
});

// ==========================================
// CONSULTA DE CAMPAÑAS DESDE LA API DE OFFERWALL
// ==========================================
app.get('/api/user/offers', auth, async (req, res) => {
  if (req.actor.type !== 'user') return jsonError(res, 403, 'No autorizado');
 
  const userId = req.actor.id;
  const userIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
 
  const PUBLIC_API_KEY = "mx3HW0edwc645oWaujD8ie9a00jbD0";
  const BEARER_TOKEN = "FAM5c1ZqgP8QajVAVi81hkktgTidt3UqXWD0jr6Y";

  try {
    const offerwallUrl = `https://offerwall.me/slapi.php?api=${PUBLIC_API_KEY}&token=${BEARER_TOKEN}&id=${userId}&ip=${userIp}&country=ALL`;
    const response = await fetch(offerwallUrl);
    const data = await response.json();

    res.json({ ok: true, offers: data.data || [] });
  } catch (error) {
    console.error("Error al obtener campañas de Offerwall:", error);
    res.json({ ok: true, offers: [] });
  }
});

// ==========================================
// RUTA DE POSTBACK (RECIBE DESDE EL .IO)
// ==========================================
app.get('/api/recibir-premio', (req, res) => {
  const { subId, transId, reward, signature } = req.query;

  if (!subId || !reward) {
    return res.status(400).send("ERROR: Faltan datos");
  }

  const SECRET_KEY = "MWZXb9IBG6wxrzFYfoi8Q6wUHDEvlZsi";

  if (signature) {
    const calculatedSignature = crypto
      .createHash('md5')
      .update(subId + (transId || '') + reward + SECRET_KEY)
      .digest('hex');

    if (calculatedSignature !== signature) {
      console.warn("Advertencia: Firma MD5 no coincide exactamente.");
    }
  }

  try {
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(subId);
   
    if (!user) {
      return res.status(404).send("ERROR: Usuario no encontrado");
    }

    db.prepare('UPDATE users SET coins = coins + ? WHERE id = ?').run(Number(reward), subId);

    console.log(`¡Monedas acreditadas! Usuario ID: ${subId}, Premio: ${reward}`);
    return res.send("OK");
  } catch (error) {
    console.error("Error en base de datos:", error);
    return res.status(500).send("ERROR interno");
  }
});

app.post('/api/auth/logout', (_req, res) => {
  res.clearCookie('macaw_session');
  res.json({ ok: true });
});

app.get('/terminos', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'terms.html'));
});

app.get('/privacidad', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'privacy.html'));
});

app.get('*', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(port, () => {
  console.log(`MacawCoin Backend corriendo en el puerto ${port}`);
});

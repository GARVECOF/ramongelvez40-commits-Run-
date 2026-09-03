import 'dotenv/config';
import express from 'express';
import cookieParser from 'cookie-parser';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import db from './db.js';

const app = express();
// Render exige usar process.env.PORT obligatoriamente
const port = process.env.PORT || 10000;
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

// LOGIN SECRETO DE ADMINISTRADOR (Vía tuerquita)
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
  if (Array.isArray(settingsRows)) {
    settingsRows.forEach(r => settings[r.key] = r.value);
  }

  if (req.actor.type === 'admin') {
    const users = db.prepare('SELECT id, name, email, coins, created_at FROM users').all();
    const platforms = db.prepare('SELECT * FROM platforms').all();
    const wheelPrizes = db.prepare('SELECT * FROM wheel_prizes').all();
    return res.json({ ok: true, isAdmin: true, users, platforms, wheelPrizes, settings });
  }

  const user = db.prepare('SELECT id, name, email, coins FROM users WHERE id = ?').get(req.actor.id);
  const platforms = db.prepare('SELECT slot, name, logo_url, link FROM platforms WHERE active = 1').all();
  const wheelPrizes = db.prepare('SELECT position, label, coins, color FROM wheel_prizes').all();

  res.json({ ok: true, isAdmin: false, user, platforms, wheelPrizes, settings });
});

// ACCIONES DE ADMIN: EDITAR PLATAFORMAS
app.post('/api/admin/platforms', auth, (req, res) => {
  if (req.actor.type !== 'admin') return jsonError(res, 403, 'No autorizado');
  const { slot, name, logo_url, link, active } = req.body;
  db.prepare('UPDATE platforms SET').run(name, logo_url, link, active ? 1 : 0, slot);
  res.json({ ok: true });
});

// ACCIONES DE ADMIN: EDITAR RULETA
app.post('/api/admin/wheel', auth, (req, res) => {
  if (req.actor.type !== 'admin') return jsonError(res, 403, 'No autorizado');
  const { prizes } = req.body;
  const updater = db.transaction((items) => {
    for (const p of items) {
      db.prepare('UPDATE wheel_prizes SET').run(p.label, Number(p.coins), p.color, p.position);
    }
  });
  updater(prizes);
  res.json({ ok: true });
});

// ACCIONES DE ADMIN: EDITAR CONFIGURACIÓN Y ANUNCIOS (AdMob)
app.post('/api/admin/settings', auth, (req, res) => {
  if (req.actor.type !== 'admin') return jsonError(res, 403, 'No autorizado');
  const { coins_per_dollar, admob_banner, admob_interstitial, admob_rewarded } = req.body;
  const setter = db.prepare('INSERT OR REPLACE INTO settings');
  setter.run('coins_per_dollar', String(coins_per_dollar || 5000));
  setter.run('admob_banner', String(admob_banner || ''));
  setter.run('admob_interstitial', String(admob_interstitial || ''));
  setter.run('admob_rewarded', String(admob_rewarded || ''));
  res.json({ ok: true });
});

// ACCIÓN USUARIO: GIRAR RULETA
app.post('/api/user/spin', auth, (req, res) => {
  if (req.actor.type !== 'user') return jsonError(res, 403, 'No autorizado');
  const prizes = db.prepare('SELECT * FROM wheel_prizes').all();
  if (!prizes || prizes.length === 0) return jsonError(res, 400, 'No hay premios configurados.');

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
  if (!user || user.coins < amount_coins) return jsonError(res, 400, 'No tienes suficientes monedas.');

  db.prepare('UPDATE users SET coins = coins - ? WHERE id = ?').run(amount_coins, req.actor.id);
  res.json({ ok: true, message: '¡Retiro de recompensa / PIN solicitado con éxito!' });
});

app.post('/api/auth/logout', (_req, res) => {
  res.clearCookie('macaw_session');
  res.json({ ok: true });
});

// RUTAS LEGALES
app.get('/terminos', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'terms.html'));
});

app.get('/privacidad', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'privacy.html'));
});

app.get('*', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(port, '0.0.0.0', () => {
  console.log(`MacawCoin Backend corriendo exitosamente en el puerto ${port}`);
});

 

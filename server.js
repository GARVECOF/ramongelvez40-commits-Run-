import 'dotenv/config';
import express from 'express';
import cookieParser from 'cookie-parser';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import nodemailer from 'nodemailer';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import db from './db.js';

const app = express();
const port = Number(process.env.PORT || 3000);
const secret = process.env.SESSION_SECRET || 'change-me-in-production';
const __dirname = path.dirname(fileURLToPath(import.meta.url));

app.use(express.json({ limit: '32kb' }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

const setting = (key, fallback) =>
  db.prepare('SELECT value FROM settings WHERE key=?').get(key)?.value ??
  String(fallback);

const coinsPerDollar = () =>
  Number(setting('coins_per_dollar', 1000));

const threshold = () =>
  Number(setting('redeem_threshold', 5000));

const jsonError = (res, status, error) =>
  res.status(status).json({ ok: false, error });

const tokenFor = (kind, id) =>
  jwt.sign({ kind, id }, secret, { expiresIn: '7d' });

function auth(req, res, next) {
  try {
    const token = req.cookies.run_session;
    if (!token) {
      return jsonError(res, 401, 'Inicia sesión para continuar.');
    }
    req.actor = jwt.verify(token, secret);
    next();
  } catch {
    return jsonError(res, 401, 'La sesión ya no es válida.');
  }
}

function adminOnly(req, res, next) {
  if (req.actor?.kind !== 'admin') {
    return jsonError(res, 403, 'Acceso solo para administración.');
  }
  next();
}

function userOnly(req, res, next) {
  if (req.actor?.kind !== 'user') {
    return jsonError(res, 403, 'Acceso solo para usuarios.');
  }
  next();
}

function safeUser(id) {
  return db
    .prepare(
      'SELECT id,name,email,coins,email_verified,created_at FROM users WHERE id=?'
    )
    .get(id);
}

function mailer() {
  if (
    !process.env.SMTP_HOST ||
    !process.env.SMTP_USER ||
    !process.env.SMTP_PASSWORD ||
    !process.env.SMTP_FROM
  ) {
    return null;
  }

  return nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT || 587),
    secure: Number(process.env.SMTP_PORT) === 465,
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASSWORD
    }
  });
}

// Configuración inicial de Admin (Solo aparece si la tabla admins está vacía)
app.get('/api/setup/status', (_req, res) => {
  res.json({
    ok: true,
    configured: Boolean(
      db.prepare('SELECT id FROM admins LIMIT 1').get()
    )
  });
});

app.post('/api/setup/admin', (req, res) => {
  if (db.prepare('SELECT id FROM admins LIMIT 1').get()) {
    return jsonError(res, 409, 'El administrador ya está configurado.');
  }

  const email = String(req.body?.email || '').trim().toLowerCase();
  const password = String(req.body?.password || '');
  const confirm = String(req.body?.confirmPassword || '');

  if (!email || !password || password.length < 8 || password !== confirm) {
    return jsonError(
      res,
      400,
      'Revisa el correo y las contraseñas. Deben coincidir y tener al menos 8 caracteres.'
    );
  }

  const result = db
    .prepare('INSERT INTO admins(email,password_hash) VALUES (?,?)')
    .run(email, bcrypt.hashSync(password, 12));

  res.cookie('run_session', tokenFor('admin', result.lastInsertRowid), {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: 7 * 86400000
  });

  res.json({ ok: true, kind: 'admin', user: { email } });
});

// Login unificado inteligente (Busca en Admin y si no, en Usuarios)
app.post('/api/auth/login', (req, res) => {
  const email = String(req.body?.email || '').trim().toLowerCase();
  const password = String(req.body?.password || '');

  if (!email || !password) {
    return jsonError(res, 400, 'Correo y contraseña obligatorios.');
  }

  // 1. Intentar como Administrador
  const admin = db.prepare('SELECT * FROM admins WHERE email = ?').get(email);
  if (admin && bcrypt.compareSync(password, admin.password_hash)) {
    res.cookie('run_session', tokenFor('admin', admin.id), {
      httpOnly: true,
      sameSite: 'lax',
      secure: process.env.NODE_ENV === 'production',
      maxAge: 7 * 86400000
    });
    return res.json({ ok: true, kind: 'admin', user: { email: admin.email, name: 'Administrador' } });
  }

  // 2. Intentar como Usuario Normal
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (user && bcrypt.compareSync(password, user.password_hash)) {
    res.cookie('run_session', tokenFor('user', user.id), {
      httpOnly: true,
      sameSite: 'lax',
      secure: process.env.NODE_ENV === 'production',
      maxAge: 7 * 86400000
    });
    return res.json({
      ok: true,
      kind: 'user',
      user: safeUser(user.id)
    });
  }

  return jsonError(res, 401, 'Correo o contraseña incorrectos.');
});

// Mantener compatibilidad con la ruta anterior de usuario por si acaso
app.post('/api/auth/user-login', (req, res) => {
  const email = String(req.body?.email || '').trim().toLowerCase();
  const password = String(req.body?.password || '');

  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return jsonError(res, 401, 'Correo o contraseña incorrectos.');
  }

  res.cookie('run_session', tokenFor('user', user.id), {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: 7 * 86400000
  });

  res.json({
    ok: true,
    kind: 'user',
    user: safeUser(user.id)
  });
});

// Endpoint para verificar sesión activa al recargar la página
app.get('/api/me', auth, (req, res) => {
  if (req.actor.kind === 'admin') {
    const admin = db.prepare('SELECT id, email FROM admins WHERE id = ?').get(req.actor.id);
    if (admin) return res.json({ ok: true, kind: 'admin', user: { id: admin.id, email: admin.email, name: 'Administrador' } });
  } else if (req.actor.kind === 'user') {
    const user = safeUser(req.actor.id);
    if (user) return res.json({ ok: true, kind: 'user', user });
  }
  return jsonError(res, 401, 'Sesión no válida.');
});

app.post('/api/auth/logout', (_req, res) => {
  res.clearCookie('run_session');
  res.json({ ok: true });
});

app.get('/api/public/config', (_req, res) => {
  res.json({
    ok: true,
    threshold: threshold(),
    coinsPerDollar: coinsPerDollar(),
    platforms: db
      .prepare('SELECT id,slot,name,logo_url,link FROM platforms WHERE active=1 ORDER BY slot')
      .all()
  });
});

// Registro de Usuario Normal
app.post('/api/auth/register', (req, res) => {
  const { name, email, password, confirmPassword } = req.body || {};

  if (!name || !email || !password) {
    return jsonError(res, 400, 'Todos los campos son obligatorios.');
  }

  if (password.length < 8) {
    return jsonError(res, 400, 'La contraseña debe tener al menos 8 caracteres.');
  }

  if (confirmPassword && password !== confirmPassword) {
    return jsonError(res, 400, 'Las contraseñas no coinciden.');
  }

  const normalized = String(email).trim().toLowerCase();

  try {
    const info = db
      .prepare('INSERT INTO users(name,email,password_hash) VALUES (?,?,?)')
      .run(
        String(name).trim(),
        normalized,
        bcrypt.hashSync(password, 12)
      );

    res.cookie('run_session', tokenFor('user', info.lastInsertRowid), {
      httpOnly: true,
      sameSite: 'lax',
      secure: process.env.NODE_ENV === 'production',
      maxAge: 7 * 86400000
    });

    res.json({
      ok: true,
      kind: 'user',
      user: safeUser(info.lastInsertRowid)
    });
  } catch {
    return jsonError(res, 409, 'Ese correo ya está registrado. Inicia sesión.');
  }
});

// Regla de respaldo obligatoria (Catch-all) para evitar errores 404 de rutas de frontend
app.get('*', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(port, () => {
  console.log(`Servidor corriendo en el puerto ${port}`);
});

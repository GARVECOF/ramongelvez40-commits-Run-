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

async function sendPinEmail(to, name, code, platformName) {
  const transport = mailer();

  if (!transport) {
    throw new Error('Correo SMTP no configurado.');
  }

  await transport.sendMail({
    from: process.env.SMTP_FROM,
    to,
    subject: 'Tu PIN de recompensa de run',
    text: `Hola ${name},

Tu solicitud fue aprobada.

Tu PIN para ${
      platformName || 'la plataforma seleccionada'
    } es:

${code}

Úsalo una sola vez en el lugar autorizado.

Equipo run`
  });
}

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
    return jsonError(
      res,
      409,
      'El administrador ya está configurado.'
    );
  }

  const email = String(req.body?.email || '')
    .trim()
    .toLowerCase();

  const password = String(req.body?.password || '');
  const confirm = String(req.body?.confirmPassword || '');

  if (
    !email ||
    !password ||
    password.length < 8 ||
    password !== confirm
  ) {
    return jsonError(
      res,
      400,
      'Revisa el correo y las dos contraseñas. Deben coincidir y tener al menos 8 caracteres.'
    );
  }

  const result = db
    .prepare(
      'INSERT INTO admins(email,password_hash) VALUES (?,?)'
    )
    .run(email, bcrypt.hashSync(password, 12));

  res.cookie(
    'run_session',
    tokenFor('admin', result.lastInsertRowid),
    {
      httpOnly: true,
      sameSite: 'lax',
      secure: process.env.NODE_ENV === 'production',
      maxAge: 7 * 86400000
    }
  );

  res.json({
    ok: true,
    kind: 'admin',
    user: { email }
  });
});

// Ruta para iniciar sesión como Admin (Añadida para que no falle el acceso)
app.post('/api/auth/login', (req, res) => {
  const email = String(req.body?.email || '').trim().toLowerCase();
  const password = String(req.body?.password || '');

  if (!email || !password) {
    return jsonError(res, 400, 'Correo y contraseña obligatorios.');
  }

  const admin = db.prepare('SELECT * FROM admins WHERE email = ?').get(email);
  if (!admin || !bcrypt.compareSync(password, admin.password_hash)) {
    return jsonError(res, 401, 'Credenciales inválidas.');
  }

  res.cookie(
    'run_session',
    tokenFor('admin', admin.id),
    {
      httpOnly: true,
      sameSite: 'lax',
      secure: process.env.NODE_ENV === 'production',
      maxAge: 7 * 86400000
    }
  );

  res.json({
    ok: true,
    kind: 'admin',
    user: { email: admin.email }
  });
});

app.get('/api/public/config', (_req, res) => {
  res.json({
    ok: true,
    threshold: threshold(),
    coinsPerDollar: coinsPerDollar(),
    platforms: db
      .prepare(
        'SELECT id,slot,name,logo_url,link FROM platforms WHERE active=1 ORDER BY slot'
      )
      .all()
  });
});

app.post('/api/auth/register', (req, res) => {
  const { name, email, password } = req.body || {};

  if (
    !name ||
    !email ||
    !password ||
    password.length < 8
  ) {
    return jsonError(
      res,
      400,
      'Nombre, correo y contraseña de al menos 8 caracteres son obligatorios.'
    );
  }

  const normalized = String(email).trim().toLowerCase();

  try {
    const info = db
      .prepare(
        'INSERT INTO users(name,email,password_hash) VALUES (?,?,?)'
      )
      .run(
        String(name).trim(),
        normalized,
        bcrypt.hashSync(password, 12)
      );

    res.cookie(
      'run_session',
      tokenFor('user', info.lastInsertRowid),
      {
        httpOnly: true,
        sameSite: 'lax',
        secure: process.env.NODE_ENV === 'production',
        maxAge: 7 * 86400000
      }
    );

    res.json({
      ok: true,
      user: safeUser(info.lastInsertRowid)
    });
  } catch {
    return jsonError(
      res,
      409,
      'Ese correo ya está registrado.'
    );
  }
});

app.listen(port, () => {
  console.log(`Servidor corriendo en el puerto ${port}`);
});

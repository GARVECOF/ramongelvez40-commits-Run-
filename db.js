import Database from 'better-sqlite3';
import bcrypt from 'bcryptjs';

const db = new Database(process.env.DB_PATH || 'run.db');
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
CREATE TABLE IF NOT EXISTS admins (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  coins INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS platforms (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  slot INTEGER NOT NULL UNIQUE,
  name TEXT NOT NULL DEFAULT '',
  logo_url TEXT NOT NULL DEFAULT '',
  link TEXT NOT NULL DEFAULT '',
  active INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS wheel_prizes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  position INTEGER NOT NULL UNIQUE,
  label TEXT NOT NULL,
  coins INTEGER NOT NULL,
  color TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
`);

// Inicializar 5 slots de plataformas
for (let slot = 1; slot <= 5; slot += 1) {
  db.prepare('INSERT OR IGNORE INTO platforms(slot) VALUES (?)').run(slot);
}

// Premios iniciales de la ruleta (configurables desde el panel de admin)
const defaultPrizes = [
  { pos: 1, label: '1 Moneda (Migaja)', coins: 1, color: '#46e0da' },
  { pos: 2, label: '2 Monedas', coins: 2, color: '#806cff' },
  { pos: 3, label: '5 Monedas', coins: 5, color: '#ffd166' },
  { pos: 4, label: '1 Moneda', coins: 1, color: '#ef476f' },
  { pos: 5, label: '10 Monedas', coins: 10, color: '#06d6a0' },
  { pos: 6, label: '50 Monedas (Premio Gordo)', coins: 50, color: '#118ab2' }
];

for (const p of defaultPrizes) {
  db.prepare('INSERT OR IGNORE INTO wheel_prizes(position, label, coins, color) VALUES (?, ?, ?, ?)').run(p.pos, p.label, p.coins, p.color);
}

// Configuración por defecto (AdMob IDs, umbrales y banners)
db.prepare("INSERT OR IGNORE INTO settings(key, value) VALUES ('coins_per_dollar', '5000')").run();
db.prepare("INSERT OR IGNORE INTO settings(key, value) VALUES ('admob_banner', 'ca-app-pub-3940256099942544/6300978111')").run();
db.prepare("INSERT OR IGNORE INTO settings(key, value) VALUES ('admob_interstitial', 'ca-app-pub-3940256099942544/1033173712')").run();
db.prepare("INSERT OR IGNORE INTO settings(key, value) VALUES ('admob_rewarded', 'ca-app-pub-3940256099942544/5224354917')").run();

// Crear admin por defecto si se configuran las variables de entorno
if (process.env.ADMIN_EMAIL && process.env.ADMIN_PASSWORD) {
  const email = process.env.ADMIN_EMAIL.toLowerCase().trim();
  const hash = bcrypt.hashSync(process.env.ADMIN_PASSWORD, 12);
  db.prepare('INSERT OR REPLACE INTO admins(email,password_hash) VALUES (?,?)').run(email, hash);
}

export default db;

 

const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  connectionTimeoutMillis: 5000,
  max: 2,
});

let ready = false;
async function getPool() {
  if (!ready) {
    ready = true;
    try {
      await pool.query(`CREATE TABLE IF NOT EXISTS orders (
        id BIGINT PRIMARY KEY, ts TEXT, name TEXT, phone TEXT,
        address TEXT, ord TEXT, payment TEXT, order_type TEXT,
        status TEXT DEFAULT 'new'
      )`);
      await pool.query(`CREATE TABLE IF NOT EXISTS menu_items (
        id BIGINT PRIMARY KEY, data JSONB NOT NULL
      )`);
    } catch (e) { console.error('DB init:', e.message); }
  }
  return pool;
}

module.exports = { getPool };

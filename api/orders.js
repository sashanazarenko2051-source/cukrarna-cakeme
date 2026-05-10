const { getPool }     = require('./_lib/db');
const { isAuthorized } = require('./_lib/auth');

module.exports = async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== 'POST') return res.status(405).end();

  const d = req.body || {};
  if (!isAuthorized(d)) return res.status(401).json({ error: 'Unauthorized' });

  const pool = await getPool();
  const { rows } = await pool.query(
    'SELECT id,ts,name,phone,address,ord AS "order",payment,order_type,status FROM orders ORDER BY id DESC'
  );
  return res.json(rows);
};

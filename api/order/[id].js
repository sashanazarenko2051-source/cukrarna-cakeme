const { getPool }     = require('../_lib/db');
const { isAuthorized } = require('../_lib/auth');

module.exports = async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  const d    = req.body || {};
  const pool = await getPool();
  const id   = parseInt(req.query.id, 10);

  if (!isAuthorized(d)) return res.status(401).json({ error: 'Unauthorized' });

  // PATCH — update order status
  if (req.method === 'PATCH') {
    const status = (d.status || '').trim();
    if (!['new', 'in_progress', 'done'].includes(status))
      return res.status(400).json({ error: 'Invalid status' });
    await pool.query('UPDATE orders SET status=$1 WHERE id=$2', [status, id]);
    return res.json({ ok: true });
  }

  // DELETE
  if (req.method === 'DELETE') {
    await pool.query('DELETE FROM orders WHERE id=$1', [id]);
    return res.json({ ok: true });
  }

  return res.status(405).end();
};

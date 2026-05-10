const { getPool }     = require('../_lib/db');
const { isAuthorized } = require('../_lib/auth');

module.exports = async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  const d    = req.body || {};
  const pool = await getPool();
  const id   = parseInt(req.query.id, 10);

  if (!isAuthorized(d)) return res.status(401).json({ error: 'Unauthorized' });

  // PATCH — update fields
  if (req.method === 'PATCH') {
    const { rows } = await pool.query('SELECT data FROM menu_items WHERE id = $1', [id]);
    if (!rows.length) return res.status(404).json({ error: 'Not found' });

    const item = rows[0].data;
    for (const f of ['price', 'badge', 'img', 'cat'])
      if (f in d) item[f] = (d[f] || '').trim();

    item.name = item.name || {};
    item.desc = item.desc || {};
    for (const lng of ['cs', 'uk', 'en']) {
      if (`name_${lng}` in d) item.name[lng] = (d[`name_${lng}`] || '').trim() || item.name[lng] || '';
      if (`desc_${lng}` in d) item.desc[lng] = (d[`desc_${lng}`] || '').trim();
    }
    await pool.query('UPDATE menu_items SET data = $1 WHERE id = $2', [JSON.stringify(item), id]);
    return res.json({ ok: true, item });
  }

  // DELETE
  if (req.method === 'DELETE') {
    await pool.query('DELETE FROM menu_items WHERE id = $1', [id]);
    return res.json({ ok: true });
  }

  return res.status(405).end();
};

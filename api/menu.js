const { getPool }     = require('./_lib/db');
const { isAuthorized } = require('./_lib/auth');

module.exports = async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  const pool = await getPool();

  // GET — public: return all custom menu items
  if (req.method === 'GET') {
    const { rows } = await pool.query('SELECT data FROM menu_items ORDER BY id ASC');
    return res.json(rows.map(r => r.data));
  }

  // POST — admin: add new item
  if (req.method === 'POST') {
    const d = req.body || {};
    if (!isAuthorized(d)) return res.status(401).json({ error: 'Unauthorized' });

    const nameCs = (d.name_cs || '').trim();
    if (!nameCs) return res.status(400).json({ error: 'name_cs required' });

    const item = {
      id:    Date.now(),
      cat:   d.cat || 'desserts',
      price: (d.price  || '').trim(),
      badge: (d.badge  || '').trim(),
      img:   (d.img    || '').trim(),
      name: {
        cs: nameCs,
        uk: (d.name_uk || '').trim() || nameCs,
        en: (d.name_en || '').trim() || nameCs,
      },
      desc: {
        cs: (d.desc_cs || '').trim(),
        uk: (d.desc_uk || '').trim() || (d.desc_cs || '').trim(),
        en: (d.desc_en || '').trim() || (d.desc_cs || '').trim(),
      },
    };
    await pool.query(
      'INSERT INTO menu_items (id, data) VALUES ($1, $2)',
      [item.id, JSON.stringify(item)]
    );
    return res.json({ ok: true, item });
  }

  return res.status(405).end();
};

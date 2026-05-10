const { getPool } = require('./_lib/db');

module.exports = async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== 'POST') return res.status(405).end();

  const pool = await getPool();
  const d    = req.body || {};

  const order = {
    id:         Date.now(),
    ts:         new Date().toISOString().slice(0, 19) + 'Z',
    name:       (d.name       || '').trim(),
    phone:      (d.phone      || '').trim(),
    address:    (d.address    || '').trim(),
    order:      (d.order      || '').trim(),
    payment:    (d.payment    || '').trim(),
    order_type: (d.order_type || '').trim(),
    status:     'new',
  };

  if (!order.name || !order.phone)
    return res.status(400).json({ success: false, error: 'name and phone required' });

  try {
    await pool.query(
      'INSERT INTO orders (id,ts,name,phone,address,ord,payment,order_type,status) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)',
      [order.id, order.ts, order.name, order.phone, order.address, order.order, order.payment, order.order_type, order.status]
    );
  } catch (e) {
    console.error('order insert:', e.message);
    return res.status(500).json({ success: false, error: 'DB error' });
  }

  return res.json({ success: true });
};

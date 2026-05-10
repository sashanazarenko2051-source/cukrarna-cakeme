const { makeToken, ADMIN_PASS } = require('./_lib/auth');

const failLog = {};

module.exports = async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== 'POST') return res.status(405).end();

  const ip = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim() || 'x';
  const now = Date.now() / 1000;
  failLog[ip] = (failLog[ip] || []).filter(t => now - t < 900);

  if (failLog[ip].length >= 5)
    return res.status(429).json({ error: 'Too many attempts. Try again in 15 minutes.' });

  const body = req.body || {};
  if (body.pass === ADMIN_PASS)
    return res.json({ token: makeToken() });

  failLog[ip].push(now);
  return res.status(401).json({ error: 'Invalid password', remaining: 5 - failLog[ip].length });
};

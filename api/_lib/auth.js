const crypto = require('crypto');

const SECRET_KEY = process.env.SECRET_KEY || 'fallback-key-set-SECRET_KEY-env';
const TOKEN_TTL  = 12 * 3600;

function makeToken() {
  const ts = Math.floor(Date.now() / 1000 / TOKEN_TTL);
  return crypto.createHmac('sha256', SECRET_KEY).update(String(ts)).digest('hex');
}

function verifyToken(tok) {
  if (!tok || typeof tok !== 'string') return false;
  const base = Math.floor(Date.now() / 1000 / TOKEN_TTL);
  for (const off of [0, -1]) {
    const exp = crypto.createHmac('sha256', SECRET_KEY).update(String(base + off)).digest('hex');
    if (tok === exp) return true;
  }
  return false;
}

module.exports = {
  ADMIN_PASS:   process.env.ADMIN_PASS || 'Tort@Praha51',
  makeToken,
  isAuthorized: (body) => verifyToken((body || {}).token),
};

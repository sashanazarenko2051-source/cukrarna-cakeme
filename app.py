from flask import Flask, send_from_directory, request, jsonify
import json, os, time, hmac, hashlib, secrets
from collections import defaultdict

app = Flask(__name__, static_folder='.', static_url_path='')

MENU_FILE    = 'custom_menu.json'
ORDERS_FILE  = 'orders.json'
ADMIN_PASS = os.environ.get('ADMIN_PASS', 'Tort@Praha51')
SECRET_KEY = os.environ.get('SECRET_KEY', secrets.token_hex(32))
TOKEN_TTL  = 12 * 3600  # token window 12 h

# ── Rate limiting (in-memory, resets on restart) ──
_fail_log  = defaultdict(list)
MAX_FAILS  = 5
FAIL_WIN   = 900  # 15 min

def _rate_ok(ip):
    now = time.time()
    _fail_log[ip] = [t for t in _fail_log[ip] if now - t < FAIL_WIN]
    return len(_fail_log[ip]) < MAX_FAILS

def _record_fail(ip):
    _fail_log[ip].append(time.time())

# ── HMAC token helpers ──
def _make_token():
    ts = int(time.time()) // TOKEN_TTL
    return hmac.new(SECRET_KEY.encode(), str(ts).encode(), hashlib.sha256).hexdigest()

def _verify_token(tok):
    if not tok:
        return False
    base = int(time.time()) // TOKEN_TTL
    for offset in [0, -1]:
        exp = hmac.new(SECRET_KEY.encode(), str(base + offset).encode(), hashlib.sha256).hexdigest()
        if hmac.compare_digest(str(tok), exp):
            return True
    return False

def _authorized(d):
    return _verify_token(d.get('token'))

def _get_ip():
    return request.headers.get('X-Forwarded-For', request.remote_addr or '').split(',')[0].strip()

# ── Security headers on every response ──
@app.after_request
def security_headers(resp):
    resp.headers['X-Frame-Options']           = 'DENY'
    resp.headers['X-Content-Type-Options']    = 'nosniff'
    resp.headers['X-XSS-Protection']          = '1; mode=block'
    resp.headers['Referrer-Policy']           = 'strict-origin-when-cross-origin'
    resp.headers['Permissions-Policy']        = 'camera=(), microphone=(), geolocation=()'
    resp.headers['Cache-Control']             = 'no-store' if request.path.startswith('/api/') else resp.headers.get('Cache-Control', '')
    return resp

# ── Menu helpers ──
def load_custom():
    try:
        if os.path.exists(MENU_FILE):
            with open(MENU_FILE, encoding='utf-8') as f:
                return json.load(f)
    except Exception:
        pass
    return []

def save_custom(items):
    with open(MENU_FILE, 'w', encoding='utf-8') as f:
        json.dump(items, f, ensure_ascii=False, indent=2)

# ── Order helpers ──
def load_orders():
    try:
        if os.path.exists(ORDERS_FILE):
            with open(ORDERS_FILE, encoding='utf-8') as f:
                return json.load(f)
    except Exception:
        pass
    return []

def save_orders(orders):
    with open(ORDERS_FILE, 'w', encoding='utf-8') as f:
        json.dump(orders, f, ensure_ascii=False, indent=2)

# ── Routes ──
@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

@app.route('/api/auth', methods=['POST'])
def api_auth():
    ip = _get_ip()
    if not _rate_ok(ip):
        return jsonify({'error': 'Too many attempts. Try again in 15 minutes.'}), 429
    d = request.get_json(force=True, silent=True) or {}
    if d.get('pass') == ADMIN_PASS:
        return jsonify({'token': _make_token()})
    _record_fail(ip)
    remaining = MAX_FAILS - len(_fail_log[ip])
    return jsonify({'error': 'Invalid password', 'remaining': remaining}), 401

@app.route('/api/menu', methods=['GET'])
def api_get():
    return jsonify(load_custom())

@app.route('/api/menu', methods=['POST'])
def api_add():
    d = request.get_json(force=True, silent=True) or {}
    if not _authorized(d):
        return jsonify({'error': 'Unauthorized'}), 401
    name_cs = (d.get('name_cs') or '').strip()
    if not name_cs:
        return jsonify({'error': 'name_cs required'}), 400
    item = {
        'id':    int(time.time() * 1000),
        'cat':   d.get('cat', 'desserts'),
        'price': (d.get('price') or '').strip(),
        'badge': (d.get('badge') or '').strip(),
        'img':   (d.get('img')   or '').strip(),
        'name': {
            'cs': name_cs,
            'uk': (d.get('name_uk') or '').strip() or name_cs,
            'en': (d.get('name_en') or '').strip() or name_cs,
        },
        'desc': {
            'cs': (d.get('desc_cs') or '').strip(),
            'uk': (d.get('desc_uk') or '').strip() or (d.get('desc_cs') or '').strip(),
            'en': (d.get('desc_en') or '').strip() or (d.get('desc_cs') or '').strip(),
        }
    }
    items = load_custom()
    items.append(item)
    save_custom(items)
    return jsonify({'ok': True, 'item': item})

@app.route('/api/order', methods=['POST'])
def api_order():
    d = request.get_json(force=True, silent=True) or {}
    order = {
        'id':         int(time.time() * 1000),
        'ts':         time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'name':       (d.get('name')       or '').strip(),
        'phone':      (d.get('phone')      or '').strip(),
        'address':    (d.get('address')    or '').strip(),
        'order':      (d.get('order')      or '').strip(),
        'payment':    (d.get('payment')    or '').strip(),
        'order_type': (d.get('order_type') or '').strip(),
        'status':     'new',
    }
    if not order['name'] or not order['phone']:
        return jsonify({'success': False, 'error': 'name and phone required'}), 400
    orders = load_orders()
    orders.insert(0, order)
    save_orders(orders[:300])
    return jsonify({'success': True})

@app.route('/api/orders', methods=['POST'])
def api_orders():
    d = request.get_json(force=True, silent=True) or {}
    if not _authorized(d):
        return jsonify({'error': 'Unauthorized'}), 401
    return jsonify(load_orders())

@app.route('/api/menu/<int:item_id>', methods=['DELETE'])
def api_delete(item_id):
    d = request.get_json(force=True, silent=True) or {}
    if not _authorized(d):
        return jsonify({'error': 'Unauthorized'}), 401
    save_custom([i for i in load_custom() if i.get('id') != item_id])
    return jsonify({'ok': True})

@app.route('/<path:path>')
def serve(path):
    return send_from_directory('.', path)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)

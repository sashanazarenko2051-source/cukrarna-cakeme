from flask import Flask, send_from_directory, request, jsonify
import json, os, time, hmac, hashlib, secrets, smtplib
from collections import defaultdict
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

try:
    import psycopg2
    import psycopg2.extras
except ImportError:
    psycopg2 = None

app = Flask(__name__, static_folder='.', static_url_path='')

MENU_FILE    = 'custom_menu.json'
ORDERS_FILE  = 'orders.json'
SMTP_USER    = os.environ.get('SMTP_USER', '')
SMTP_PASS    = os.environ.get('SMTP_PASS', '')
ORDER_TO     = os.environ.get('ORDER_TO', '')
ADMIN_PASS   = os.environ.get('ADMIN_PASS', 'Tort@Praha51')
SECRET_KEY   = os.environ.get('SECRET_KEY', secrets.token_hex(32))
DATABASE_URL = os.environ.get('DATABASE_URL', '')
TOKEN_TTL    = 12 * 3600

_fail_log  = defaultdict(list)
MAX_FAILS  = 5
FAIL_WIN   = 900

def _rate_ok(ip):
    now = time.time()
    _fail_log[ip] = [t for t in _fail_log[ip] if now - t < FAIL_WIN]
    return len(_fail_log[ip]) < MAX_FAILS

def _record_fail(ip):
    _fail_log[ip].append(time.time())

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

@app.after_request
def security_headers(resp):
    resp.headers['X-Frame-Options']        = 'DENY'
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['X-XSS-Protection']       = '1; mode=block'
    resp.headers['Referrer-Policy']        = 'strict-origin-when-cross-origin'
    resp.headers['Permissions-Policy']     = 'camera=(), microphone=(), geolocation=()'
    resp.headers['Cache-Control']          = 'no-store' if request.path.startswith('/api/') else resp.headers.get('Cache-Control', '')
    return resp

# ── Database ──
def _get_conn():
    return psycopg2.connect(DATABASE_URL, connect_timeout=5)

def _init_db():
    if not DATABASE_URL or not psycopg2:
        return
    try:
        with _get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS orders (
                        id BIGINT PRIMARY KEY,
                        ts TEXT,
                        name TEXT,
                        phone TEXT,
                        address TEXT,
                        ord TEXT,
                        payment TEXT,
                        order_type TEXT,
                        status TEXT DEFAULT 'new'
                    )
                """)
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS menu_items (
                        id BIGINT PRIMARY KEY,
                        data JSONB NOT NULL
                    )
                """)
    except Exception:
        pass

_init_db()

# ── Menu helpers ──
def load_custom():
    if DATABASE_URL and psycopg2:
        try:
            with _get_conn() as conn:
                with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                    cur.execute("SELECT data FROM menu_items ORDER BY id ASC")
                    return [r['data'] for r in cur.fetchall()]
        except Exception:
            pass
    try:
        if os.path.exists(MENU_FILE):
            with open(MENU_FILE, encoding='utf-8') as f:
                return json.load(f)
    except Exception:
        pass
    return []

def save_custom(items):
    if DATABASE_URL and psycopg2:
        try:
            with _get_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute("DELETE FROM menu_items")
                    for item in items:
                        cur.execute(
                            "INSERT INTO menu_items (id, data) VALUES (%s, %s)",
                            (item['id'], json.dumps(item, ensure_ascii=False))
                        )
            return
        except Exception:
            pass
    with open(MENU_FILE, 'w', encoding='utf-8') as f:
        json.dump(items, f, ensure_ascii=False, indent=2)

# ── Email ──
def send_order_email(order):
    if not SMTP_USER or not SMTP_PASS or not ORDER_TO:
        return
    try:
        msg = MIMEMultipart()
        msg['Subject'] = f"\U0001f382 Нове замовлення CakeMe — {order['name']}"
        msg['From']    = SMTP_USER
        msg['To']      = ORDER_TO
        body = (
            f"Нове замовлення!\n\n"
            f"Ім'я:       {order['name']}\n"
            f"Телефон:    {order['phone']}\n"
            f"Адреса:     {order.get('address') or '—'}\n"
            f"Тип:        {order.get('order_type') or '—'}\n"
            f"Замовлення: {order.get('order') or '—'}\n"
            f"Оплата:     {order.get('payment') or '—'}\n"
            f"Час:        {order['ts']}\n"
        )
        msg.attach(MIMEText(body, 'plain', 'utf-8'))
        with smtplib.SMTP_SSL('smtp.gmail.com', 465, timeout=10) as s:
            s.login(SMTP_USER, SMTP_PASS)
            s.send_message(msg)
    except Exception:
        pass

# ── Order helpers (DB + JSON fallback) ──
def load_orders():
    if DATABASE_URL and psycopg2:
        try:
            with _get_conn() as conn:
                with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                    cur.execute("SELECT id,ts,name,phone,address,ord AS \"order\",payment,order_type,status FROM orders ORDER BY id DESC")
                    return [dict(r) for r in cur.fetchall()]
        except Exception:
            pass
    try:
        if os.path.exists(ORDERS_FILE):
            with open(ORDERS_FILE, encoding='utf-8') as f:
                return json.load(f)
    except Exception:
        pass
    return []

def _save_order_db(order):
    with _get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO orders (id,ts,name,phone,address,ord,payment,order_type,status) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT (id) DO NOTHING",
                (order['id'], order['ts'], order['name'], order['phone'],
                 order.get('address',''), order.get('order',''),
                 order.get('payment',''), order.get('order_type',''), order['status'])
            )

def _update_status_db(order_id, status):
    with _get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE orders SET status=%s WHERE id=%s", (status, order_id))

def _delete_order_db(order_id):
    with _get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM orders WHERE id=%s", (order_id,))

def _save_order_json(order):
    orders = []
    try:
        if os.path.exists(ORDERS_FILE):
            with open(ORDERS_FILE, encoding='utf-8') as f:
                orders = json.load(f)
    except Exception:
        pass
    orders.insert(0, order)
    with open(ORDERS_FILE, 'w', encoding='utf-8') as f:
        json.dump(orders[:300], f, ensure_ascii=False, indent=2)

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
    saved = False
    if DATABASE_URL and psycopg2:
        try:
            _save_order_db(order)
            saved = True
        except Exception:
            pass
    if not saved:
        try:
            _save_order_json(order)
        except Exception:
            pass
    send_order_email(order)
    return jsonify({'success': True})

@app.route('/api/orders', methods=['POST'])
def api_orders():
    d = request.get_json(force=True, silent=True) or {}
    if not _authorized(d):
        return jsonify({'error': 'Unauthorized'}), 401
    return jsonify(load_orders())

@app.route('/api/order/<int:order_id>', methods=['PATCH'])
def api_order_status(order_id):
    d = request.get_json(force=True, silent=True) or {}
    if not _authorized(d):
        return jsonify({'error': 'Unauthorized'}), 401
    status = (d.get('status') or '').strip()
    if status not in ('new', 'in_progress', 'done'):
        return jsonify({'error': 'Invalid status'}), 400
    if DATABASE_URL and psycopg2:
        try:
            _update_status_db(order_id, status)
            return jsonify({'ok': True})
        except Exception:
            pass
    try:
        orders = load_orders()
        for o in orders:
            if o.get('id') == order_id:
                o['status'] = status
                break
        with open(ORDERS_FILE, 'w', encoding='utf-8') as f:
            json.dump(orders, f, ensure_ascii=False, indent=2)
    except Exception:
        pass
    return jsonify({'ok': True})

@app.route('/api/order/<int:order_id>', methods=['DELETE'])
def api_order_del(order_id):
    d = request.get_json(force=True, silent=True) or {}
    if not _authorized(d):
        return jsonify({'error': 'Unauthorized'}), 401
    if DATABASE_URL and psycopg2:
        try:
            _delete_order_db(order_id)
            return jsonify({'ok': True})
        except Exception:
            pass
    try:
        orders = [o for o in load_orders() if o.get('id') != order_id]
        with open(ORDERS_FILE, 'w', encoding='utf-8') as f:
            json.dump(orders, f, ensure_ascii=False, indent=2)
    except Exception:
        pass
    return jsonify({'ok': True})

@app.route('/api/menu/<int:item_id>', methods=['PATCH'])
def api_update_menu(item_id):
    d = request.get_json(force=True, silent=True) or {}
    if not _authorized(d):
        return jsonify({'error': 'Unauthorized'}), 401
    items = load_custom()
    item = next((i for i in items if i.get('id') == item_id), None)
    if not item:
        return jsonify({'error': 'Not found'}), 404
    for field in ('price', 'badge', 'img', 'cat'):
        if field in d:
            item[field] = (d[field] or '').strip()
    item.setdefault('name', {})
    item.setdefault('desc', {})
    for lng in ('cs', 'uk', 'en'):
        if f'name_{lng}' in d:
            item['name'][lng] = (d[f'name_{lng}'] or '').strip() or item['name'].get(lng, '')
        if f'desc_{lng}' in d:
            item['desc'][lng] = (d[f'desc_{lng}'] or '').strip()
    save_custom(items)
    return jsonify({'ok': True, 'item': item})

@app.route('/api/menu/<int:item_id>', methods=['DELETE'])
def api_delete(item_id):
    d = request.get_json(force=True, silent=True) or {}
    if not _authorized(d):
        return jsonify({'error': 'Unauthorized'}), 401
    save_custom([i for i in load_custom() if i.get('id') != item_id])
    return jsonify({'ok': True})

_BLOCKED = {'app.py', 'orders.json', 'custom_menu.json', 'requirements.txt',
            'Procfile', '.env', 'wsgi.py'}

@app.route('/<path:path>')
def serve(path):
    if path in _BLOCKED or path.startswith('.'):
        return '', 404
    return send_from_directory('.', path)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)

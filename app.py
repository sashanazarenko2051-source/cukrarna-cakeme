import hashlib, hmac, json, os, secrets, time
from collections import defaultdict
import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from psycopg_pool import ConnectionPool
import stripe as _stripe
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse

app = FastAPI(docs_url=None, redoc_url=None)

DATABASE_URL        = os.environ.get('DATABASE_URL', '')
ADMIN_PASS          = os.environ.get('ADMIN_PASS', 'Tort@Praha51')
SECRET_KEY          = os.environ.get('SECRET_KEY', secrets.token_hex(32))
STRIPE_SECRET_KEY   = os.environ.get('STRIPE_SECRET_KEY', '')
STRIPE_PUB_KEY      = os.environ.get('STRIPE_PUBLISHABLE_KEY', '')
TOKEN_TTL           = 12 * 3600

if STRIPE_SECRET_KEY:
    _stripe.api_key = STRIPE_SECRET_KEY

_fail_log: dict = defaultdict(list)
_pool: ConnectionPool = None

# ── Auth ──────────────────────────────────────────────────────────────────────
def _make_token():
    ts = int(time.time()) // TOKEN_TTL
    return hmac.new(SECRET_KEY.encode(), str(ts).encode(), hashlib.sha256).hexdigest()

def _verify_token(tok):
    if not tok:
        return False
    base = int(time.time()) // TOKEN_TTL
    for off in [0, -1]:
        exp = hmac.new(SECRET_KEY.encode(), str(base + off).encode(), hashlib.sha256).hexdigest()
        if hmac.compare_digest(str(tok), exp):
            return True
    return False

def _get_ip(req: Request) -> str:
    return req.headers.get('X-Forwarded-For', req.client.host or '').split(',')[0].strip()

# ── DB pool ───────────────────────────────────────────────────────────────────
def _get_pool() -> ConnectionPool:
    global _pool
    if _pool is None and DATABASE_URL:
        _pool = ConnectionPool(DATABASE_URL, min_size=1, max_size=5, open=True)
        _init_tables()
    return _pool

def _init_tables():
    with _pool.connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS orders (
                id BIGINT PRIMARY KEY, ts TEXT, name TEXT, phone TEXT,
                address TEXT, ord TEXT, payment TEXT, order_type TEXT,
                status TEXT DEFAULT 'new'
            )""")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS menu_items (
                id BIGINT PRIMARY KEY, data JSONB NOT NULL
            )""")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                key VARCHAR(100) PRIMARY KEY, value TEXT NOT NULL DEFAULT ''
            )""")

@app.on_event('startup')
async def _startup():
    if DATABASE_URL:
        try:
            _get_pool()
        except Exception as e:
            print('DB startup error:', e)

# ── Security headers ──────────────────────────────────────────────────────────
@app.middleware('http')
async def _sec(req: Request, call_next):
    resp = await call_next(req)
    resp.headers.update({
        'X-Frame-Options':        'DENY',
        'X-Content-Type-Options': 'nosniff',
        'X-XSS-Protection':       '1; mode=block',
        'Referrer-Policy':        'strict-origin-when-cross-origin',
    })
    if req.url.path.startswith('/api/'):
        resp.headers['Cache-Control'] = 'no-store'
    elif 'text/html' in resp.headers.get('content-type', ''):
        resp.headers['Cache-Control'] = 'no-cache, must-revalidate'
    return resp

@app.exception_handler(HTTPException)
async def _http_err(req, exc):
    detail = exc.detail
    body = detail if isinstance(detail, dict) else {'error': detail}
    return JSONResponse(status_code=exc.status_code, content=body)

# ── /api/auth ─────────────────────────────────────────────────────────────────
@app.post('/api/auth')
async def api_auth(req: Request):
    ip  = _get_ip(req)
    now = time.time()
    _fail_log[ip] = [t for t in _fail_log[ip] if now - t < 900]
    if len(_fail_log[ip]) >= 5:
        raise HTTPException(429, 'Too many attempts. Try again in 15 minutes.')
    d = await req.json()
    if d.get('pass') == ADMIN_PASS:
        return {'token': _make_token()}
    _fail_log[ip].append(now)
    raise HTTPException(401, {'error': 'Invalid password', 'remaining': 5 - len(_fail_log[ip])})

# ── /api/menu ─────────────────────────────────────────────────────────────────
@app.get('/api/menu')
def api_menu_get():
    with _get_pool().connection() as conn:
        rows = conn.execute('SELECT data FROM menu_items ORDER BY id ASC').fetchall()
    return [r[0] for r in rows]

@app.post('/api/menu')
async def api_menu_add(req: Request):
    d = await req.json()
    if not _verify_token(d.get('token')):
        raise HTTPException(401, 'Unauthorized')
    name_cs = (d.get('name_cs') or '').strip()
    if not name_cs:
        raise HTTPException(400, 'name_cs required')
    item = {
        'id':    int(time.time() * 1000),
        'cat':   d.get('cat', 'desserts'),
        'price': (d.get('price')   or '').strip(),
        'badge': (d.get('badge')   or '').strip(),
        'img':   (d.get('img')     or '').strip(),
        'name': {
            'cs': name_cs,
            'uk': (d.get('name_uk') or '').strip() or name_cs,
            'en': (d.get('name_en') or '').strip() or name_cs,
        },
        'desc': {
            'cs': (d.get('desc_cs') or '').strip(),
            'uk': (d.get('desc_uk') or '').strip() or (d.get('desc_cs') or '').strip(),
            'en': (d.get('desc_en') or '').strip() or (d.get('desc_cs') or '').strip(),
        },
    }
    with _get_pool().connection() as conn:
        conn.execute('INSERT INTO menu_items (id, data) VALUES (%s, %s)',
                     (item['id'], Jsonb(item)))
    return {'ok': True, 'item': item}

@app.patch('/api/menu/{item_id}')
async def api_menu_patch(item_id: int, req: Request):
    d = await req.json()
    if not _verify_token(d.get('token')):
        raise HTTPException(401, 'Unauthorized')
    with _get_pool().connection() as conn:
        row = conn.execute('SELECT data FROM menu_items WHERE id=%s', (item_id,)).fetchone()
        if not row:
            raise HTTPException(404, 'Not found')
        item = dict(row[0])
        for f in ('price', 'badge', 'img', 'cat'):
            if f in d:
                item[f] = (d[f] or '').strip()
        if 'favorite' in d:
            item['favorite'] = bool(d['favorite'])
        item.setdefault('name', {})
        item.setdefault('desc', {})
        for lng in ('cs', 'uk', 'en'):
            if f'name_{lng}' in d:
                item['name'][lng] = (d[f'name_{lng}'] or '').strip() or item['name'].get(lng, '')
            if f'desc_{lng}' in d:
                item['desc'][lng] = (d[f'desc_{lng}'] or '').strip()
        conn.execute('UPDATE menu_items SET data=%s WHERE id=%s', (Jsonb(item), item_id))
    return {'ok': True, 'item': item}

@app.delete('/api/menu/{item_id}')
async def api_menu_del(item_id: int, req: Request):
    d = await req.json()
    if not _verify_token(d.get('token')):
        raise HTTPException(401, 'Unauthorized')
    with _get_pool().connection() as conn:
        conn.execute('DELETE FROM menu_items WHERE id=%s', (item_id,))
    return {'ok': True}

# ── /api/static-favs ─────────────────────────────────────────────────────────
import json as _json

@app.get('/api/static-favs')
def api_static_favs_get():
    with _get_pool().connection() as conn:
        row = conn.execute("SELECT value FROM settings WHERE key='static_favs'").fetchone()
        return {'favs': _json.loads(row[0]) if row and row[0] else []}

@app.post('/api/static-favs')
async def api_static_favs_set(req: Request):
    d = await req.json()
    if not _verify_token(d.get('token')):
        raise HTTPException(401, 'Unauthorized')
    favs = [int(x) for x in (d.get('favs') or [])]
    with _get_pool().connection() as conn:
        conn.execute(
            "INSERT INTO settings(key,value) VALUES('static_favs',%s) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value",
            (_json.dumps(favs),)
        )
    return {'ok': True}

# ── /api/order ────────────────────────────────────────────────────────────────
@app.post('/api/order')
async def api_order(req: Request):
    d = await req.json()
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
    with _get_pool().connection() as conn:
        conn.execute(
            'INSERT INTO orders (id,ts,name,phone,address,ord,payment,order_type,status)'
            ' VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)',
            (order['id'], order['ts'], order['name'], order['phone'],
             order['address'], order['order'], order['payment'],
             order['order_type'], order['status'])
        )
    return {'success': True}

# ── /api/orders ───────────────────────────────────────────────────────────────
@app.post('/api/orders')
async def api_orders(req: Request):
    d = await req.json()
    if not _verify_token(d.get('token')):
        raise HTTPException(401, 'Unauthorized')
    with _get_pool().connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                'SELECT id,ts,name,phone,address,ord AS "order",'
                'payment,order_type,status FROM orders ORDER BY id DESC'
            )
            rows = cur.fetchall()
    return rows

@app.patch('/api/order/{order_id}')
async def api_order_status(order_id: int, req: Request):
    d = await req.json()
    if not _verify_token(d.get('token')):
        raise HTTPException(401, 'Unauthorized')
    status = (d.get('status') or '').strip()
    if status not in ('new', 'in_progress', 'done', 'paid'):
        raise HTTPException(400, 'Invalid status')
    with _get_pool().connection() as conn:
        conn.execute('UPDATE orders SET status=%s WHERE id=%s', (status, order_id))
    return {'ok': True}

@app.delete('/api/order/{order_id}')
async def api_order_del(order_id: int, req: Request):
    d = await req.json()
    if not _verify_token(d.get('token')):
        raise HTTPException(401, 'Unauthorized')
    with _get_pool().connection() as conn:
        conn.execute('DELETE FROM orders WHERE id=%s', (order_id,))
    return {'ok': True}

# ── /api/create-checkout-session ──────────────────────────────────────────────
@app.post('/api/create-checkout-session')
async def api_create_checkout(req: Request):
    if not STRIPE_SECRET_KEY:
        raise HTTPException(503, 'Stripe not configured')
    d = await req.json()
    total_czk = int(d.get('total_czk') or 0)
    if total_czk < 1:
        raise HTTPException(400, 'Invalid amount')
    deposit_czk = max(1, -(-total_czk // 2))  # ceiling division for 50%
    amount_hellers = deposit_czk * 100

    order_id = int(time.time() * 1000)
    ts = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    order = {
        'id': order_id, 'ts': ts,
        'name':       (d.get('name')       or '').strip(),
        'phone':      (d.get('phone')      or '').strip(),
        'address':    (d.get('address')    or '').strip(),
        'order':      (d.get('order')      or '').strip(),
        'payment':    'online',
        'order_type': (d.get('order_type') or '').strip(),
        'status':     'pending_payment',
    }
    with _get_pool().connection() as conn:
        conn.execute(
            'INSERT INTO orders (id,ts,name,phone,address,ord,payment,order_type,status)'
            ' VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)',
            (order['id'], order['ts'], order['name'], order['phone'],
             order['address'], order['order'], order['payment'],
             order['order_type'], order['status'])
        )

    host   = req.headers.get('X-Forwarded-Host') or req.headers.get('host', '')
    scheme = req.headers.get('X-Forwarded-Proto', 'https')
    base   = f'{scheme}://{host}'
    try:
        session = _stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[{
                'price_data': {
                    'currency': 'czk',
                    'product_data': {'name': f'CakeMe — záloha 50 % (#{order_id})'},
                    'unit_amount': amount_hellers,
                },
                'quantity': 1,
            }],
            mode='payment',
            success_url=f'{base}/success?session_id={{CHECKOUT_SESSION_ID}}&order_id={order_id}',
            cancel_url=f'{base}/cancel?order_id={order_id}',
            metadata={'order_id': str(order_id)},
        )
    except Exception:
        with _get_pool().connection() as conn:
            conn.execute('DELETE FROM orders WHERE id=%s', (order_id,))
        raise HTTPException(502, 'Payment service unavailable')
    return {'url': session.url}

# ── /api/verify-payment ───────────────────────────────────────────────────────
@app.get('/api/verify-payment')
async def api_verify_payment(session_id: str, order_id: int):
    if not STRIPE_SECRET_KEY:
        raise HTTPException(503, 'Stripe not configured')
    try:
        session = _stripe.checkout.Session.retrieve(session_id)
    except Exception:
        raise HTTPException(400, 'Invalid session')
    if (session.payment_status == 'paid'
            and str(session.metadata.get('order_id')) == str(order_id)):
        with _get_pool().connection() as conn:
            conn.execute(
                'UPDATE orders SET status=%s WHERE id=%s AND status=%s',
                ('paid', order_id, 'pending_payment')
            )
        return {'paid': True}
    return {'paid': False}

# ── /api/order/{id} PATCH — allow 'paid' status for admin ────────────────────
# (override to extend valid statuses)

# ── Static files ──────────────────────────────────────────────────────────────
_BLOCKED = {
    'app.py', 'orders.json', 'custom_menu.json',
    'requirements.txt', 'Procfile', '.env', 'wsgi.py',
}

@app.get('/')
def _index():
    return FileResponse('index.html')

@app.get('/success')
def _success():
    return FileResponse('success.html')

@app.get('/cancel')
def _cancel():
    return FileResponse('cancel.html')

@app.get('/{path:path}')
def _static(path: str):
    if path in _BLOCKED or path.startswith('.'):
        raise HTTPException(404)
    if os.path.isfile(path):
        return FileResponse(path)
    raise HTTPException(404)

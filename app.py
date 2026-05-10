import hashlib, hmac, json, os, secrets, time
from collections import defaultdict
import psycopg2, psycopg2.extras, psycopg2.pool
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse

app = FastAPI(docs_url=None, redoc_url=None)

DATABASE_URL = os.environ.get('DATABASE_URL', '')
ADMIN_PASS   = os.environ.get('ADMIN_PASS', 'Tort@Praha51')
SECRET_KEY   = os.environ.get('SECRET_KEY', secrets.token_hex(32))
TOKEN_TTL    = 12 * 3600

_fail_log: dict = defaultdict(list)
_pool = None

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
def _get_pool():
    global _pool
    if _pool is None and DATABASE_URL:
        _pool = psycopg2.pool.ThreadedConnectionPool(
            1, 5, DATABASE_URL, connect_timeout=10
        )
        _init_tables()
    return _pool

def _init_tables():
    conn = _pool.getconn()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS orders (
                    id BIGINT PRIMARY KEY, ts TEXT, name TEXT, phone TEXT,
                    address TEXT, ord TEXT, payment TEXT, order_type TEXT,
                    status TEXT DEFAULT 'new'
                )""")
            cur.execute("""
                CREATE TABLE IF NOT EXISTS menu_items (
                    id BIGINT PRIMARY KEY, data JSONB NOT NULL
                )""")
        conn.commit()
    finally:
        _pool.putconn(conn)

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
    pool = _get_pool()
    conn = pool.getconn()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute('SELECT data FROM menu_items ORDER BY id ASC')
            return [r['data'] for r in cur.fetchall()]
    finally:
        pool.putconn(conn)

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
    pool = _get_pool()
    conn = pool.getconn()
    try:
        with conn.cursor() as cur:
            cur.execute('INSERT INTO menu_items (id, data) VALUES (%s, %s)',
                        (item['id'], json.dumps(item, ensure_ascii=False)))
        conn.commit()
    finally:
        pool.putconn(conn)
    return {'ok': True, 'item': item}

@app.patch('/api/menu/{item_id}')
async def api_menu_patch(item_id: int, req: Request):
    d = await req.json()
    if not _verify_token(d.get('token')):
        raise HTTPException(401, 'Unauthorized')
    pool = _get_pool()
    conn = pool.getconn()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute('SELECT data FROM menu_items WHERE id=%s', (item_id,))
            row = cur.fetchone()
            if not row:
                raise HTTPException(404, 'Not found')
            item = dict(row['data'])
            for f in ('price', 'badge', 'img', 'cat'):
                if f in d:
                    item[f] = (d[f] or '').strip()
            item.setdefault('name', {})
            item.setdefault('desc', {})
            for lng in ('cs', 'uk', 'en'):
                if f'name_{lng}' in d:
                    item['name'][lng] = (d[f'name_{lng}'] or '').strip() or item['name'].get(lng, '')
                if f'desc_{lng}' in d:
                    item['desc'][lng] = (d[f'desc_{lng}'] or '').strip()
            cur.execute('UPDATE menu_items SET data=%s WHERE id=%s',
                        (json.dumps(item, ensure_ascii=False), item_id))
        conn.commit()
    finally:
        pool.putconn(conn)
    return {'ok': True, 'item': item}

@app.delete('/api/menu/{item_id}')
async def api_menu_del(item_id: int, req: Request):
    d = await req.json()
    if not _verify_token(d.get('token')):
        raise HTTPException(401, 'Unauthorized')
    pool = _get_pool()
    conn = pool.getconn()
    try:
        with conn.cursor() as cur:
            cur.execute('DELETE FROM menu_items WHERE id=%s', (item_id,))
        conn.commit()
    finally:
        pool.putconn(conn)
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
    # DEBUG: validation disabled
    # if not order['name'] or not order['phone']:
    #     raise HTTPException(400, {'success': False, 'error': 'name and phone required'})
    pool = _get_pool()
    conn = pool.getconn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                'INSERT INTO orders (id,ts,name,phone,address,ord,payment,order_type,status)'
                ' VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)',
                (order['id'], order['ts'], order['name'], order['phone'],
                 order['address'], order['order'], order['payment'],
                 order['order_type'], order['status'])
            )
        conn.commit()
    finally:
        pool.putconn(conn)
    return {'success': True}

# ── /api/orders ───────────────────────────────────────────────────────────────
@app.post('/api/orders')
async def api_orders(req: Request):
    d = await req.json()
    if not _verify_token(d.get('token')):
        raise HTTPException(401, 'Unauthorized')
    pool = _get_pool()
    conn = pool.getconn()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                'SELECT id,ts,name,phone,address,ord AS "order",'
                'payment,order_type,status FROM orders ORDER BY id DESC'
            )
            return [dict(r) for r in cur.fetchall()]
    finally:
        pool.putconn(conn)

@app.patch('/api/order/{order_id}')
async def api_order_status(order_id: int, req: Request):
    d = await req.json()
    if not _verify_token(d.get('token')):
        raise HTTPException(401, 'Unauthorized')
    status = (d.get('status') or '').strip()
    if status not in ('new', 'in_progress', 'done'):
        raise HTTPException(400, 'Invalid status')
    pool = _get_pool()
    conn = pool.getconn()
    try:
        with conn.cursor() as cur:
            cur.execute('UPDATE orders SET status=%s WHERE id=%s', (status, order_id))
        conn.commit()
    finally:
        pool.putconn(conn)
    return {'ok': True}

@app.delete('/api/order/{order_id}')
async def api_order_del(order_id: int, req: Request):
    d = await req.json()
    if not _verify_token(d.get('token')):
        raise HTTPException(401, 'Unauthorized')
    pool = _get_pool()
    conn = pool.getconn()
    try:
        with conn.cursor() as cur:
            cur.execute('DELETE FROM orders WHERE id=%s', (order_id,))
        conn.commit()
    finally:
        pool.putconn(conn)
    return {'ok': True}

# ── Static files ──────────────────────────────────────────────────────────────
_BLOCKED = {
    'app.py', 'orders.json', 'custom_menu.json',
    'requirements.txt', 'Procfile', '.env', 'wsgi.py',
}

@app.get('/')
def _index():
    return FileResponse('index.html')

@app.get('/{path:path}')
def _static(path: str):
    if path in _BLOCKED or path.startswith('.'):
        raise HTTPException(404)
    if os.path.isfile(path):
        return FileResponse(path)
    raise HTTPException(404)

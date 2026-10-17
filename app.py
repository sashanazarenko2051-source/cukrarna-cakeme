import base64, hashlib, hmac, json, os, re, secrets, time
from collections import defaultdict
import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from psycopg_pool import ConnectionPool
import stripe as _stripe
from fastapi import BackgroundTasks, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, Response

app = FastAPI(docs_url=None, redoc_url=None)

DATABASE_URL        = os.environ.get('DATABASE_URL', '')
ADMIN_PASS          = os.environ.get('ADMIN_PASS', 'Tort@Praha51')
# Without the env var the key is kept in the DB (see _init_tables), so admin
# sessions survive restarts and redeploys instead of expiring each time.
SECRET_KEY          = os.environ.get('SECRET_KEY', '') or secrets.token_hex(32)
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

_STATIC_IMG_BY_NAME = {
    'Cheesecake':              'https://imageproxy.wolt.com/assets/697228caf1232b338e039779',
    'Ořechový koláč':          'https://imageproxy.wolt.com/assets/697228caf1232b338e039778',
    'Pavlova':                 'https://imageproxy.wolt.com/assets/698343bca2c5decc0bfdcb6d',
    'Citronový koláč':         'https://imageproxy.wolt.com/assets/69997daf3eb3341f036ea0ae',
    'Citronový s malinami':    'https://imageproxy.wolt.com/assets/69de33ac73316796ef90e4cb',
    'Nanuk jahodový':          'https://imageproxy.wolt.com/assets/697992ef72674ce89f7a8f71',
    'Karamelový větrník':      'https://imageproxy.wolt.com/assets/697228caf1232b338e039783',
    'Borůvková tartaletka':    'https://imageproxy.wolt.com/assets/697228caf1232b338e03976f',
    'Kremrole':                'https://imageproxy.wolt.com/assets/697228caf1232b338e039773',
    'Malinová makronka':       'https://imageproxy.wolt.com/assets/697998f6aded7a30ce7db068',
    'Malinová tartaletka':     'https://imageproxy.wolt.com/assets/697228caf1232b338e039784',
    'Panna cotta':             'https://imageproxy.wolt.com/assets/69a1815dea4a83292ef03b2c',
    'Pistáciový mousse':       'https://imageproxy.wolt.com/assets/697228caf1232b338e039771',
    'Slaný karamel':           'https://imageproxy.wolt.com/assets/697228caf1232b338e039782',
    'Vanilkový věneček':       'https://imageproxy.wolt.com/assets/697228caf1232b338e039785',
    'Věneček s jahodami':      'https://imageproxy.wolt.com/assets/697228caf1232b338e03977f',
    'Nanuk višňový':           'https://imageproxy.wolt.com/assets/69799345520d609a024a691a',
    'Nanuk čokoládový':        'https://imageproxy.wolt.com/assets/6979924372674ce89f7a8f6d',
    'Nanuk banánový':          'https://imageproxy.wolt.com/assets/69799356a005afdf1964ffeb',
    'Nanuk pistáciový':        'https://imageproxy.wolt.com/assets/6979935e520d609a024a691c',
    'Capri-Sun':               'https://imageproxy.wolt.com/assets/697228caf1232b338e03977e',
}

def _init_tables():
    global SECRET_KEY
    with _pool.connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS orders (
                id BIGINT PRIMARY KEY, ts TEXT, name TEXT, phone TEXT,
                address TEXT, ord TEXT, payment TEXT, order_type TEXT,
                status TEXT DEFAULT 'new'
            )""")
        conn.execute("ALTER TABLE orders ADD COLUMN IF NOT EXISTS delivery_date TEXT DEFAULT ''")
        conn.execute("ALTER TABLE orders ADD COLUMN IF NOT EXISTS delivery_time TEXT DEFAULT ''")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS menu_items (
                id BIGINT PRIMARY KEY, data JSONB NOT NULL
            )""")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                key VARCHAR(100) PRIMARY KEY, value TEXT NOT NULL DEFAULT ''
            )""")
        if not os.environ.get('SECRET_KEY'):
            conn.execute("INSERT INTO settings(key,value) VALUES('secret_key',%s) ON CONFLICT(key) DO NOTHING",
                         (secrets.token_hex(32),))
            SECRET_KEY = conn.execute("SELECT value FROM settings WHERE key='secret_key'").fetchone()[0]
        # Backfill missing images for custom items that match a known static item
        rows = conn.execute("SELECT id, data FROM menu_items WHERE data->>'img' = '' OR data->>'img' IS NULL").fetchall()
        for row in rows:
            item = dict(row[1])
            name_cs = item.get('name', {}).get('cs', '')
            img_url = _STATIC_IMG_BY_NAME.get(name_cs)
            if img_url:
                item['img'] = img_url
                conn.execute('UPDATE menu_items SET data=%s WHERE id=%s', (Jsonb(item), row[0]))

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
    if req.url.path.startswith('/api/menu-img/'):
        pass  # set by the endpoint: long-lived, the URL changes when the photo does
    elif req.url.path.startswith('/api/'):
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
    ip = _get_ip(req)
    d  = await req.json()
    now = time.time()
    attempts = [t for t in _fail_log.get(ip, []) if now - t < 900]
    if attempts:
        _fail_log[ip] = attempts
    elif ip in _fail_log:
        del _fail_log[ip]
    if len(attempts) >= 5:
        raise HTTPException(429, 'Too many attempts. Try again in 15 minutes.')
    if hmac.compare_digest(str(d.get('pass') or ''), ADMIN_PASS):
        return {'token': _make_token()}
    attempts.append(now)
    _fail_log[ip] = attempts
    raise HTTPException(401, {'error': 'Invalid password', 'remaining': 5 - len(attempts)})

# ── /api/menu ─────────────────────────────────────────────────────────────────
# Photos uploaded in the admin are stored in the item as data: URIs. The menu
# returns a short URL for them instead, so the page doesn't download every photo
# inside one 5 MB JSON; ?v=<hash> changes whenever the photo changes.
_IMG_URL_RE = re.compile(r'^/api/menu-img/(\d+)')

def _public_item(item):
    img = item.get('img') or ''
    if not img.startswith('data:'):
        return item
    v = hashlib.sha1(img.encode()).hexdigest()[:10]
    return {**item, 'img': f"/api/menu-img/{item['id']}?v={v}"}

def _resolve_img(conn, img):
    """Turn a /api/menu-img/<id> URL sent back by the admin form into the stored photo."""
    m = _IMG_URL_RE.match(img or '')
    if not m:
        return (img or '').strip()
    row = conn.execute('SELECT data FROM menu_items WHERE id=%s', (int(m.group(1)),)).fetchone()
    return (row[0].get('img') or '') if row else ''

@app.get('/api/menu')
def api_menu_get(full: int = 0):
    with _get_pool().connection() as conn:
        rows = conn.execute('SELECT data FROM menu_items ORDER BY id ASC').fetchall()
    # full=1 keeps the photos inline (used by the admin JSON export / backup)
    return [r[0] if full else _public_item(r[0]) for r in rows]

@app.get('/api/menu-img/{item_id}')
def api_menu_img(item_id: int):
    with _get_pool().connection() as conn:
        row = conn.execute('SELECT data FROM menu_items WHERE id=%s', (item_id,)).fetchone()
    img = (row[0].get('img') or '') if row else ''
    m = re.match(r'^data:(image/[\w.+-]+);base64,(.*)$', img, re.S)
    if not m:
        raise HTTPException(404)
    return Response(base64.b64decode(m.group(2)), media_type=m.group(1),
                    headers={'Cache-Control': 'public, max-age=31536000, immutable'})

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
        'img':   '',
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
        'sizes':    [s for s in d.get('sizes', []) if s.get('label') and s.get('price')],
        'qty_ctrl': True if d.get('qty_ctrl') is True else (False if d.get('qty_ctrl') is False else None),
        'qty_min':  max(1, min(999, int(d['qty_min']))) if str(d.get('qty_min') or '').strip().isdigit() else 5,
        'img_pos':  (d.get('img_pos') or '').strip(),
        'weight':   (d.get('weight') or '').strip()[:30],
        'static_src_idx': int(d['static_src_idx']) if d.get('static_src_idx') is not None else None,
    }
    with _get_pool().connection() as conn:
        item['img'] = _resolve_img(conn, d.get('img'))
        conn.execute('INSERT INTO menu_items (id, data) VALUES (%s, %s)',
                     (item['id'], Jsonb(item)))
    return {'ok': True, 'item': _public_item(item)}

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
        for f in ('price', 'badge', 'cat'):
            if f in d:
                item[f] = (d[f] or '').strip()
        if 'img' in d:
            item['img'] = _resolve_img(conn, d['img'])
        if 'favorite' in d:
            item['favorite'] = bool(d['favorite'])
        if 'qty_ctrl' in d:
            val = d['qty_ctrl']
            item['qty_ctrl'] = True if val is True else (False if val is False else None)
        if 'qty_min' in d:
            raw = str(d['qty_min'] or '').strip()
            item['qty_min'] = max(1, min(999, int(raw))) if raw.isdigit() else 5
        if 'img_pos' in d:
            item['img_pos'] = (d['img_pos'] or '').strip()
        if 'weight' in d:
            item['weight'] = (d['weight'] or '').strip()[:30]
        if 'sizes' in d:
            raw = d['sizes'] if isinstance(d['sizes'], list) else []
            item['sizes'] = [s for s in raw if s.get('label') and s.get('price')]
        item.setdefault('name', {})
        item.setdefault('desc', {})
        for lng in ('cs', 'uk', 'en'):
            if f'name_{lng}' in d:
                item['name'][lng] = (d[f'name_{lng}'] or '').strip() or item['name'].get(lng, '')
            if f'desc_{lng}' in d:
                item['desc'][lng] = (d[f'desc_{lng}'] or '').strip()
        conn.execute('UPDATE menu_items SET data=%s WHERE id=%s', (Jsonb(item), item_id))
    return {'ok': True, 'item': _public_item(item)}

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

@app.get('/api/hidden-statics')
def api_hidden_statics_get():
    with _get_pool().connection() as conn:
        row = conn.execute("SELECT value FROM settings WHERE key='hidden_statics'").fetchone()
        return {'hidden': _json.loads(row[0]) if row and row[0] else []}

@app.post('/api/hidden-statics')
async def api_hidden_statics_set(req: Request):
    d = await req.json()
    if not _verify_token(d.get('token')):
        raise HTTPException(401, 'Unauthorized')
    hidden = [int(x) for x in (d.get('hidden') or [])]
    with _get_pool().connection() as conn:
        conn.execute(
            "INSERT INTO settings(key,value) VALUES('hidden_statics',%s) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value",
            (_json.dumps(hidden),)
        )
    return {'ok': True}

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

# ── Web Push ─────────────────────────────────────────────────────────────────
def _get_vapid_keys():
    """Return (private_pem, public_b64url). Auto-generates on first call."""
    with _get_pool().connection() as conn:
        priv = conn.execute("SELECT value FROM settings WHERE key='vapid_private_key'").fetchone()
        pub  = conn.execute("SELECT value FROM settings WHERE key='vapid_public_key'").fetchone()
        if priv and pub:
            return priv[0], pub[0]
    # Generate new VAPID key pair (EC P-256)
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization
    key = ec.generate_private_key(ec.SECP256R1())
    priv_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()
    ).decode()
    pub_raw = key.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint
    )
    pub_b64 = base64.urlsafe_b64encode(pub_raw).rstrip(b'=').decode()
    with _get_pool().connection() as conn:
        conn.execute(
            "INSERT INTO settings(key,value) VALUES('vapid_private_key',%s) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value",
            (priv_pem,)
        )
        conn.execute(
            "INSERT INTO settings(key,value) VALUES('vapid_public_key',%s) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value",
            (pub_b64,)
        )
    return priv_pem, pub_b64

def _send_push_notifications(payload_dict: dict, subs: list = None):
    import sys
    try:
        from pywebpush import webpush, WebPushException
    except ImportError as e:
        print(f'[PUSH] pywebpush not installed: {e}', file=sys.stderr)
        return
    try:
        priv_pem, _ = _get_vapid_keys()
        if subs is None:
            with _get_pool().connection() as conn:
                row = conn.execute("SELECT value FROM settings WHERE key='push_subscriptions'").fetchone()
                subs = _json.loads(row[0]) if row and row[0] else []
        if not subs:
            print('[PUSH] No subscribers', file=sys.stderr)
            return
        payload = _json.dumps(payload_dict)
        print(f'[PUSH] Sending to {len(subs)} subscriber(s)', file=sys.stderr)
        dead = []
        for sub in subs:
            try:
                webpush(
                    subscription_info=sub,
                    data=payload,
                    vapid_private_key=priv_pem,
                    vapid_claims={'sub': 'mailto:cakeme.cukrarna@seznam.cz'}
                )
            except WebPushException as e:
                print(f'[PUSH] WebPushException: {e} status={getattr(e.response,"status_code",None)}', file=sys.stderr)
                if e.response is not None and e.response.status_code in (404, 410):
                    dead.append(sub.get('endpoint'))
            except Exception as e:
                print(f'[PUSH] Error sending push: {e}', file=sys.stderr)
        if dead:
            subs = [s for s in subs if s.get('endpoint') not in dead]
            with _get_pool().connection() as conn:
                conn.execute(
                    "INSERT INTO settings(key,value) VALUES('push_subscriptions',%s) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value",
                    (_json.dumps(subs),)
                )
            print(f'[PUSH] Removed {len(dead)} dead subscription(s)', file=sys.stderr)
    except Exception as e:
        print(f'[PUSH] Fatal error: {e}', file=sys.stderr)

@app.get('/api/push/vapid-key')
def api_push_vapid_key():
    _, pub = _get_vapid_keys()
    return {'publicKey': pub}

@app.post('/api/push/subscribe')
async def api_push_subscribe(req: Request):
    d = await req.json()
    if not _verify_token(d.get('token')):
        raise HTTPException(401, 'Unauthorized')
    sub = d.get('subscription')
    if not sub or not sub.get('endpoint'):
        raise HTTPException(400, 'Bad subscription')
    with _get_pool().connection() as conn:
        row = conn.execute("SELECT value FROM settings WHERE key='push_subscriptions'").fetchone()
        subs = _json.loads(row[0]) if row and row[0] else []
        subs = [s for s in subs if s.get('endpoint') != sub['endpoint']]
        subs.append(sub)
        conn.execute(
            "INSERT INTO settings(key,value) VALUES('push_subscriptions',%s) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value",
            (_json.dumps(subs),)
        )
    return {'ok': True}

@app.post('/api/push/unsubscribe')
async def api_push_unsubscribe(req: Request):
    d = await req.json()
    if not _verify_token(d.get('token')):
        raise HTTPException(401, 'Unauthorized')
    endpoint = d.get('endpoint')
    if not endpoint:
        raise HTTPException(400, 'Missing endpoint')
    with _get_pool().connection() as conn:
        row = conn.execute("SELECT value FROM settings WHERE key='push_subscriptions'").fetchone()
        subs = _json.loads(row[0]) if row and row[0] else []
        subs = [s for s in subs if s.get('endpoint') != endpoint]
        conn.execute(
            "INSERT INTO settings(key,value) VALUES('push_subscriptions',%s) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value",
            (_json.dumps(subs),)
        )
    return {'ok': True}

@app.post('/api/push/test')
async def api_push_test(req: Request, bg: BackgroundTasks):
    d = await req.json()
    if not _verify_token(d.get('token')):
        raise HTTPException(401, 'Unauthorized')
    with _get_pool().connection() as conn:
        row = conn.execute("SELECT value FROM settings WHERE key='push_subscriptions'").fetchone()
        subs = _json.loads(row[0]) if row and row[0] else []
    bg.add_task(_send_ntfy, {
        'name': 'TEST', 'phone': '', 'order': 'Testovaci zprava — notifikace fungují!'
    })
    if not subs:
        return {'ok': True, 'subscribers': 0, 'note': 'ntfy sent, no web-push subscribers'}
    bg.add_task(_send_push_notifications, {
        'title': 'Test notifikace ✅',
        'body':  'Push notifikace fungují správně!',
        'url':   '/admin.html'
    }, subs)
    return {'ok': True, 'subscribers': len(subs)}

# ── ntfy.sh notifications ────────────────────────────────────────────────────
def _get_ntfy_topic() -> str:
    with _get_pool().connection() as conn:
        row = conn.execute("SELECT value FROM settings WHERE key='ntfy_topic'").fetchone()
        if row and row[0]:
            return row[0]
    topic = 'cakeme-' + secrets.token_urlsafe(20)
    with _get_pool().connection() as conn:
        conn.execute(
            "INSERT INTO settings(key,value) VALUES('ntfy_topic',%s) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value",
            (topic,)
        )
    import sys
    print(f'[NTFY] Generated new topic: {topic}', file=sys.stderr)
    return topic

def _send_ntfy(order: dict):
    import sys, urllib.request, urllib.error
    try:
        topic = _get_ntfy_topic()
        name  = (order.get('name') or '').strip()
        items = (order.get('order') or '').strip()[:120]
        phone = (order.get('phone') or '').strip()
        date  = (order.get('delivery_date') or '').strip()
        time_ = (order.get('delivery_time') or '').strip()
        dt    = f"{date} {time_}".strip()
        date_line = f"\nDatum: {dt}" if dt else ''
        body  = f"{name} | {phone}{date_line}\n{items}".strip().encode('utf-8')
        req   = urllib.request.Request(
            f'https://ntfy.sh/{topic}',
            data=body,
            headers={
                'Title':        'Nova objednavka! Cukrarna CakeMe',
                'Priority':     'urgent',
                'Tags':         'bell,cake',
                'Content-Type': 'text/plain; charset=utf-8',
            },
            method='POST'
        )
        urllib.request.urlopen(req, timeout=8)
        print(f'[NTFY] Sent for order: {name}', file=sys.stderr)
    except Exception as e:
        print(f'[NTFY] Error: {e}', file=sys.stderr)

def _send_telegram(order: dict):
    import sys, urllib.request, urllib.parse, urllib.error
    token    = os.environ.get('TELEGRAM_TOKEN', '')
    chat_ids = [c.strip() for c in os.environ.get('TELEGRAM_CHAT_ID', '').split(',') if c.strip()]
    if not token or not chat_ids:
        return
    try:
        name  = (order.get('name') or '').strip()
        phone = (order.get('phone') or '').strip()
        items = (order.get('order') or '').strip()
        date  = (order.get('delivery_date') or '').strip()
        time_ = (order.get('delivery_time') or '').strip()
        dt    = f"{date} {time_}".strip()
        lines = ['🎂 Nová objednávka! Cukrárna CakeMe', f'Jméno: {name}', f'Telefon: {phone}']
        if dt:
            lines.append(f'Datum: {dt}')
        if items:
            lines.append(f'Objednávka: {items}')
        if order.get('address'):
            lines.append(f"Adresa: {order['address']}")
        if order.get('payment'):
            lines.append(f"Platba: {order['payment']}")
        text = '\n'.join(lines)[:4000]  # Telegram rejects messages over 4096 chars
    except Exception as e:
        print(f'[TG] Error: {e}', file=sys.stderr)
        return
    # One failing chat (bot blocked, wrong id) must not stop the others
    for chat_id in chat_ids:
        try:
            body = urllib.parse.urlencode({'chat_id': chat_id, 'text': text}).encode()
            req  = urllib.request.Request(
                f'https://api.telegram.org/bot{token}/sendMessage',
                data=body, method='POST'
            )
            urllib.request.urlopen(req, timeout=8)
            print(f'[TG] Sent to {chat_id} for order: {name}', file=sys.stderr)
        except Exception as e:
            print(f'[TG] Error for chat {chat_id}: {e}', file=sys.stderr)

@app.post('/api/notif-info')
async def api_notif_info(req: Request):
    d = await req.json()
    if not _verify_token(d.get('token')):
        raise HTTPException(401, 'Unauthorized')
    topic = _get_ntfy_topic()
    return {'topic': topic, 'url': f'https://ntfy.sh/{topic}'}

# ── /api/categories ───────────────────────────────────────────────────────────
# Built-in sections (cakes, kolace, desserts, doplnky) can be renamed or hidden:
# 'builtin' maps id -> {'label': new name or '', 'hidden': bool}
_BUILTIN_CAT_IDS = ('all', 'cakes', 'kolace', 'desserts', 'doplnky', 'fav', 'celebration')

@app.get('/api/categories')
def api_categories_get():
    with _get_pool().connection() as conn:
        row = conn.execute("SELECT value FROM settings WHERE key='custom_categories'").fetchone()
        brow = conn.execute("SELECT value FROM settings WHERE key='builtin_categories'").fetchone()
        return {'categories': _json.loads(row[0]) if row and row[0] else [],
                'builtin': _json.loads(brow[0]) if brow and brow[0] else {}}

@app.post('/api/categories')
async def api_categories_set(req: Request):
    d = await req.json()
    if not _verify_token(d.get('token')):
        raise HTTPException(401, 'Unauthorized')
    cats = [{'id': c['id'], 'label': c['label']} for c in (d.get('categories') or []) if c.get('id') and c.get('label')]
    with _get_pool().connection() as conn:
        conn.execute(
            "INSERT INTO settings(key,value) VALUES('custom_categories',%s) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value",
            (_json.dumps(cats),)
        )
        if isinstance(d.get('builtin'), dict):
            builtin = {}
            for cid in _BUILTIN_CAT_IDS:
                b = d['builtin'].get(cid) or {}
                label = str(b.get('label') or '').strip()[:60]
                if label or b.get('hidden'):
                    builtin[cid] = {'label': label, 'hidden': bool(b.get('hidden'))}
            conn.execute(
                "INSERT INTO settings(key,value) VALUES('builtin_categories',%s) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value",
                (_json.dumps(builtin),)
            )
    return {'ok': True}

# ── /api/menu-layout ──────────────────────────────────────────────────────────
# Item keys: 's:<static index>' for items built into menu.html, 'c:<id>' for DB items.
_POPULAR_MODES = ('auto', 'manual', 'off')

def _clean_keys(raw, limit):
    out = []
    for k in (raw if isinstance(raw, list) else [])[:limit]:
        k = str(k).strip()[:64]
        if k and k not in out:
            out.append(k)
    return out

# Shown in "Doporučujeme" until the admin saves their own list ('Vánoční cukroví')
_DEFAULT_FEATURED = ['c:1790338678888']

def _default_layout():
    return {'order': [], 'cats': [], 'featured': list(_DEFAULT_FEATURED),
            'popular': {'mode': 'auto', 'count': 8, 'pinned': [], 'excluded': []}}

@app.get('/api/menu-layout')
def api_menu_layout_get():
    with _get_pool().connection() as conn:
        row = conn.execute("SELECT value FROM settings WHERE key='menu_layout'").fetchone()
    layout = _default_layout()
    if row and row[0]:
        saved = _json.loads(row[0])
        layout.update({k: v for k, v in saved.items() if k in ('order', 'cats', 'featured')})
        layout['popular'].update(saved.get('popular') or {})
    return layout

@app.post('/api/menu-layout')
async def api_menu_layout_set(req: Request):
    d = await req.json()
    if not _verify_token(d.get('token')):
        raise HTTPException(401, 'Unauthorized')
    pop = d.get('popular') or {}
    mode = pop.get('mode') if pop.get('mode') in _POPULAR_MODES else 'auto'
    try:
        count = max(1, min(24, int(pop.get('count') or 8)))
    except (TypeError, ValueError):
        count = 8
    layout = {
        'order': _clean_keys(d.get('order'), 2000),
        'cats':  _clean_keys(d.get('cats'), 100),
        # An admin page opened before this field existed doesn't send it; keep what's saved
        'featured': _clean_keys(d['featured'], 24) if 'featured' in d else api_menu_layout_get()['featured'],
        'popular': {'mode': mode, 'count': count, 'pinned': _clean_keys(pop.get('pinned'), 24),
                    # Items the admin removed from the strip; auto-fill skips them
                    'excluded': _clean_keys(pop.get('excluded'), 500)},
    }
    with _get_pool().connection() as conn:
        conn.execute(
            "INSERT INTO settings(key,value) VALUES('menu_layout',%s) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value",
            (_json.dumps(layout),)
        )
    return {'ok': True}

# ── /api/popular ──────────────────────────────────────────────────────────────
# Public: only item names and ordered quantities from the last 90 days, no customer data.
_ORDER_LINE_RE = re.compile(r'^(.+?)(?:\s+\([^)]*\))?\s+x(\d+)(?:\s+\(\d[\d\s]*Kč\))?$')

@app.get('/api/popular')
def api_popular():
    cutoff = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(time.time() - 90 * 86400))
    with _get_pool().connection() as conn:
        rows = conn.execute(
            "SELECT ord FROM orders WHERE ts >= %s AND status <> 'pending_payment'", (cutoff,)
        ).fetchall()
    counts = defaultdict(int)
    for (ord_text,) in rows:
        for part in (ord_text or '').split('|')[0].split(','):
            m = _ORDER_LINE_RE.match(part.strip())
            if m:
                counts[m.group(1).strip()] += int(m.group(2))
    top = sorted(counts.items(), key=lambda kv: -kv[1])[:50]
    return {'items': [{'name': n, 'qty': q} for n, q in top]}

# ── /api/order ────────────────────────────────────────────────────────────────
# Orders come from a public form: cap field sizes so nobody can push megabytes
# into the DB and the Telegram/ntfy notifications.
_ORDER_LIMITS = {'name': 120, 'phone': 40, 'address': 400, 'order': 4000, 'payment': 60,
                 'order_type': 40, 'delivery_date': 20, 'delivery_time': 20}

def _clip_order(order):
    for k, limit in _ORDER_LIMITS.items():
        order[k] = str(order.get(k) or '')[:limit]

@app.post('/api/order')
async def api_order(req: Request, bg: BackgroundTasks):
    d = await req.json()
    order = {
        'id':            int(time.time() * 1000),
        'ts':            time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'name':          (d.get('name')          or '').strip(),
        'phone':         (d.get('phone')         or '').strip(),
        'address':       (d.get('address')       or '').strip(),
        'order':         (d.get('order')         or '').strip(),
        'payment':       (d.get('payment')       or '').strip(),
        'order_type':    (d.get('order_type')    or '').strip(),
        'delivery_date': (d.get('delivery_date') or '').strip(),
        'delivery_time': (d.get('delivery_time') or '').strip(),
        'status':        'new',
    }
    _clip_order(order)
    with _get_pool().connection() as conn:
        conn.execute(
            'INSERT INTO orders (id,ts,name,phone,address,ord,payment,order_type,delivery_date,delivery_time,status)'
            ' VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)',
            (order['id'], order['ts'], order['name'], order['phone'],
             order['address'], order['order'], order['payment'],
             order['order_type'], order['delivery_date'], order['delivery_time'], order['status'])
        )
    bg.add_task(_send_ntfy, order)
    bg.add_task(_send_telegram, order)
    bg.add_task(_send_push_notifications, {
        'title': 'Nová objednávka! 🎂',
        'body':  f"{order['name']} — {(order['order'] or '')[:80]}",
        'url':   '/admin.html'
    })
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
                'payment,order_type,delivery_date,delivery_time,status FROM orders ORDER BY id DESC'
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
        'name':          (d.get('name')          or '').strip(),
        'phone':         (d.get('phone')         or '').strip(),
        'address':       (d.get('address')       or '').strip(),
        'order':         (d.get('order')         or '').strip(),
        'payment':       'online',
        'order_type':    (d.get('order_type')    or '').strip(),
        'delivery_date': (d.get('delivery_date') or '').strip(),
        'delivery_time': (d.get('delivery_time') or '').strip(),
        'status':        'pending_payment',
    }
    _clip_order(order)
    with _get_pool().connection() as conn:
        conn.execute(
            'INSERT INTO orders (id,ts,name,phone,address,ord,payment,order_type,delivery_date,delivery_time,status)'
            ' VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)',
            (order['id'], order['ts'], order['name'], order['phone'],
             order['address'], order['order'], order['payment'],
             order['order_type'], order['delivery_date'], order['delivery_time'], order['status'])
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
async def api_verify_payment(session_id: str, order_id: int, bg: BackgroundTasks):
    if not STRIPE_SECRET_KEY:
        raise HTTPException(503, 'Stripe not configured')
    try:
        session = _stripe.checkout.Session.retrieve(session_id)
    except Exception:
        raise HTTPException(400, 'Invalid session')
    if (session.payment_status == 'paid'
            and str(session.metadata.get('order_id')) == str(order_id)):
        with _get_pool().connection() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    'UPDATE orders SET status=%s WHERE id=%s AND status=%s'
                    ' RETURNING id,ts,name,phone,address,ord AS "order",'
                    'payment,order_type,delivery_date,delivery_time',
                    ('paid', order_id, 'pending_payment')
                )
                row = cur.fetchone()
        if row:
            bg.add_task(_send_ntfy, row)
            bg.add_task(_send_telegram, row)
            bg.add_task(_send_push_notifications, {
                'title': 'Nová objednávka (zaplaceno) 🎂',
                'body':  f"{row['name']} — {(row['order'] or '')[:80]}",
                'url':   '/admin.html'
            })
        return {'paid': True}
    return {'paid': False}

# ── /api/order/{id} PATCH — allow 'paid' status for admin ────────────────────
# (override to extend valid statuses)

# ── /api/pageviews ────────────────────────────────────────────────────────────
@app.get('/api/pageviews')
def api_pageviews():
    with _get_pool().connection() as conn:
        row = conn.execute("SELECT value FROM settings WHERE key='pageviews_daily'").fetchone()
        return {'daily': _json.loads(row[0]) if row and row[0] else {}}

def _inc_pageviews():
    try:
        pool = _get_pool()
        if not pool:
            return
        today = time.strftime('%Y-%m-%d', time.gmtime())
        with pool.connection() as conn:
            row = conn.execute("SELECT value FROM settings WHERE key='pageviews_daily'").fetchone()
            data = _json.loads(row[0]) if row and row[0] else {}
            data[today] = data.get(today, 0) + 1
            cutoff = time.time() - 90 * 86400
            data = {k: v for k, v in data.items()
                    if time.mktime(time.strptime(k, '%Y-%m-%d')) >= cutoff}
            conn.execute(
                "INSERT INTO settings(key,value) VALUES('pageviews_daily',%s)"
                " ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value",
                (_json.dumps(data),)
            )
    except:
        pass

# ── Static files ──────────────────────────────────────────────────────────────
_BLOCKED = {
    'app.py', 'orders.json', 'custom_menu.json',
    'requirements.txt', 'Procfile', '.env', 'wsgi.py',
}

_NO_TRACK = {'admin.html', 'success.html', 'cancel.html'}

@app.get('/')
def _index():
    _inc_pageviews()
    return FileResponse('index.html')

@app.get('/success')
def _success():
    return FileResponse('success.html')

@app.get('/cancel')
def _cancel():
    return FileResponse('cancel.html')

# Only website assets are served; anything else in the app folder (code, __pycache__,
# config files) stays private even if it isn't listed in _BLOCKED.
_STATIC_EXT = {'.html', '.js', '.css', '.svg', '.webp', '.png', '.jpg', '.jpeg', '.gif', '.ico', '.woff', '.woff2'}

@app.get('/{path:path}')
def _static(path: str):
    norm = os.path.normpath(path).replace(os.sep, '/')
    if (norm.startswith('..') or os.path.isabs(norm) or norm in _BLOCKED
            or any(part.startswith(('.', '_')) for part in norm.split('/'))
            or os.path.splitext(norm)[1].lower() not in _STATIC_EXT):
        raise HTTPException(404)
    if os.path.isfile(norm):
        if norm.endswith('.html') and norm not in _NO_TRACK:
            _inc_pageviews()
        return FileResponse(norm)
    raise HTTPException(404)

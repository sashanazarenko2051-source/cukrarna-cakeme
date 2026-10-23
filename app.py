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

# Ukrainian/English texts for items and sections added in the admin panel (translations.json).
# Used only where the item has no own translation (missing or same as Czech).
def _load_translations():
    try:
        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'translations.json'), encoding='utf-8') as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}

_TR = _load_translations()
_TR_PHRASES = {p['cs']: p for p in _TR.get('phrases', []) if p.get('cs')}

def _translate(item):
    tr = _TR.get('items', {}).get(str(item.get('id')), {})
    out = {**item, 'name': dict(item.get('name') or {}), 'desc': dict(item.get('desc') or {})}
    for field in ('name', 'desc'):
        cs = out[field].get('cs', '')
        stale = set((tr.get(field) or {}).get('replace') or [])  # Czech text once saved as a "translation"
        for lang in ('uk', 'en'):
            cur = out[field].get(lang, '')
            if cur and cur != cs and cur not in stale:
                continue
            new = (tr.get(field) or {}).get(lang) or (_TR_PHRASES.get(cs) or {}).get(lang)
            if new:
                out[field][lang] = new
    return out

def _public_item(item):
    item = _translate(item)
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

# ── /api/translate ────────────────────────────────────────────────────────────
# Draft UA/EN translation of a Czech menu text for the admin form. The admin sees
# it in the form and can fix it before saving (short names are often mistranslated).
def _gtranslate(text, target):
    import urllib.request, urllib.parse
    url = ('https://translate.googleapis.com/translate_a/single?client=gtx&sl=cs&tl=%s&dt=t&q=%s'
           % (target, urllib.parse.quote(text)))
    try:
        data = json.loads(urllib.request.urlopen(url, timeout=6).read().decode('utf-8'))
        return ''.join(seg[0] for seg in data[0] if seg and seg[0]).strip()
    except Exception:
        return ''

@app.post('/api/translate')
async def api_translate(req: Request):
    from starlette.concurrency import run_in_threadpool
    d = await req.json()
    if not _verify_token(d.get('token')):
        raise HTTPException(401, 'Unauthorized')
    text = str(d.get('text') or '').strip()[:3000]
    if not text:
        return {'uk': '', 'en': ''}
    uk = await run_in_threadpool(_gtranslate, text, 'uk')
    en = await run_in_threadpool(_gtranslate, text, 'en')
    return {'uk': uk, 'en': en}

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
        cats = _json.loads(row[0]) if row and row[0] else []
        builtin = _json.loads(brow[0]) if brow and brow[0] else {}
    # Section names per language: label (Czech), label_uk, label_en; fill gaps from translations.json
    for c in cats:
        tr = _TR.get('categories', {}).get(c.get('id'), {})
        for lang in ('uk', 'en'):
            if not c.get('label_' + lang) and tr.get(lang):
                c['label_' + lang] = tr[lang]
    return {'categories': cats, 'builtin': builtin}

@app.post('/api/categories')
async def api_categories_set(req: Request):
    d = await req.json()
    if not _verify_token(d.get('token')):
        raise HTTPException(401, 'Unauthorized')
    def _labels(c):
        return {k: str(c.get(k) or '').strip()[:60] for k in ('label', 'label_uk', 'label_en') if str(c.get(k) or '').strip()}
    cats = [{'id': c['id'], **_labels(c)} for c in (d.get('categories') or []) if c.get('id') and c.get('label')]
    with _get_pool().connection() as conn:
        conn.execute(
            "INSERT INTO settings(key,value) VALUES('custom_categories',%s) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value",
            (_json.dumps(cats),)
        )
        if isinstance(d.get('builtin'), dict):
            builtin = {}
            for cid in _BUILTIN_CAT_IDS:
                b = d['builtin'].get(cid) or {}
                labels = _labels(b)
                if labels or b.get('hidden'):
                    builtin[cid] = {**labels, 'hidden': bool(b.get('hidden'))}
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

# ── Server-side prices ────────────────────────────────────────────────────────
# The cart in the browser can't be trusted for the amount charged online, so the
# server prices every line itself: built-in items are read from menu.html (the
# same list the menu page shows), admin-added items from the DB.
def _lead_int(v):
    """Leading integer like JS parseInt: '97 Kč' -> 97, 800 -> 800, 'abc' -> None."""
    m = re.match(r'\s*(\d+)', str(v if v is not None else ''))
    return int(m.group(1)) if m else None

def _load_static_items():
    try:
        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'menu.html'), encoding='utf-8') as f:
            src = f.read()
        block = src[src.index('let ITEMS=['):]
        block = block[:block.index('\n];')]
    except (OSError, ValueError):
        return []
    items = []
    for cat, body, name in re.findall(r"\{cat:'([^']*)'(.*?)name:\{cs:'([^']*)'", block, re.S):
        sizes = [{'label': l, 'price': int(p)} for l, p in re.findall(r"\{label:'([^']*)',price:(\d+)\}", body)]
        price = re.search(r"price:'([^']*)'", body)
        items.append({'cat': cat, 'name': name, 'sizes': sizes, 'price': price.group(1) if price else ''})
    return items

_STATIC_ITEMS = _load_static_items()

def _price_catalog(conn):
    """(Czech name, size label) -> set of valid unit prices for everything currently on the menu."""
    catalog = defaultdict(set)
    def add(name, sizes, price):
        if sizes:
            for s in sizes:
                p = _lead_int(s.get('price'))
                if p:
                    catalog[(name, str(s.get('label') or ''))].add(p)
        elif _lead_int(price):
            catalog[(name, '')].add(_lead_int(price))
    custom = [r[0] for r in conn.execute('SELECT data FROM menu_items ORDER BY id ASC').fetchall()]
    row = conn.execute("SELECT value FROM settings WHERE key='hidden_statics'").fetchone()
    hidden = set(_json.loads(row[0])) if row and row[0] else set()
    custom_names = {(i.get('name') or {}).get('cs') for i in custom}
    replaced = {i.get('static_src_idx') for i in custom if i.get('static_src_idx') is not None}
    # Same rule as menu.html: a built-in item replaced by an admin copy (same name) is not on sale
    for idx, it in enumerate(_STATIC_ITEMS):
        if idx in hidden or idx in replaced or it['name'] in custom_names:
            continue
        add(it['name'], it['sizes'], it['price'])
    for it in custom:
        add((it.get('name') or {}).get('cs', ''), it.get('sizes') or [], it.get('price'))
    return catalog

def _price_cart(conn, cart):
    """Price cart lines [{name, size, qty, price}] on the server.
    Returns (lines, total, unknown_names); the client's price only picks between
    duplicates that share a name, it never sets the amount."""
    catalog = _price_catalog(conn)
    lines, total, unknown = [], 0, []
    for c in cart if isinstance(cart, list) else []:
        if not isinstance(c, dict):
            continue
        name, size = str(c.get('name') or '').strip(), str(c.get('size') or '').strip()
        qty = _lead_int(c.get('qty')) or 0
        if qty < 1:
            continue
        valid = catalog.get((name, size))
        if not valid:
            unknown.append(name + (f' ({size})' if size else ''))
            continue
        unit = _lead_int(c.get('price'))
        if unit not in valid:
            unit = max(valid)
        qty = min(qty, 999)
        lines.append(f"{name}{f' ({size})' if size else ''} x{qty} ({unit * qty} Kč)")
        total += unit * qty
    return lines, total, unknown

def _priced_order_text(lines, total):
    return ', '.join(lines) + f' | Celkem: {total} Kč'

# ── Delivery/pickup slots ─────────────────────────────────────────────────────
# Customers pick a day within the next `days_ahead` days (2 months) and a time
# interval with free capacity. Capacity is counted from existing orders, so no
# separate bookings table is needed. Closed days older than 2 months are dropped.
import datetime as _dt
try:
    from zoneinfo import ZoneInfo
    _TZ = ZoneInfo('Europe/Prague')
except Exception:
    _TZ = _dt.timezone(_dt.timedelta(hours=1))

_SLOT_DEFAULT = {
    'enabled': True,
    'days_ahead': 60,       # how far ahead customers can book (2 months)
    'min_lead_days': 1,     # earliest day: tomorrow
    'weekdays': [0, 1, 2, 3, 4, 5, 6],  # Mon=0 … Sun=6
    'times': ['09:00-11:00', '11:00-13:00', '13:00-15:00', '15:00-17:00', '17:00-20:00'],
    'per_slot': 3,          # orders per interval
    'per_day': 12,          # orders per day
    'closed': [],           # YYYY-MM-DD days off
}
_SLOT_KEEP_DAYS = 60        # closed days and the admin schedule go 2 months back
_TIME_RE = re.compile(r'^([01]\d|2[0-3]):[0-5]\d-([01]\d|2[0-3]):[0-5]\d$')
_DATE_RE = re.compile(r'^\d{4}-\d{2}-\d{2}$')

def _today():
    return _dt.datetime.now(_TZ).date()

def _clean_slot_cfg(raw):
    cfg = dict(_SLOT_DEFAULT)
    raw = raw if isinstance(raw, dict) else {}
    num = lambda v, lo, hi, dflt: max(lo, min(hi, _lead_int(v))) if _lead_int(v) is not None else dflt
    cfg['enabled'] = bool(raw.get('enabled', cfg['enabled']))
    cfg['days_ahead'] = num(raw.get('days_ahead'), 1, 180, cfg['days_ahead'])
    cfg['min_lead_days'] = num(raw.get('min_lead_days'), 0, 60, cfg['min_lead_days'])
    cfg['per_slot'] = num(raw.get('per_slot'), 1, 500, cfg['per_slot'])
    cfg['per_day'] = num(raw.get('per_day'), 1, 2000, cfg['per_day'])
    if isinstance(raw.get('weekdays'), list):
        cfg['weekdays'] = sorted({int(w) for w in raw['weekdays'] if str(w).isdigit() and 0 <= int(w) <= 6})
    if isinstance(raw.get('times'), list):
        times = [str(t).replace(' ', '').replace('–', '-') for t in raw['times']]
        cfg['times'] = sorted({t for t in times if _TIME_RE.match(t) and t[:5] < t[6:]})[:24]
    oldest = (_today() - _dt.timedelta(days=_SLOT_KEEP_DAYS)).isoformat()
    cfg['closed'] = sorted({str(c) for c in (raw.get('closed') or []) if _DATE_RE.match(str(c)) and str(c) >= oldest})
    return cfg

def _slot_cfg(conn):
    row = conn.execute("SELECT value FROM settings WHERE key='slot_config'").fetchone()
    return _clean_slot_cfg(_json.loads(row[0]) if row and row[0] else {})

def _slot_counts(conn, start, end):
    """Orders per (date, time) and per date between start and end (ISO dates).
    Unpaid online orders hold their place for 30 minutes, then free it."""
    rows = conn.execute(
        'SELECT delivery_date, delivery_time, status, ts FROM orders WHERE delivery_date >= %s AND delivery_date <= %s',
        (start, end)).fetchall()
    stale = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(time.time() - 1800))
    by_slot, by_day = defaultdict(int), defaultdict(int)
    for date, tm, status, ts in rows:
        if status == 'pending_payment' and (ts or '') < stale:
            continue
        by_slot[(date, tm)] += 1
        by_day[date] += 1
    return by_slot, by_day

def _slot_days(conn, cfg):
    """Bookable days from the earliest allowed date up to days_ahead, with free places."""
    today = _today()
    first = today + _dt.timedelta(days=cfg['min_lead_days'])
    last = today + _dt.timedelta(days=cfg['days_ahead'])
    by_slot, by_day = _slot_counts(conn, first.isoformat(), last.isoformat())
    now_hm = _dt.datetime.now(_TZ).strftime('%H:%M')
    days, d = [], first
    while d <= last:
        iso = d.isoformat()
        open_day = d.weekday() in cfg['weekdays'] and iso not in cfg['closed']
        day_left = max(0, cfg['per_day'] - by_day[iso])
        slots = []
        if open_day:
            for tm in cfg['times']:
                if d == today and tm[:5] <= now_hm:
                    continue  # interval already started today
                slots.append({'time': tm, 'left': min(day_left, max(0, cfg['per_slot'] - by_slot[(iso, tm)]))})
        days.append({'date': iso, 'open': open_day and day_left > 0 and any(s['left'] for s in slots), 'slots': slots})
        d += _dt.timedelta(days=1)
    return days

def _check_slot(conn, date, tm):
    """None if the order may take this date/time, otherwise an error code."""
    cfg = _slot_cfg(conn)
    if not cfg['enabled']:
        return None
    day = next((x for x in _slot_days(conn, cfg) if x['date'] == date), None)
    if not day or not day['open']:
        return 'slot_unavailable'
    slot = next((s for s in day['slots'] if s['time'] == tm), None)
    if not slot or slot['left'] < 1:
        return 'slot_full'
    return None

@app.get('/api/slots')
def api_slots():
    with _get_pool().connection() as conn:
        cfg = _slot_cfg(conn)
        if not cfg['enabled']:
            return {'enabled': False, 'days': []}
        return {'enabled': True, 'days': _slot_days(conn, cfg)}

@app.get('/api/slot-config')
def api_slot_config_get():
    with _get_pool().connection() as conn:
        return {**_slot_cfg(conn), 'keep_days': _SLOT_KEEP_DAYS}

@app.post('/api/slot-config')
async def api_slot_config_set(req: Request):
    d = await req.json()
    if not _verify_token(d.get('token')):
        raise HTTPException(401, 'Unauthorized')
    cfg = _clean_slot_cfg(d.get('config'))
    with _get_pool().connection() as conn:
        conn.execute(
            "INSERT INTO settings(key,value) VALUES('slot_config',%s) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value",
            (_json.dumps(cfg),)
        )
    return {'ok': True, 'config': cfg}

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
    with _get_pool().connection() as conn:
        err = _check_slot(conn, order['delivery_date'], order['delivery_time'])
        if err:
            raise HTTPException(409, {'error': err})
        # Pay-on-delivery: use server prices when every line is known, otherwise keep
        # the customer's text so the order still arrives (staff check it anyway)
        if d.get('cart'):
            lines, total, unknown = _price_cart(conn, d['cart'])
            if lines and not unknown:
                order['order'] = _priced_order_text(lines, total)
        _clip_order(order)
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
    # The amount comes from server prices, never from the browser's total_czk
    with _get_pool().connection() as conn:
        lines, total_czk, unknown = _price_cart(conn, d.get('cart'))
        slot_err = _check_slot(conn, (d.get('delivery_date') or '').strip(), (d.get('delivery_time') or '').strip())
    if slot_err:
        raise HTTPException(409, {'error': slot_err})
    if unknown:
        raise HTTPException(409, {'error': 'unknown_items', 'items': unknown})
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
        'order':         _priced_order_text(lines, total_czk),
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
        _mark_paid(order_id, bg)
        return {'paid': True}
    return {'paid': False}

def _mark_paid(order_id, bg):
    """pending_payment -> paid and notify. Runs once per order, whichever comes
    first: the customer's return to /success or Stripe's webhook."""
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

# ── /api/stripe-webhook ───────────────────────────────────────────────────────
# Stripe calls this when a payment completes, so a paid order is confirmed even if
# the customer closes the browser before returning to /success. Needs the webhook's
# signing secret in the STRIPE_WEBHOOK_SECRET env var (Stripe dashboard -> Webhooks).
@app.post('/api/stripe-webhook')
async def api_stripe_webhook(req: Request, bg: BackgroundTasks):
    secret = os.environ.get('STRIPE_WEBHOOK_SECRET', '')
    if not STRIPE_SECRET_KEY or not secret:
        raise HTTPException(503, 'Stripe webhook not configured')
    payload = await req.body()
    try:
        _stripe.Webhook.construct_event(payload, req.headers.get('stripe-signature', ''), secret)
    except Exception:
        raise HTTPException(400, 'Invalid signature')
    # Signature checked; read the event as plain JSON (StripeObject API differs between library versions)
    event = json.loads(payload)
    if event.get('type') in ('checkout.session.completed', 'checkout.session.async_payment_succeeded'):
        session = event['data']['object']
        order_id = _lead_int((session.get('metadata') or {}).get('order_id'))
        if order_id and session.get('payment_status') == 'paid':
            _mark_paid(order_id, bg)
    return {'received': True}

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

import base64, hashlib, hmac, json, os, re, secrets, time
from collections import defaultdict
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
        # Example picture uploaded with a custom cake from the builder (data: URI)
        conn.execute("ALTER TABLE orders ADD COLUMN IF NOT EXISTS attachment TEXT DEFAULT ''")
        conn.execute("ALTER TABLE orders ADD COLUMN IF NOT EXISTS email TEXT DEFAULT ''")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS menu_items (
                id BIGINT PRIMARY KEY, data JSONB NOT NULL
            )""")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                key VARCHAR(100) PRIMARY KEY, value TEXT NOT NULL DEFAULT ''
            )""")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS reviews (
                id BIGINT PRIMARY KEY, ts TEXT, name TEXT, stars INT, body TEXT,
                item TEXT DEFAULT '', photo TEXT DEFAULT '', status TEXT DEFAULT 'new',
                verified BOOLEAN DEFAULT FALSE, reply TEXT DEFAULT ''
            )""")
        # Where a review came from when the admin moved it over from elsewhere (google, instagram…)
        conn.execute("ALTER TABLE reviews ADD COLUMN IF NOT EXISTS source TEXT DEFAULT ''")
        # Reviews are now published at once; ones still waiting from before go live too
        conn.execute("UPDATE reviews SET status='published' WHERE status='new'")
        # Customers who asked for a birthday reminder when ordering (opt-in)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS subscribers (
                email TEXT PRIMARY KEY, name TEXT DEFAULT '', bday TEXT NOT NULL, lang TEXT DEFAULT 'cs',
                token TEXT NOT NULL, created TEXT DEFAULT '', active BOOLEAN DEFAULT TRUE, last_sent_year INT DEFAULT 0
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
    if req.url.path.startswith(('/api/menu-img/', '/api/review-img/', '/api/builder-img/')):
        pass  # set by the endpoint: long-lived, the URL changes when the photo does
    elif req.url.path.startswith('/api/'):
        resp.headers['Cache-Control'] = 'no-store'
    elif any(t in resp.headers.get('content-type', '') for t in ('text/html', 'javascript', 'text/css')):
        # Pages and their scripts are re-checked every time (cheap 304 via ETag), so
        # visitors never get a new page with an old builder.js / reviews.js
        resp.headers['Cache-Control'] = 'no-cache, must-revalidate'
    _maybe_send_birthdays()  # once a day, on whatever request comes first
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
        items = [r[0] for r in rows]
        left = _stock_left(conn, items)
    # full=1 keeps the photos inline (used by the admin JSON export / backup)
    out = [i if full else _public_item(i) for i in items]
    return [{**i, 'stock_left': left[i['id']]} if i['id'] in left else i for i in out]

# ── Item rules: minimum notice, pickup window, limited quantity (pre-orders) ──
# lead_days  — earliest pickup/delivery is today + lead_days (e.g. 14 for big cakes)
# avail_from / avail_to — pickup only on these days (e.g. 20–23 December)
# stock_total — how many can be sold; sold pieces are counted from orders placed
#               since stock_since (reset whenever the admin changes stock_total)
def _apply_rules(item, d):
    if 'lead_days' in d:
        v = _lead_int(d['lead_days'])
        item['lead_days'] = max(0, min(120, v)) if v is not None else None
    for f in ('avail_from', 'avail_to'):
        if f in d:
            v = str(d[f] or '').strip()
            item[f] = v if _DATE_RE.match(v) else ''
    if 'stock_total' in d:
        v = _lead_int(d['stock_total'])
        v = max(0, min(100000, v)) if v is not None else None
        if v != item.get('stock_total') or not item.get('stock_since'):
            item['stock_since'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        item['stock_total'] = v

def _stock_left(conn, items):
    """{item id: pieces left} for items with a limited quantity."""
    limited = [i for i in items if i.get('stock_total') is not None]
    if not limited:
        return {}
    since = min(i.get('stock_since') or '' for i in limited)
    rows = conn.execute('SELECT ord, ts, status FROM orders WHERE ts >= %s', (since,)).fetchall()
    stale = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(time.time() - 1800))
    left = {}
    for it in limited:
        name, sold = (it.get('name') or {}).get('cs', ''), 0
        for ord_text, ts, status in rows:
            if (ts or '') < (it.get('stock_since') or '') or (status == 'pending_payment' and (ts or '') < stale):
                continue
            for part in (ord_text or '').split('|')[0].split(','):
                m = _ORDER_LINE_RE.match(part.strip())
                if m and m.group(1).strip() == name:
                    sold += int(m.group(2))
        left[it['id']] = max(0, it['stock_total'] - sold)
    return left

def _check_item_rules(conn, cart, date):
    """None if the cart can be ordered for this date, otherwise an error dict."""
    if not isinstance(cart, list) or not cart:
        return None
    if any(isinstance(c, dict) and c.get('builder') is not None for c in cart):
        earliest = (_today() + _dt.timedelta(days=_builder_cfg(conn)['lead_days'])).isoformat()
        if not date or date < earliest:
            return {'error': 'too_early', 'item': _BUILDER_NAME, 'earliest': earliest}
    items = [r[0] for r in conn.execute('SELECT data FROM menu_items ORDER BY id ASC').fetchall()]
    by_name = {}
    for it in items:
        if it.get('lead_days') or it.get('avail_from') or it.get('avail_to') or it.get('stock_total') is not None:
            by_name.setdefault((it.get('name') or {}).get('cs', ''), it)
    wanted = defaultdict(int)
    for c in cart:
        if isinstance(c, dict) and c.get('name') in by_name:
            wanted[c['name']] += _lead_int(c.get('qty')) or 0
    if not wanted:
        return None
    for name in wanted:
        it = by_name[name]
        if it.get('lead_days'):
            earliest = (_today() + _dt.timedelta(days=it['lead_days'])).isoformat()
            if not date or date < earliest:
                return {'error': 'too_early', 'item': name, 'earliest': earliest}
        if (it.get('avail_from') and (not date or date < it['avail_from'])) or \
           (it.get('avail_to') and (not date or date > it['avail_to'])):
            return {'error': 'outside_window', 'item': name, 'from': it.get('avail_from', ''), 'to': it.get('avail_to', '')}
    left = _stock_left(conn, list(by_name.values()))
    sold_out = [n for n, q in wanted.items() if by_name[n]['id'] in left and q > left[by_name[n]['id']]]
    if sold_out:
        return {'error': 'sold_out', 'items': sold_out, 'left': {n: left[by_name[n]['id']] for n in sold_out}}
    return None

# ── /api/translate ────────────────────────────────────────────────────────────
# Draft UA/EN translation of a Czech menu text for the admin form. The admin sees
# it in the form and can fix it before saving (short names are often mistranslated).
def _gtranslate(text, target, source='cs'):
    import urllib.request, urllib.parse
    url = ('https://translate.googleapis.com/translate_a/single?client=gtx&sl=%s&tl=%s&dt=t&q=%s'
           % (source, target, urllib.parse.quote(text)))
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
    if d.get('source') == 'auto':
        # Text written in any language (one description field): all three versions
        out = {}
        for lang in ('cs', 'uk', 'en'):
            out[lang] = await run_in_threadpool(_gtranslate, text, lang, 'auto') or text
        return out
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
    _apply_rules(item, d)
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
        _apply_rules(item, d)
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
    import sys
    try:
        text = _tg_order_text(order)
    except Exception as e:
        print(f'[TG] Error: {e}', file=sys.stderr)
        return
    _tg_send(text, f"order: {order.get('name') or ''}")

# The shop reads the notices in Ukrainian; the order itself may come in any site language
_TG_WD = ['пн', 'вт', 'ср', 'чт', 'пт', 'сб', 'нд']
_TG_LINE_RE = re.compile(r'(.+?) x(\d+) \((\d+) Kč\)(?:, |$)')

def _tg_order_kind(order):
    t = (order.get('order_type') or '').lower()
    addr = (order.get('address') or '').strip()
    if any(w in t for w in ('míst', 'eat', 'місці')) or re.match(r'^(Stůl|Table|Стіл)\b', addr):
        return '🍽 НА МІСЦІ — заздалегідь' if order.get('delivery_date') else '🍽 НА МІСЦІ — зараз'
    if any(w in t for w in ('odběr', 'pickup', 'самовив')):
        return '🏃 САМОВИВІЗ'
    if any(w in t for w in ('doruč', 'deliver', 'достав')):
        return '🚚 ДОСТАВКА'
    return '🛍 ЗАМОВЛЕННЯ'

def _tg_order_text(order):
    sep = '━━━━━━━━━━━━'
    name  = (order.get('name') or '').strip() or '—'
    phone = (order.get('phone') or '').strip()
    items = (order.get('order') or '').strip()
    date  = (order.get('delivery_date') or '').strip()
    tm    = (order.get('delivery_time') or '').strip().replace('-', '–')
    addr  = (order.get('address') or '').strip()
    pay   = (order.get('payment') or '').strip().lower()
    out = [f'🎂 НОВЕ ЗАМОВЛЕННЯ · {_tg_order_kind(order)}', sep, f'👤 {name}']
    if phone:
        out.append(f'📞 {phone}')
    if order.get('email'):
        out.append(f"✉️ {order['email']}")
    if date:
        try:
            d = _dt.date.fromisoformat(date)
            when = f'{_TG_WD[d.weekday()]}, {d.day:02d}.{d.month:02d}.{d.year}'
        except ValueError:
            when = date
        out.append(f"📅 {when}{' · ' + tm if tm else ''}")
    if items:
        out.append(sep)
        body, _, total = items.partition(' | Celkem:')
        lines = list(_TG_LINE_RE.finditer(body))
        if lines and ''.join(m.group(0) for m in lines) == body:
            out += [f'• {m.group(1)} × {m.group(2)} — {m.group(3)} Kč' for m in lines]
        else:
            out.append(body)
        if total.strip():
            out.append(f'💰 Разом: {total.strip()}')
    if addr:
        out.append(sep)
        place, _, link = addr.partition(' · 📍 ')
        out.append(('🪑 ' if re.match(r'^(Stůl|Table|Стіл)\b', place) else '📍 ') + place)
        if link:
            out.append(f'🗺 Карта для кур’єра: {link}')
    if pay:
        paid = order.get('status') == 'paid' or pay in ('online', 'card')
        out.append('💳 Оплачено онлайн ✅' if paid else '💵 Оплата при отриманні' if pay == 'cash' else f'💳 {pay}')
    if order.get('attachment'):
        out.append('📎 Картинка-приклад — в адмінці (Замовлення)')
    out += [sep, f'🔗 {SITE_URL}/admin.html']
    return '\n'.join(out)

def _tg_send(text, label='', env='TELEGRAM_CHAT_ID'):
    """Send a message to every chat listed in the env variable (orders: TELEGRAM_CHAT_ID)."""
    import sys, urllib.request, urllib.parse
    token    = os.environ.get('TELEGRAM_TOKEN', '')
    chat_ids = [c.strip() for c in os.environ.get(env, '').split(',') if c.strip()]
    if not token or not chat_ids:
        return
    text = text[:4000]  # Telegram rejects messages over 4096 chars
    # One failing chat (bot blocked, wrong id) must not stop the others
    for chat_id in chat_ids:
        try:
            body = urllib.parse.urlencode({'chat_id': chat_id, 'text': text}).encode()
            req  = urllib.request.Request(
                f'https://api.telegram.org/bot{token}/sendMessage',
                data=body, method='POST'
            )
            urllib.request.urlopen(req, timeout=8)
            print(f'[TG] Sent to {chat_id} ({label})', file=sys.stderr)
        except Exception as e:
            print(f'[TG] Error for chat {chat_id}: {e}', file=sys.stderr)

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
    for cat, body, name, uk, en in re.findall(r"\{cat:'([^']*)'(.*?)name:\{cs:'([^']*)'(?:,uk:'([^']*)')?(?:,en:'([^']*)')?", block, re.S):
        sizes = [{'label': l, 'price': int(p)} for l, p in re.findall(r"\{label:'([^']*)',price:(\d+)\}", body)]
        price = re.search(r"price:'([^']*)'", body)
        items.append({'cat': cat, 'name': name, 'names': {'cs': name, 'uk': uk or name, 'en': en or name},
                      'sizes': sizes, 'price': price.group(1) if price else ''})
    return items

def _visible_items(conn):
    """Everything currently on the menu as (Czech name, {cs, uk, en} names, admin item or None)."""
    custom = [r[0] for r in conn.execute('SELECT data FROM menu_items ORDER BY id ASC').fetchall()]
    row = conn.execute("SELECT value FROM settings WHERE key='hidden_statics'").fetchone()
    hidden = set(_json.loads(row[0])) if row and row[0] else set()
    custom_names = {(i.get('name') or {}).get('cs') for i in custom}
    replaced = {i.get('static_src_idx') for i in custom if i.get('static_src_idx') is not None}
    out = [(it['name'], it['names'], None) for idx, it in enumerate(_STATIC_ITEMS)
           if idx not in hidden and idx not in replaced and it['name'] not in custom_names]
    for it in custom:
        names = _translate(it).get('name') or {}
        out.append((names.get('cs', ''), {k: names.get(k) or names.get('cs', '') for k in ('cs', 'uk', 'en')}, it))
    return out

@app.get('/api/review-items')
def api_review_items():
    """Menu items a review can be about (Czech name is the key, plus UA/EN labels)."""
    with _get_pool().connection() as conn:
        seen, out = set(), []
        for cs, names, _ in _visible_items(conn):
            if cs and cs not in seen:
                seen.add(cs)
                out.append(names)
    return {'items': out}

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
    builder = None
    for c in cart if isinstance(cart, list) else []:
        if not isinstance(c, dict):
            continue
        name, size = str(c.get('name') or '').strip(), str(c.get('size') or '').strip()
        qty = _lead_int(c.get('qty')) or 0
        if qty < 1:
            continue
        if c.get('builder') is not None:   # custom cake from the builder: priced from its settings
            builder = builder or _builder_cfg(conn)
            res = _builder_line(builder, c['builder'], min(qty, 10))
            if not res:
                unknown.append(_BUILDER_NAME)
                continue
            lines.append(res[0]); total += res[1]
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

# ── Cake builder ──────────────────────────────────────────────────────────────
# Customers put a custom cake together (occasion, size, filling, decor, inscription,
# example picture). The admin sets the options and prices; the server prices every
# builder cake itself, requires lead_days of notice and (with Stripe) a 50 % prepayment.
_BUILDER_NAME = 'Dort na zakázku'
_BUILDER_DEFAULT = {
    'enabled': True,
    'lead_days': 14,
    'price_mode': 'from',   # 'from': shown as "od … Kč", the pastry chef confirms the final price
    'occasions': [
        {'id': 'birthday', 'name': {'cs': 'Narozeniny', 'uk': 'День народження', 'en': 'Birthday'}},
        {'id': 'wedding', 'name': {'cs': 'Svatba', 'uk': 'Весілля', 'en': 'Wedding'}},
        {'id': 'kids', 'name': {'cs': 'Dětská oslava', 'uk': 'Дитяче свято', 'en': 'Kids’ party'}},
        {'id': 'corporate', 'name': {'cs': 'Firemní akce', 'uk': 'Корпоратив', 'en': 'Corporate event'}},
        {'id': 'other', 'name': {'cs': 'Jiná příležitost', 'uk': 'Інша нагода', 'en': 'Other occasion'}},
    ],
    'sizes': [   # sample prices — the pastry shop sets its own in the admin panel
        {'id': 'xs', 'label': 'XS 16 cm', 'min_guests': 4, 'max_guests': 8, 'price': 1500},
        {'id': 's', 'label': 'S 18 cm', 'min_guests': 9, 'max_guests': 12, 'price': 1900},
        {'id': 'm', 'label': 'M 23 cm', 'min_guests': 13, 'max_guests': 20, 'price': 2500},
        {'id': 'l', 'label': 'L 26 cm', 'min_guests': 21, 'max_guests': 30, 'price': 3200},
    ],
    'fillings': [
        {'id': 'choco', 'name': {'cs': 'Čokoládová', 'uk': 'Шоколадна', 'en': 'Chocolate'}, 'extra': 0, 'img': ''},
        {'id': 'rasp', 'name': {'cs': 'Malinová', 'uk': 'Малинова', 'en': 'Raspberry'}, 'extra': 0, 'img': ''},
        {'id': 'cheese', 'name': {'cs': 'Cheesecake', 'uk': 'Чізкейк', 'en': 'Cheesecake'}, 'extra': 0, 'img': ''},
        {'id': 'pist', 'name': {'cs': 'Pistáciová', 'uk': 'Фісташкова', 'en': 'Pistachio'}, 'extra': 200, 'img': ''},
    ],
    'decor': [
        {'id': 'text', 'name': {'cs': 'Nápis na dortu', 'uk': 'Напис на торті', 'en': 'Inscription'}, 'price': 0},
        {'id': 'number', 'name': {'cs': 'Číslo / věk', 'uk': 'Цифра / вік', 'en': 'Number / age'}, 'price': 150},
        {'id': 'flowers', 'name': {'cs': 'Živé květy', 'uk': 'Живі квіти', 'en': 'Fresh flowers'}, 'price': 300},
        {'id': 'figures', 'name': {'cs': 'Figurky', 'uk': 'Фігурки', 'en': 'Figurines'}, 'price': 400},
        {'id': 'photo', 'name': {'cs': 'Jedlá fotka', 'uk': 'Їстівне фото', 'en': 'Edible photo'}, 'price': 250},
    ],
}
_ID_RE = re.compile(r'^[a-z0-9_-]{1,32}$')
# Photo of the main ingredient for the sample fillings, used until the admin uploads others
# (CC0 / public-domain photos from Wikimedia Commons, stored with the site)
_BUILDER_DEFAULT_IMGS = {
    'choco': '/fill-choco.jpg',
    'rasp': '/fill-rasp.jpg',
    'cheese': '/fill-cheese.jpg',
    'pist': '/fill-pist.jpg',
}

def _clean_names(raw):
    raw = raw if isinstance(raw, dict) else {}
    cs = str(raw.get('cs') or '').strip()[:80]
    return {'cs': cs, 'uk': str(raw.get('uk') or '').strip()[:80] or cs, 'en': str(raw.get('en') or '').strip()[:80] or cs}

def _clean_builder(raw, old=None):
    raw = raw if isinstance(raw, dict) else {}
    old_imgs = {f['id']: f.get('img', '') for f in ((old or {}).get('fillings') or [])}
    cfg = {'enabled': bool(raw.get('enabled', True)),
           'lead_days': max(0, min(120, _lead_int(raw.get('lead_days')) if _lead_int(raw.get('lead_days')) is not None else 14)),
           'price_mode': 'exact' if raw.get('price_mode') == 'exact' else 'from'}
    def items(key, fn):
        out, seen = [], set()
        for x in (raw.get(key) or [])[:30]:
            if isinstance(x, dict) and _ID_RE.match(str(x.get('id') or '')) and x['id'] not in seen:
                y = fn(x)
                if y:
                    seen.add(x['id']); out.append(y)
        return out
    cfg['occasions'] = items('occasions', lambda x: {'id': x['id'], 'name': _clean_names(x.get('name'))} if _clean_names(x.get('name'))['cs'] else None)
    cfg['sizes'] = items('sizes', lambda x: {'id': x['id'], 'label': re.sub(r'[(),|]', '', str(x.get('label') or '')).strip()[:30],
                                             'min_guests': max(0, _lead_int(x.get('min_guests')) or 0),
                                             'max_guests': max(0, _lead_int(x.get('max_guests')) or 0),
                                             'price': max(0, _lead_int(x.get('price')) or 0)} if str(x.get('label') or '').strip() and _lead_int(x.get('price')) else None)
    def filling(x):
        names = _clean_names(x.get('name'))
        if not names['cs']:
            return None
        img = str(x.get('img') or '')
        if img.startswith('/api/builder-img/'):
            img = old_imgs.get(x['id'], '')          # unchanged photo sent back as its URL
        elif img and (len(img) > 1_500_000 or not _PHOTO_RE.match(img)):
            img = ''
        return {'id': x['id'], 'name': names, 'extra': max(0, _lead_int(x.get('extra')) or 0), 'img': img}
    cfg['fillings'] = items('fillings', filling)
    cfg['decor'] = items('decor', lambda x: {'id': x['id'], 'name': _clean_names(x.get('name')), 'price': max(0, _lead_int(x.get('price')) or 0)}
                         if _clean_names(x.get('name'))['cs'] else None)
    return cfg

def _builder_cfg(conn):
    row = conn.execute("SELECT value FROM settings WHERE key='cake_builder'").fetchone()
    return _clean_builder(_json.loads(row[0])) if row and row[0] else _clean_builder(_BUILDER_DEFAULT)

def _public_builder(cfg):
    out = dict(cfg)
    out['fillings'] = [{**f, 'img': f"/api/builder-img/{f['id']}?v={hashlib.sha1(f['img'].encode()).hexdigest()[:10]}"
                        if f.get('img') else _BUILDER_DEFAULT_IMGS.get(f['id'], '')}
                       for f in cfg['fillings']]
    return out

def _builder_line(cfg, b, qty):
    """Price one builder cake: (order line, total, photo) or None when the choice is invalid."""
    if not cfg['enabled'] or not isinstance(b, dict):
        return None
    pick = lambda key, i: next((x for x in cfg[key] if x['id'] == i), None)
    size, filling = pick('sizes', b.get('size')), pick('fillings', b.get('filling'))
    occasion = pick('occasions', b.get('occasion'))
    if not size or not filling:
        return None
    decor = [x for x in (pick('decor', i) for i in (b.get('decor') or [])[:10]) if x]
    unit = size['price'] + filling['extra'] + sum(x['price'] for x in decor)
    clean = lambda s: re.sub(r'[(),|]', ' ', str(s or '')).strip()
    text = clean(b.get('text'))[:60]
    parts = [size['label'], filling['name']['cs']] + [x['name']['cs'] for x in decor]
    if occasion:
        parts.insert(0, occasion['name']['cs'])
    if text:
        parts.append(f'nápis: „{text}“')
    number = re.sub(r'\D', '', str(b.get('number') or ''))[:3]
    if number:
        parts.append(f'číslo: {number}')
    photo = str(b.get('photo') or '')
    if photo and (len(photo) > 1_500_000 or not _PHOTO_RE.match(photo)):
        photo = ''
    if photo:
        parts.append('📎 obrázek')
    label = clean(' · '.join(parts))
    return f'{_BUILDER_NAME} ({label}) x{qty} ({unit * qty} Kč)', unit * qty, photo

@app.get('/api/builder')
def api_builder_get():
    with _get_pool().connection() as conn:
        return _public_builder(_builder_cfg(conn))

@app.post('/api/builder')
async def api_builder_set(req: Request):
    d = await req.json()
    if not _verify_token(d.get('token')):
        raise HTTPException(401, 'Unauthorized')
    with _get_pool().connection() as conn:
        cfg = _clean_builder(d.get('config'), _builder_cfg(conn))
        conn.execute(
            "INSERT INTO settings(key,value) VALUES('cake_builder',%s) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value",
            (_json.dumps(cfg),))
    return {'ok': True, 'config': _public_builder(cfg)}

@app.get('/api/builder-img/{fid}')
def api_builder_img(fid: str):
    with _get_pool().connection() as conn:
        f = next((x for x in _builder_cfg(conn)['fillings'] if x['id'] == fid), None)
    m = re.match(r'^data:(image/[\w.+-]+);base64,(.*)$', (f or {}).get('img') or '', re.S)
    if not m:
        raise HTTPException(404)
    return Response(base64.b64decode(m.group(2)), media_type=m.group(1),
                    headers={'Cache-Control': 'public, max-age=31536000, immutable'})

# ── Seasonal look (New Year, Christmas, Halloween, …) ─────────────────────────
# The admin picks a theme, or "auto" which follows the calendar below; theme.js on the
# public pages draws the decorations. banner = own greeting text per language (optional).
_THEME_IDS = ('new_year', 'christmas', 'halloween', 'valentine', 'easter')
_THEME_DEFAULT = {'mode': 'off', 'effects': True, 'banner': {'cs': '', 'uk': '', 'en': ''}}

def _easter_sunday(y):
    a, b, c = y % 19, y // 100, y % 100
    d, e = b // 4, b % 4
    g = (8 * b + 13) // 25
    h = (19 * a + b - d - g + 15) % 30
    i, k = c // 4, c % 4
    l = (32 + 2 * e + 2 * i - h - k) % 7
    m = (a + 11 * h + 22 * l) // 451
    return _dt.date(y, (h + l - 7 * m + 114) // 31, (h + l - 7 * m + 114) % 31 + 1)

def _auto_theme(day):
    """The theme "auto" mode shows on this day ('' = none)."""
    md = (day.month, day.day)
    if (12, 27) <= md or md <= (1, 7):
        return 'new_year'
    if (12, 1) <= md <= (12, 26):
        return 'christmas'
    if (10, 20) <= md <= (10, 31):
        return 'halloween'
    if (2, 7) <= md <= (2, 14):
        return 'valentine'
    e = _easter_sunday(day.year)
    if e - _dt.timedelta(days=10) <= day <= e + _dt.timedelta(days=1):
        return 'easter'
    return ''

def _clean_theme(raw):
    raw = raw if isinstance(raw, dict) else {}
    mode = raw.get('mode') if raw.get('mode') in ('off', 'auto') + _THEME_IDS else 'off'
    ban = raw.get('banner') if isinstance(raw.get('banner'), dict) else {}
    return {'mode': mode, 'effects': raw.get('effects') is not False,
            'banner': {l: str(ban.get(l) or '').strip()[:200] for l in ('cs', 'uk', 'en')}}

def _theme_cfg(conn):
    row = conn.execute("SELECT value FROM settings WHERE key='site_theme'").fetchone()
    return _clean_theme(_json.loads(row[0]) if row and row[0] else _THEME_DEFAULT)

@app.get('/api/theme')
def api_theme_get():
    with _get_pool().connection() as conn:
        cfg = _theme_cfg(conn)
    theme = _auto_theme(_today()) if cfg['mode'] == 'auto' else ('' if cfg['mode'] == 'off' else cfg['mode'])
    return JSONResponse({**cfg, 'theme': theme}, headers={'Cache-Control': 'no-store'})

@app.post('/api/theme')
async def api_theme_set(req: Request):
    d = await req.json()
    if not _verify_token(d.get('token')):
        raise HTTPException(401, 'Unauthorized')
    cfg = _clean_theme(d.get('config'))
    with _get_pool().connection() as conn:
        conn.execute("INSERT INTO settings(key,value) VALUES('site_theme',%s) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value",
                     (_json.dumps(cfg),))
    return {'ok': True, 'config': cfg}

# ── Reviews ───────────────────────────────────────────────────────────────────
# Customers leave stars (1–5), text and an optional photo. New reviews wait for the
# admin to publish them; stars and text can't be edited by anyone, and the rating is
# the plain average of all published reviews. A review is marked "verified" when the
# phone given (never shown or stored) matches an existing order.
_REVIEW_COLS = "id, ts, name, stars, body, item, photo, status, verified, reply, COALESCE(source, '')"
_REVIEW_SOURCES = ('google', 'instagram', 'facebook', 'in_person', 'other')
_review_log: dict = defaultdict(list)
_PHOTO_RE = re.compile(r'^data:image/(jpeg|png|webp);base64,[A-Za-z0-9+/=]+$')

def _digits(phone):
    return re.sub(r'\D', '', str(phone or ''))[-9:]

def _review_row(r, admin=False, token=''):
    rid, ts, name, stars, body, item, photo, status, verified, reply, source = r
    out = {'id': rid, 'ts': ts, 'name': name, 'stars': stars, 'text': body, 'item': item or '',
           'verified': bool(verified), 'reply': reply or '', 'status': status, 'source': source or ''}
    if photo:
        v = hashlib.sha1(photo.encode()).hexdigest()[:10]
        out['photo'] = f'/api/review-img/{rid}?v={v}' + (f'&token={token}' if admin else '')
    return out

def _review_summary(rows):
    stars = [r[3] for r in rows]
    dist = {str(n): stars.count(n) for n in range(1, 6)}
    return {'count': len(stars), 'avg': round(sum(stars) / len(stars), 1) if stars else 0, 'dist': dist}

@app.get('/api/reviews')
def api_reviews_get():
    with _get_pool().connection() as conn:
        rows = conn.execute(f"SELECT {_REVIEW_COLS} FROM reviews WHERE status='published' ORDER BY id DESC").fetchall()
    return {'summary': _review_summary(rows), 'reviews': [_review_row(r) for r in rows[:200]]}

@app.post('/api/reviews')
async def api_reviews_add(req: Request, bg: BackgroundTasks):
    d = await req.json()
    if d.get('website'):  # hidden field only bots fill in
        return {'ok': True}
    ip, now = _get_ip(req), time.time()
    recent = [t for t in _review_log.get(ip, []) if now - t < 3600]
    if len(recent) >= 3:
        raise HTTPException(429, 'Too many reviews, try later')
    stars = _lead_int(d.get('stars'))
    name = str(d.get('name') or '').strip()[:60]
    body = str(d.get('text') or '').strip()[:1500]
    if not stars or not 1 <= stars <= 5 or not name or len(body) < 3:
        raise HTTPException(400, 'stars, name and text are required')
    photo = str(d.get('photo') or '')
    if photo and (len(photo) > 2_000_000 or not _PHOTO_RE.match(photo)):
        raise HTTPException(400, 'Invalid photo')
    item = str(d.get('item') or '').strip()[:120]
    rid = int(now * 1000)
    with _get_pool().connection() as conn:
        phone = _digits(d.get('phone'))
        verified = False
        if len(phone) >= 9:
            phones = conn.execute("SELECT phone FROM orders WHERE phone <> ''").fetchall()
            verified = any(_digits(p[0]) == phone for p in phones)
        conn.execute(
            'INSERT INTO reviews (id, ts, name, stars, body, item, photo, status, verified, reply)'
            " VALUES (%s,%s,%s,%s,%s,%s,%s,'published',%s,'')",
            (rid, time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), name, stars, body, item, photo, verified))
    recent.append(now)
    _review_log[ip] = recent
    bg.add_task(_tg_send, f"⭐ НОВИЙ ВІДГУК ({'★' * stars}{'☆' * (5 - stars)})\n👤 {name}"
                          f"{' · перевірений клієнт' if verified else ''}\n💬 {body[:500]}\n\nВже на сайті. Прибрати спам: {SITE_URL}/admin.html", 'review', 'TELEGRAM_REVIEWS_CHAT_ID')
    return {'ok': True}

@app.get('/api/review-img/{review_id}')
def api_review_img(review_id: int, token: str = ''):
    with _get_pool().connection() as conn:
        row = conn.execute('SELECT photo, status FROM reviews WHERE id=%s', (review_id,)).fetchone()
    # Photos of unpublished reviews are visible only in the admin panel
    if not row or not row[0] or (row[1] != 'published' and not _verify_token(token)):
        raise HTTPException(404)
    m = re.match(r'^data:(image/[\w.+-]+);base64,(.*)$', row[0], re.S)
    if not m:
        raise HTTPException(404)
    return Response(base64.b64decode(m.group(2)), media_type=m.group(1),
                    headers={'Cache-Control': 'public, max-age=31536000, immutable' if row[1] == 'published' else 'no-store'})

@app.post('/api/reviews/admin')
async def api_reviews_admin(req: Request):
    d = await req.json()
    tok = d.get('token')
    if not _verify_token(tok):
        raise HTTPException(401, 'Unauthorized')
    with _get_pool().connection() as conn:
        rows = conn.execute(f'SELECT {_REVIEW_COLS} FROM reviews ORDER BY id DESC').fetchall()
    published = [r for r in rows if r[7] == 'published']
    return {'summary': _review_summary(published), 'reviews': [_review_row(r, True, tok) for r in rows]}

@app.post('/api/reviews/import')
async def api_reviews_import(req: Request):
    """Admin moves over a real review left elsewhere (Google, Instagram, in person…).
    It is published with its source shown, never as a review written on this site."""
    d = await req.json()
    if not _verify_token(d.get('token')):
        raise HTTPException(401, 'Unauthorized')
    stars = _lead_int(d.get('stars'))
    name = str(d.get('name') or '').strip()[:60]
    body = str(d.get('text') or '').strip()[:1500]
    source = d.get('source') if d.get('source') in _REVIEW_SOURCES else ''
    if not stars or not 1 <= stars <= 5 or not name or len(body) < 3 or not source:
        raise HTTPException(400, 'stars, name, text and source are required')
    photo = str(d.get('photo') or '')
    if photo and (len(photo) > 2_000_000 or not _PHOTO_RE.match(photo)):
        raise HTTPException(400, 'Invalid photo')
    date = str(d.get('date') or '').strip()
    ts = f'{date}T12:00:00Z' if _DATE_RE.match(date) else time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    rid = int(time.time() * 1000)
    with _get_pool().connection() as conn:
        conn.execute(
            'INSERT INTO reviews (id, ts, name, stars, body, item, photo, status, verified, reply, source)'
            " VALUES (%s,%s,%s,%s,%s,%s,%s,'published',FALSE,'',%s)",
            (rid, ts, name, stars, body, str(d.get('item') or '').strip()[:120], photo, source))
    return {'ok': True, 'id': rid}

@app.patch('/api/reviews/{review_id}')
async def api_reviews_patch(review_id: int, req: Request):
    """Publish / hide a review and set the shop's reply. Stars and text stay as written."""
    d = await req.json()
    if not _verify_token(d.get('token')):
        raise HTTPException(401, 'Unauthorized')
    with _get_pool().connection() as conn:
        if d.get('status') in ('new', 'published', 'hidden'):
            conn.execute('UPDATE reviews SET status=%s WHERE id=%s', (d['status'], review_id))
        if 'reply' in d:
            conn.execute('UPDATE reviews SET reply=%s WHERE id=%s', (str(d['reply'] or '').strip()[:1000], review_id))
    return {'ok': True}

@app.delete('/api/reviews/{review_id}')
async def api_reviews_del(review_id: int, req: Request):
    d = await req.json()
    if not _verify_token(d.get('token')):
        raise HTTPException(401, 'Unauthorized')
    with _get_pool().connection() as conn:
        conn.execute('DELETE FROM reviews WHERE id=%s', (review_id,))
    return {'ok': True}

# ── Birthday reminders ────────────────────────────────────────────────────────
# When ordering, a customer may tick "remind me before my birthday" and give an e-mail
# and day/month. `days_before` days ahead they get one e-mail a year inviting them to
# order a cake. Every e-mail has an unsubscribe link. Sending needs SMTP settings:
# SMTP_HOST, SMTP_PORT (465 = SSL, 587 = STARTTLS), SMTP_USER, SMTP_PASS, SMTP_FROM.
import threading
_EMAIL_RE = re.compile(r'^[^@\s]{1,64}@[^@\s]{1,190}\.[A-Za-z]{2,24}$')
_BDAY_RE = re.compile(r'^(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])$')
SITE_URL = os.environ.get('SITE_URL', 'https://cukrarna-cakeme.onrender.com').rstrip('/')
_BDAY_DEFAULT = {
    'enabled': True,
    'days_before': 14,
    'subject': {'cs': '🎂 Blíží se vaše narozeniny — dort od Cukrárny CakeMe?',
                'uk': '🎂 Скоро ваш день народження — торт від Cukrárna CakeMe?',
                'en': '🎂 Your birthday is coming — a cake from Cukrárna CakeMe?'},
    'body': {'cs': 'Dobrý den, {name}!\n\nZa {days} dní máte narozeniny 🎉 Cukrárna CakeMe je tu s vámi a ráda vám připraví dort na oslavu.\nNechcete si objednat dort na svůj svátek? Stačí kliknout:\n{link}\n\nS láskou,\nCukrárna CakeMe',
             'uk': 'Добрий день, {name}!\n\nЗа {days} днів ваш день народження 🎉 Кондитерська CakeMe з вами і з радістю приготує торт для свята.\nНе хочете замовити торт на своє свято? Достатньо натиснути:\n{link}\n\nЗ любов’ю,\nCukrárna CakeMe',
             'en': 'Hello {name}!\n\nYour birthday is in {days} days 🎉 Cukrárna CakeMe is with you and would love to make a cake for your celebration.\nWould you like to order a cake for your day? Just click:\n{link}\n\nWith love,\nCukrárna CakeMe'},
}
_UNSUB_TXT = {'cs': 'Nechcete už připomínky? Odhlásit se: {url}', 'uk': 'Не хочете отримувати нагадування? Відписатися: {url}',
              'en': 'Don’t want reminders any more? Unsubscribe: {url}'}
_bday_lock = threading.Lock()
_bday_checked = {'day': ''}

def _smtp_ready():
    """Sending is possible: Brevo API key (works where SMTP ports are blocked) or SMTP login."""
    return bool(os.environ.get('BREVO_API_KEY') and (os.environ.get('MAIL_FROM') or os.environ.get('SMTP_FROM'))) \
        or all(os.environ.get(k) for k in ('SMTP_HOST', 'SMTP_USER', 'SMTP_PASS'))

def _send_email(to, subject, body):
    if os.environ.get('BREVO_API_KEY'):
        # Brevo (brevo.com) over HTTPS; the sender address must be verified in Brevo
        import urllib.request
        sender = os.environ.get('MAIL_FROM') or os.environ.get('SMTP_FROM')
        req = urllib.request.Request('https://api.brevo.com/v3/smtp/email', method='POST',
            data=json.dumps({'sender': {'email': sender, 'name': 'Cukrárna CakeMe'}, 'to': [{'email': to}],
                             'subject': subject, 'textContent': body}).encode(),
            headers={'api-key': os.environ['BREVO_API_KEY'], 'Content-Type': 'application/json', 'Accept': 'application/json'})
        urllib.request.urlopen(req, timeout=20)
        return
    import smtplib, ssl
    from email.message import EmailMessage
    msg = EmailMessage()
    msg['From'] = os.environ.get('SMTP_FROM') or os.environ['SMTP_USER']
    msg['To'], msg['Subject'] = to, subject
    msg.set_content(body)
    host, port = os.environ['SMTP_HOST'], int(os.environ.get('SMTP_PORT') or 465)
    if port == 465:
        with smtplib.SMTP_SSL(host, port, context=ssl.create_default_context(), timeout=20) as s:
            s.login(os.environ['SMTP_USER'], os.environ['SMTP_PASS']); s.send_message(msg)
    else:
        with smtplib.SMTP(host, port, timeout=20) as s:
            s.starttls(context=ssl.create_default_context())
            s.login(os.environ['SMTP_USER'], os.environ['SMTP_PASS']); s.send_message(msg)

def _bday_cfg(conn):
    row = conn.execute("SELECT value FROM settings WHERE key='bday_config'").fetchone()
    raw = _json.loads(row[0]) if row and row[0] else {}
    cfg = {'enabled': bool(raw.get('enabled', _BDAY_DEFAULT['enabled'])),
           'days_before': max(1, min(60, _lead_int(raw.get('days_before')) or _BDAY_DEFAULT['days_before']))}
    for k in ('subject', 'body'):
        src = raw.get(k) if isinstance(raw.get(k), dict) else {}
        cfg[k] = {lng: (str(src.get(lng) or '').strip()[:4000 if k == 'body' else 200] or _BDAY_DEFAULT[k][lng]) for lng in ('cs', 'uk', 'en')}
    return cfg

def _bday_email(cfg, sub):
    lang = sub['lang'] if sub['lang'] in ('cs', 'uk', 'en') else 'cs'
    name = sub['name'] or {'cs': 'zákazníku', 'uk': 'друже', 'en': 'there'}[lang]
    body = cfg['body'][lang].replace('{name}', name).replace('{days}', str(cfg['days_before'])).replace('{link}', SITE_URL + '/menu.html')
    body += '\n\n—\n' + _UNSUB_TXT[lang].format(url=f"{SITE_URL}/api/unsubscribe?t={sub['token']}")
    return cfg['subject'][lang], body

def _subscribe(conn, d):
    """Save an opt-in from the order form. Returns True when stored."""
    email = str(d.get('bday_email') or '').strip().lower()[:254]
    bday = str(d.get('bday') or '').strip()
    if not d.get('bday_optin') or not _EMAIL_RE.match(email) or not _BDAY_RE.match(bday):
        return False
    lang = d.get('lang') if d.get('lang') in ('cs', 'uk', 'en') else 'cs'
    name = str(d.get('name') or '').strip()[:60]
    row = conn.execute('SELECT token FROM subscribers WHERE email=%s', (email,)).fetchone()
    if row:
        conn.execute('UPDATE subscribers SET name=%s, bday=%s, lang=%s, active=TRUE WHERE email=%s', (name, bday, lang, email))
    else:
        conn.execute('INSERT INTO subscribers (email, name, bday, lang, token, created, active, last_sent_year)'
                     ' VALUES (%s,%s,%s,%s,%s,%s,TRUE,0)',
                     (email, name, bday, lang, secrets.token_urlsafe(16), time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())))
    return True

def _send_due_birthdays(conn=None):
    """Send today's reminders (birthday = today + days_before). Returns how many were sent."""
    if conn is None:
        with _get_pool().connection() as c:
            return _send_due_birthdays(c)
    cfg = _bday_cfg(conn)
    if not cfg['enabled'] or not _smtp_ready():
        return 0
    target = _today() + _dt.timedelta(days=cfg['days_before'])
    wanted = {target.strftime('%m-%d')}
    if target.month == 2 and target.day == 28 and not (target.year % 4 == 0 and (target.year % 100 or target.year % 400 == 0)):
        wanted.add('02-29')  # 29 Feb birthdays are reminded on 28 Feb in other years
    rows = conn.execute('SELECT email, name, bday, lang, token FROM subscribers WHERE active=TRUE AND last_sent_year < %s',
                        (target.year,)).fetchall()
    sent = 0
    for email, name, bday, lang, token in rows:
        if bday not in wanted:
            continue
        subj, body = _bday_email(cfg, {'name': name, 'lang': lang, 'token': token})
        try:
            _send_email(email, subj, body)
            conn.execute('UPDATE subscribers SET last_sent_year=%s WHERE email=%s', (target.year, email))
            sent += 1
        except Exception as e:
            import sys
            print(f'[BDAY] Error for {email}: {e}', file=sys.stderr)
    return sent

def _notify_due_birthdays(conn):
    """Tell the shop in Telegram (orders chat) about every subscriber whose birthday is
    within days_before, once per birthday, so they can write to them. Returns how many."""
    cfg = _bday_cfg(conn)
    if not cfg['enabled']:
        return 0
    today = _today()
    row = conn.execute("SELECT value FROM settings WHERE key='bday_tg_notified'").fetchone()
    done = _json.loads(row[0]) if row and row[0] else {}   # email -> year of the birthday already announced
    rows = conn.execute('SELECT email, name, bday, lang, token FROM subscribers WHERE active=TRUE AND last_sent_year < %s',
                        (today.year + 2,)).fetchall()
    told = 0
    for email, name, bday, lang, token in rows:
        nxt = _next_bday(bday, today)
        left = (nxt - today).days
        if left > cfg['days_before'] or done.get(email) == nxt.year:
            continue
        auto = _smtp_ready()
        _tg_send(f"🎂 Через {left} дн. день народження: {name or '—'} ({nxt.strftime('%d.%m.')})\n"
                 f"✉️ {email}\n"
                 + ("Лист із пропозицією торта надіслано автоматично." if auto else
                    f"Надішліть привітання з пропозицією торта: {SITE_URL}/admin.html → «🎉 Нагадування»"),
                 'birthday')
        done[email] = nxt.year
        told += 1
    if told:
        conn.execute("INSERT INTO settings(key,value) VALUES('bday_tg_notified',%s) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value",
                     (_json.dumps(done),))
    return told

def _maybe_send_birthdays():
    """Once a day, in the background (no cron needed): e-mail today's reminders when a
    mail service is connected, and tell the shop in Telegram whose birthday is near."""
    day = _today().isoformat()
    if _bday_checked['day'] == day or not DATABASE_URL:
        return
    _bday_checked['day'] = day
    def run():
        if not _bday_lock.acquire(blocking=False):
            return
        try:
            with _get_pool().connection() as conn:
                row = conn.execute("SELECT value FROM settings WHERE key='bday_last_run'").fetchone()
                if row and row[0] == day:
                    return  # another worker already did today
                conn.execute("INSERT INTO settings(key,value) VALUES('bday_last_run',%s) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value", (day,))
                _send_due_birthdays(conn)
                _notify_due_birthdays(conn)
        except Exception as e:
            import sys
            print(f'[BDAY] {e}', file=sys.stderr)
        finally:
            _bday_lock.release()
    threading.Thread(target=run, daemon=True).start()

@app.get('/api/bday/status')
def api_bday_status():
    """Whether the order form offers the reminder. Without a mail service the admin
    sends the e-mails by hand from the admin tab, so only the switch matters."""
    with _get_pool().connection() as conn:
        cfg = _bday_cfg(conn)
    return {'on': cfg['enabled'], 'days': cfg['days_before']}

@app.get('/api/unsubscribe')
def api_unsubscribe(t: str = ''):
    with _get_pool().connection() as conn:
        row = conn.execute('SELECT lang FROM subscribers WHERE token=%s', (t,)).fetchone()
        if row:
            conn.execute('UPDATE subscribers SET active=FALSE WHERE token=%s', (t,))
    lang = row[0] if row and row[0] in ('cs', 'uk', 'en') else 'cs'
    text = {'cs': 'Odhlášeno. Připomínky narozenin už vám nebudeme posílat.', 'uk': 'Ви відписалися. Нагадування про день народження більше не надходитимуть.',
            'en': 'Unsubscribed. You won’t receive birthday reminders any more.'}[lang] if row else 'Link is not valid.'
    return Response(f'<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
                    f'<title>CakeMe</title><body style="background:#0a0a0a;color:#f5f0e8;font-family:sans-serif;display:flex;'
                    f'align-items:center;justify-content:center;min-height:90vh;text-align:center;padding:20px">'
                    f'<div><p style="font-size:1.2rem">{text}</p><p><a style="color:#c9a96e" href="/">Cukrárna CakeMe</a></p></div>',
                    media_type='text/html')

def _next_bday(bday, today):
    """Next date of a 'MM-DD' birthday from today (29 Feb -> 28 Feb in other years)."""
    m, d = map(int, bday.split('-'))
    for year in (today.year, today.year + 1):
        try:
            day = _dt.date(year, m, d)
        except ValueError:
            day = _dt.date(year, 2, 28)
        if day >= today:
            return day
    return _dt.date(today.year + 1, m, min(d, 28))

@app.post('/api/bday/admin')
async def api_bday_admin(req: Request):
    """Settings, SMTP status and subscribers for the admin tab."""
    d = await req.json()
    if not _verify_token(d.get('token')):
        raise HTTPException(401, 'Unauthorized')
    with _get_pool().connection() as conn:
        if isinstance(d.get('config'), dict):
            conn.execute("INSERT INTO settings(key,value) VALUES('bday_config',%s) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value",
                         (_json.dumps(d['config']),))
        if d.get('deactivate'):
            conn.execute('UPDATE subscribers SET active=FALSE WHERE email=%s', (str(d['deactivate']),))
        cfg = _bday_cfg(conn)
        today = _today()
        if d.get('mark_sent'):  # the admin sent it by hand: don't offer it again this year
            row = conn.execute('SELECT bday FROM subscribers WHERE email=%s', (str(d['mark_sent']),)).fetchone()
            if row:
                conn.execute('UPDATE subscribers SET last_sent_year=%s WHERE email=%s',
                             (_next_bday(row[0], today).year, str(d['mark_sent'])))
        subs = conn.execute('SELECT email, name, bday, lang, active, last_sent_year, created, token FROM subscribers ORDER BY bday').fetchall()
        order_mails = conn.execute("SELECT email, name, ts FROM orders WHERE COALESCE(email,'') <> '' ORDER BY id DESC").fetchall()
    out = []
    for e, n, b, l, a, y, c, tok in subs:
        nxt = _next_bday(b, today)
        left = (nxt - today).days
        subj, body = _bday_email(cfg, {'name': n, 'lang': l, 'token': tok})
        out.append({'email': e, 'name': n, 'bday': b, 'lang': l, 'active': bool(a), 'last_sent_year': y, 'created': c,
                    'days_left': left, 'due': bool(a) and left <= cfg['days_before'] and (y or 0) < nxt.year,
                    'unsub': f"{SITE_URL}/api/unsubscribe?t={tok}" if a else '',
                    'mail': {'subject': subj, 'body': body}})
    # Everyone who left an e-mail: from orders (newest first) and from subscriptions
    contacts = {}
    for e, n, ts in order_mails:
        c = contacts.setdefault(e.strip().lower(), {'email': e.strip(), 'name': n or '', 'orders': 0, 'last': ts or '', 'subscribed': False})
        c['orders'] += 1
    for x in out:
        c = contacts.setdefault(x['email'].lower(), {'email': x['email'], 'name': x['name'], 'orders': 0, 'last': x['created'] or '', 'subscribed': False})
        c['subscribed'] = x['active']
        c['name'] = c['name'] or x['name']
        c['lang'], c['unsub'] = x['lang'], x['unsub']
    return {'config': cfg, 'smtp': _smtp_ready(), 'subscribers': out,
            'link': SITE_URL + '/menu.html', 'unsub_txt': _UNSUB_TXT,
            'contacts': sorted(contacts.values(), key=lambda c: c['last'], reverse=True)}

@app.post('/api/bday/test')
async def api_bday_test(req: Request):
    """Send the reminder e-mail to the admin's own address to see how it looks."""
    from starlette.concurrency import run_in_threadpool
    d = await req.json()
    if not _verify_token(d.get('token')):
        raise HTTPException(401, 'Unauthorized')
    to = str(d.get('email') or '').strip()
    if not _EMAIL_RE.match(to):
        raise HTTPException(400, 'Invalid e-mail')
    with _get_pool().connection() as conn:
        subj, body = _bday_email(_bday_cfg(conn), {'name': 'Jana', 'lang': d.get('lang') or 'cs', 'token': 'test'})
    if not _smtp_ready():  # no mail service: the admin opens this e-mail in their own mailbox
        return {'ok': False, 'manual': True, 'subject': subj, 'body': body}
    try:
        await run_in_threadpool(_send_email, to, subj, body)
    except Exception as e:
        raise HTTPException(502, f'E-mail failed: {e}')
    return {'ok': True}

# ── Delivery/pickup slots ─────────────────────────────────────────────────────
# Customers pick a day up to the end of next year (or within `days_ahead` days) and a time
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
    'days_ahead': 0,        # how far ahead customers can book; 0 = to the end of next year
    'min_lead_days': 1,     # earliest day: tomorrow
    'weekdays': [0, 1, 2, 3, 4, 5, 6],  # Mon=0 … Sun=6
    'times': ['09:00-11:00', '11:00-13:00', '13:00-15:00', '15:00-17:00', '17:00-20:00'],
    'per_slot': 3,          # orders per interval
    'per_day': 12,          # orders per day
    'closed': [],           # YYYY-MM-DD days off
    'holidays': {},         # red days: YYYY-MM-DD -> holiday name; closed for everything (tables too)
    'short': {},            # short days: YYYY-MM-DD -> 'HH:MM' closing time
}
_SLOT_KEEP_DAYS = 60        # closed days and the admin schedule go 2 months back
_TIME_RE = re.compile(r'^([01]\d|2[0-3]):[0-5]\d-([01]\d|2[0-3]):[0-5]\d$')
_DATE_RE = re.compile(r'^\d{4}-\d{2}-\d{2}$')
_HM_RE = re.compile(r'^([01]\d|2[0-3]):[0-5]\d$')

def _today():
    return _dt.datetime.now(_TZ).date()

def _clean_slot_cfg(raw):
    cfg = dict(_SLOT_DEFAULT)
    raw = raw if isinstance(raw, dict) else {}
    num = lambda v, lo, hi, dflt: max(lo, min(hi, _lead_int(v))) if _lead_int(v) is not None else dflt
    cfg['enabled'] = bool(raw.get('enabled', cfg['enabled']))
    cfg['days_ahead'] = num(raw.get('days_ahead'), 0, 800, cfg['days_ahead'])
    cfg['ahead_v2'] = True
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
    hol, short = raw.get('holidays'), raw.get('short')
    cfg['holidays'] = {k: str(v or '').strip()[:60] for k, v in sorted(hol.items())
                       if _DATE_RE.match(str(k)) and k >= oldest} if isinstance(hol, dict) else {}
    cfg['short'] = {k: str(v) for k, v in sorted(short.items())
                    if _DATE_RE.match(str(k)) and k >= oldest and _HM_RE.match(str(v)) and k not in cfg['holidays']} if isinstance(short, dict) else {}
    return cfg

def _slot_cfg(conn):
    row = conn.execute("SELECT value FROM settings WHERE key='slot_config'").fetchone()
    raw = _json.loads(row[0]) if row and row[0] else {}
    if isinstance(raw, dict) and not raw.get('ahead_v2'):
        raw['days_ahead'] = 0  # saved before the yearly window: the old 2-month default
    return _clean_slot_cfg(raw)

def _last_day(today, days_ahead=0):
    """Last bookable day: today + days_ahead, or 31 Dec of next year when days_ahead is 0."""
    return today + _dt.timedelta(days=days_ahead) if days_ahead else _dt.date(today.year + 1, 12, 31)

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
        if tm and '-' not in tm:
            continue  # a table booking (single time), not a cake slot
        by_slot[(date, tm)] += 1
        by_day[date] += 1
    return by_slot, by_day

def _slot_days(conn, cfg):
    """Bookable days from the earliest allowed date up to the last one, with free places."""
    today = _today()
    first = today + _dt.timedelta(days=cfg['min_lead_days'])
    last = _last_day(today, cfg['days_ahead'])
    by_slot, by_day = _slot_counts(conn, first.isoformat(), last.isoformat())
    now_hm = _dt.datetime.now(_TZ).strftime('%H:%M')
    days, d = [], first
    while d <= last:
        iso = d.isoformat()
        open_day = d.weekday() in cfg['weekdays'] and iso not in cfg['closed'] and iso not in cfg['holidays']
        day_left = max(0, cfg['per_day'] - by_day[iso])
        short = cfg['short'].get(iso)
        slots = []
        if open_day:
            for tm in cfg['times']:
                if d == today and tm[:5] <= now_hm:
                    continue  # interval already started today
                if short and tm[6:] > short:
                    continue  # short day: only intervals that end by closing time
                slots.append({'time': tm, 'left': min(day_left, max(0, cfg['per_slot'] - by_slot[(iso, tm)]))})
        day = {'date': iso, 'open': open_day and day_left > 0 and any(s['left'] for s in slots), 'slots': slots}
        if iso in cfg['holidays']:
            day['holiday'] = cfg['holidays'][iso]
        if short:
            day['short'] = short
        days.append(day)
        d += _dt.timedelta(days=1)
    return days

# Table bookings (eat in, in advance): any day up to the end of next year, opening hours only.
# They don't use the cake slots and don't take their places.
DINE_FROM, DINE_TO, DINE_STEP = '11:00', '18:00', 30

def _dine_times():
    h, m = map(int, DINE_FROM.split(':')); end = DINE_TO
    out = []
    while f'{h:02d}:{m:02d}' < end:
        out.append(f'{h:02d}:{m:02d}')
        m += DINE_STEP; h, m = h + m // 60, m % 60
    return out

def _check_dine(date, tm, cfg=None):
    """None if a table can be booked for this date/time, otherwise an error code.
    Red days are closed; on a short day only times before closing."""
    try:
        day = _dt.date.fromisoformat(date)
    except ValueError:
        return 'slot_unavailable'
    today = _today()
    if day < today or day > _last_day(today):
        return 'slot_unavailable'
    if tm not in _dine_times():
        return 'slot_full'
    if day == today and tm <= _dt.datetime.now(_TZ).strftime('%H:%M'):
        return 'slot_full'
    if cfg and date in cfg['holidays']:
        return 'slot_unavailable'
    if cfg and cfg['short'].get(date) and tm >= cfg['short'][date]:
        return 'slot_full'
    return None

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
        today = _today().isoformat()
        # red and short days also apply to table bookings, which work without the slot picker
        extra = {'holidays': {k: v for k, v in cfg['holidays'].items() if k >= today},
                 'short': {k: v for k, v in cfg['short'].items() if k >= today}}
        if not cfg['enabled']:
            return {'enabled': False, 'days': [], **extra}
        return {'enabled': True, 'days': _slot_days(conn, cfg), **extra}

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
_ORDER_LIMITS = {'name': 120, 'phone': 40, 'email': 254, 'address': 400, 'order': 4000, 'payment': 60,
                 'order_type': 40, 'delivery_date': 20, 'delivery_time': 20}

def _order_email(d):
    """Optional contact e-mail from the order form ('' when missing or not an address)."""
    v = str(d.get('email') or '').strip()[:254]
    return v if _EMAIL_RE.match(v) else ''

def _clip_order(order):
    for k, limit in _ORDER_LIMITS.items():
        order[k] = str(order.get(k) or '')[:limit]

def _has_builder(cart):
    return isinstance(cart, list) and any(isinstance(c, dict) and c.get('builder') is not None for c in cart)

def _cart_photo(cart):
    """First valid example picture from builder cakes in the cart ('' if none)."""
    for c in cart if isinstance(cart, list) else []:
        p = str(((c or {}).get('builder') or {}).get('photo') or '') if isinstance(c, dict) and isinstance(c.get('builder'), dict) else ''
        if p and len(p) <= 1_500_000 and _PHOTO_RE.match(p):
            return p
    return ''

def _insert_order(conn, order):
    conn.execute(
        'INSERT INTO orders (id,ts,name,phone,address,ord,payment,order_type,delivery_date,delivery_time,status,attachment,email)'
        ' VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)',
        (order['id'], order['ts'], order['name'], order['phone'],
         order['address'], order['order'], order['payment'],
         order['order_type'], order['delivery_date'], order['delivery_time'], order['status'],
         order.get('attachment') or '', order.get('email') or ''))

@app.post('/api/order')
async def api_order(req: Request, bg: BackgroundTasks):
    d = await req.json()
    order = {
        'id':            int(time.time() * 1000),
        'ts':            time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'name':          (d.get('name')          or '').strip(),
        'phone':         (d.get('phone')         or '').strip(),
        'email':         _order_email(d),
        'address':       (d.get('address')       or '').strip(),
        'order':         (d.get('order')         or '').strip(),
        'payment':       (d.get('payment')       or '').strip(),
        'order_type':    (d.get('order_type')    or '').strip(),
        'delivery_date': (d.get('delivery_date') or '').strip(),
        'delivery_time': (d.get('delivery_time') or '').strip(),
        'status':        'new',
    }
    with _get_pool().connection() as conn:
        if d.get('dine_in') is True:
            order['delivery_date'] = order['delivery_time'] = ''
        else:
            if d.get('dine_in') == 'later':
                err = _check_dine(order['delivery_date'], order['delivery_time'], _slot_cfg(conn))
            else:
                err = _check_slot(conn, order['delivery_date'], order['delivery_time'])
            if err:
                raise HTTPException(409, {'error': err})
        rule_err = _check_item_rules(conn, d.get('cart'), order['delivery_date'] or _today().isoformat())
        if rule_err:
            raise HTTPException(409, rule_err)
        # A custom cake from the builder is paid 50 % in advance by card when card payments work
        if STRIPE_SECRET_KEY and _has_builder(d.get('cart')):
            raise HTTPException(409, {'error': 'prepay_required'})
        # Pay-on-delivery: use server prices when every line is known, otherwise keep
        # the customer's text so the order still arrives (staff check it anyway)
        if d.get('cart'):
            lines, total, unknown = _price_cart(conn, d['cart'])
            if lines and not unknown:
                order['order'] = _priced_order_text(lines, total)
        order['attachment'] = _cart_photo(d.get('cart'))
        _clip_order(order)
        _insert_order(conn, order)
        _subscribe(conn, d)  # birthday reminder, only if the customer ticked it
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
                "payment,order_type,delivery_date,delivery_time,status,"
                "COALESCE(attachment,'') <> '' AS has_attachment, COALESCE(email,'') AS email FROM orders ORDER BY id DESC"
            )
            rows = cur.fetchall()
    return rows

@app.get('/api/order-img/{order_id}')
def api_order_img(order_id: int, token: str = ''):
    """Example picture attached to a builder order (admin only)."""
    if not _verify_token(token):
        raise HTTPException(401, 'Unauthorized')
    with _get_pool().connection() as conn:
        row = conn.execute('SELECT attachment FROM orders WHERE id=%s', (order_id,)).fetchone()
    m = re.match(r'^data:(image/[\w.+-]+);base64,(.*)$', (row[0] if row else '') or '', re.S)
    if not m:
        raise HTTPException(404)
    return Response(base64.b64decode(m.group(2)), media_type=m.group(1), headers={'Cache-Control': 'no-store'})

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
        if d.get('dine_in') is True:
            d['delivery_date'] = d['delivery_time'] = ''
            slot_err = None
        elif d.get('dine_in') == 'later':
            slot_err = _check_dine((d.get('delivery_date') or '').strip(), (d.get('delivery_time') or '').strip(), _slot_cfg(conn))
        else:
            slot_err = _check_slot(conn, (d.get('delivery_date') or '').strip(), (d.get('delivery_time') or '').strip())
        rule_err = _check_item_rules(conn, d.get('cart'), (d.get('delivery_date') or '').strip() or _today().isoformat())
    if slot_err:
        raise HTTPException(409, {'error': slot_err})
    if rule_err:
        raise HTTPException(409, rule_err)
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
        'email':         _order_email(d),
        'address':       (d.get('address')       or '').strip(),
        'order':         _priced_order_text(lines, total_czk),
        'payment':       'online',
        'order_type':    (d.get('order_type')    or '').strip(),
        'delivery_date': (d.get('delivery_date') or '').strip(),
        'delivery_time': (d.get('delivery_time') or '').strip(),
        'status':        'pending_payment',
        'attachment':    _cart_photo(d.get('cart')),
    }
    _clip_order(order)
    with _get_pool().connection() as conn:
        _insert_order(conn, order)
        _subscribe(conn, d)  # birthday reminder, only if the customer ticked it

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
                'payment,order_type,delivery_date,delivery_time,email',
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

# ── /api/pageviews ────────────────────────────────────────────────────────────
@app.get('/api/pageviews')
def api_pageviews():
    with _get_pool().connection() as conn:
        row = conn.execute("SELECT value FROM settings WHERE key='pageviews_daily'").fetchone()
        src = conn.execute("SELECT value FROM settings WHERE key='traffic_daily'").fetchone()
        return {'daily': _json.loads(row[0]) if row and row[0] else {},
                'sources': _json.loads(src[0]) if src and src[0] else {}}

# Where a visitor came from: ?utm_source=… wins, then ad click ids, then the Referer
# host. Moving between the site's own pages is not a new visit and is not counted.
# Paid clicks get an "_ads" suffix (google_ads, facebook_ads, …): ad click ids that only
# ads add (gclid, ttclid, …) or utm_medium=cpc/paid.
_TRAFFIC_HOSTS = [('instagram', 'instagram'), ('facebook', 'facebook'), ('fb.com', 'facebook'), ('fb.me', 'facebook'),
                  ('messenger', 'facebook'), ('tiktok', 'tiktok'), ('t.me', 'telegram'), ('telegram', 'telegram'),
                  ('whatsapp', 'whatsapp'), ('wa.me', 'whatsapp'), ('wolt', 'wolt'), ('youtube', 'youtube'),
                  ('google.', 'google'), ('seznam', 'seznam'), ('mapy.', 'seznam'), ('bing.', 'search'),
                  ('duckduckgo', 'search'), ('yahoo.', 'search'), ('yandex', 'search'), ('firmy.cz', 'seznam'),
                  ('pinterest', 'pinterest'), ('linkedin', 'linkedin'), ('lnkd.in', 'linkedin'), ('twitter', 'x'),
                  ('threads.', 'threads'), ('viber', 'viber'), ('reddit', 'reddit')]
_TRAFFIC_EXACT = {'x.com': 'x', 't.co': 'x', 'bing.com': 'bing', 'www.bing.com': 'bing'}
_TRAFFIC_PAID_MEDIUM = {'cpc', 'ppc', 'paid', 'paidsocial', 'paid_social', 'paid-social', 'ads', 'ad', 'cpm', 'sponsored', 'display'}
# click ids added only by ad networks (fbclid is not here: Facebook adds it to ordinary shared links too)
_TRAFFIC_AD_IDS = [('gclid', 'google'), ('gbraid', 'google'), ('wbraid', 'google'), ('gad_source', 'google'),
                   ('ttclid', 'tiktok'), ('sznclid', 'seznam'), ('msclkid', 'bing'), ('twclid', 'x')]
_TRAFFIC_UTM = {'ig': 'instagram', 'insta': 'instagram', 'fb': 'facebook', 'tg': 'telegram', 'wa': 'whatsapp', 'tt': 'tiktok',
                'sklik': 'seznam', 'adwords': 'google', 'twitter': 'x', 'meta': 'facebook'}

def _traffic_host(host):
    if host in _TRAFFIC_EXACT:
        return _TRAFFIC_EXACT[host]
    return next((v for k, v in _TRAFFIC_HOSTS if k in host), None)

def _traffic_source(req):
    if req is None:
        return None
    q = req.query_params
    from urllib.parse import urlparse
    ref = req.headers.get('referer') or ''
    host = (urlparse(ref).hostname or '').lower() if ref else ''
    own = (req.headers.get('host') or '').split(':')[0].lower()
    medium = (q.get('utm_medium') or '').lower().strip()
    paid = medium in _TRAFFIC_PAID_MEDIUM
    utm = re.sub(r'[^a-z0-9_-]', '', (q.get('utm_source') or '').lower())[:20]
    if utm:
        utm = _TRAFFIC_UTM.get(utm, utm)
        src = _TRAFFIC_EXACT.get(utm) or next((v for k, v in _TRAFFIC_HOSTS if k.rstrip('.') in utm), utm)
        return src + '_ads' if paid and not src.endswith('_ads') else src
    ad = next((v for k, v in _TRAFFIC_AD_IDS if q.get(k)), None)
    if ad:
        return ad + '_ads'
    if q.get('fbclid'):
        # Meta adds fbclid on Instagram too; the referer tells which app it was
        return ('instagram' if 'instagram' in host else 'facebook') + ('_ads' if paid else '')
    if not ref:
        return 'direct'
    if not host or host == own:
        return None
    src = _traffic_host(host) or 'other'
    return src + '_ads' if paid else src

def _inc_pageviews(req=None):
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
            src = _traffic_source(req)
            if src:
                row = conn.execute("SELECT value FROM settings WHERE key='traffic_daily'").fetchone()
                tr = _json.loads(row[0]) if row and row[0] else {}
                day = tr.setdefault(today, {})
                day[src] = day.get(src, 0) + 1
                tr = {k: v for k, v in tr.items() if time.mktime(time.strptime(k, '%Y-%m-%d')) >= cutoff}
                conn.execute(
                    "INSERT INTO settings(key,value) VALUES('traffic_daily',%s)"
                    " ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value",
                    (_json.dumps(tr),)
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
def _index(req: Request):
    _inc_pageviews(req)
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
def _static(path: str, req: Request):
    norm = os.path.normpath(path).replace(os.sep, '/')
    if (norm.startswith('..') or os.path.isabs(norm) or norm in _BLOCKED
            or any(part.startswith(('.', '_')) for part in norm.split('/'))
            or os.path.splitext(norm)[1].lower() not in _STATIC_EXT):
        raise HTTPException(404)
    if os.path.isfile(norm):
        if norm.endswith('.html') and norm not in _NO_TRACK:
            _inc_pageviews(req)
        return FileResponse(norm)
    raise HTTPException(404)

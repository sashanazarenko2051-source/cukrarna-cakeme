/* Custom cake builder (menu page). Opens a dialog: occasion → guests/size → filling →
   decor, inscription and example picture → price → cart. The server re-prices the cake
   from the same settings (/api/builder), requires the notice period and a 50 % deposit.
   Uses the menu page's globals: lang, getCart, saveCart, updateCartUI. */
(function(){
  const BT = {
    cs: {open:'🎂 Sestavit vlastní dort', ttl:'Dort na zakázku', occasion:'Příležitost', guests:'Počet hostů',
      guests_hint:'Napište počet hostů — doporučíme velikost.', size:'Velikost', filling:'Náplň', decor:'Zdobení',
      text:'Nápis na dortu (nepovinné)', text_ph:'např. Všechno nejlepší, Jano!', photo:'Obrázek-předloha (nepovinné)',
      photo_btn:'📷 Nahrát „chci takový“', photo_rm:'✕ Odebrat', guests_n:'{a}–{b} hostů', from:'od', total:'Cena',
      earliest:'Nejdříve k vyzvednutí {d} (objednávka {n} dní předem).', deposit:'Při objednávce zaplatíte zálohu 50 % kartou.',
      from_note:'Konečnou cenu potvrdí cukrář podle náročnosti zdobení.', add:'Do košíku', need:'Vyberte velikost a náplň.',
      added:'Dort je v košíku ✓', name:'Dort na zakázku', close:'Zavřít', recommended:'doporučeno'},
    en: {open:'🎂 Build your own cake', ttl:'Custom cake', occasion:'Occasion', guests:'Number of guests',
      guests_hint:'Enter the number of guests — we’ll suggest a size.', size:'Size', filling:'Filling', decor:'Decor',
      text:'Inscription (optional)', text_ph:'e.g. Happy birthday, Jana!', photo:'Example picture (optional)',
      photo_btn:'📷 Upload “I want this”', photo_rm:'✕ Remove', guests_n:'{a}–{b} guests', from:'from', total:'Price',
      earliest:'Earliest pickup {d} (order {n} days ahead).', deposit:'You pay a 50 % deposit by card when ordering.',
      from_note:'The pastry chef confirms the final price depending on the decor.', add:'Add to cart', need:'Choose a size and a filling.',
      added:'The cake is in your cart ✓', name:'Custom cake', close:'Close', recommended:'recommended'},
    uk: {open:'🎂 Зібрати свій торт', ttl:'Торт на замовлення', occasion:'Привід', guests:'Кількість гостей',
      guests_hint:'Вкажіть кількість гостей — підкажемо розмір.', size:'Розмір', filling:'Начинка', decor:'Декор',
      text:'Напис на торті (необов’язково)', text_ph:'напр. З днем народження, Яно!', photo:'Картинка-приклад (необов’язково)',
      photo_btn:'📷 Завантажити «хочу як тут»', photo_rm:'✕ Прибрати', guests_n:'{a}–{b} гостей', from:'від', total:'Ціна',
      earliest:'Найраніше отримання {d} (замовлення за {n} днів).', deposit:'При оформленні — передоплата 50 % карткою.',
      from_note:'Остаточну ціну кондитер підтвердить залежно від складності декору.', add:'До кошика', need:'Оберіть розмір і начинку.',
      added:'Торт у кошику ✓', name:'Торт на замовлення', close:'Закрити', recommended:'рекомендовано'},
  };
  const LOCALE = {cs:'cs-CZ', en:'en-GB', uk:'uk-UA'};
  const L = () => (typeof lang !== 'undefined' && BT[lang]) ? lang : 'cs';
  const tr = (k, v) => { let s = BT[L()][k]; Object.entries(v || {}).forEach(([a, b]) => s = s.replace('{'+a+'}', b)); return s; };
  const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const nm = x => (x.name && (x.name[L()] || x.name.cs)) || '';

  const css = `
.bld-open{display:inline-flex;align-items:center;gap:8px;background:var(--gold);color:var(--bg0);border:none;padding:13px 26px;font:700 .76rem 'Raleway',sans-serif;letter-spacing:2px;text-transform:uppercase;cursor:pointer;transition:.25s}
.bld-open:hover{background:var(--gold-l)}
.bld-ov{position:fixed;inset:0;background:rgba(0,0,0,.82);z-index:2500;display:flex;justify-content:center;align-items:flex-start;overflow-y:auto;padding:30px 14px}
.bld-box{background:var(--bg2,#161616);border:1px solid var(--gold-d);width:100%;max-width:780px;padding:30px;position:relative}
.bld-box h2{font-family:'Playfair Display',serif;font-weight:400;color:var(--tx0);font-size:1.8rem;margin-bottom:6px}
.bld-x{position:absolute;top:14px;right:16px;background:none;border:none;color:var(--gold);font-size:1.6rem;cursor:pointer}
.bld-step{margin-top:24px}
.bld-step h4{font-size:.72rem;letter-spacing:2px;text-transform:uppercase;color:var(--gold);margin-bottom:10px;font-weight:600}
.bld-chips{display:flex;flex-wrap:wrap;gap:8px}
.bld-chip{background:var(--bg3);border:1px solid var(--bdr);color:var(--tx0);padding:10px 14px;cursor:pointer;font:.82rem 'Raleway',sans-serif;text-align:left;transition:.2s}
.bld-chip small{display:block;color:var(--tx2);font-size:.7rem;margin-top:2px}
.bld-chip:hover{border-color:var(--gold)}
.bld-chip.on{border-color:var(--gold);background:rgba(201,169,110,.12);color:var(--gold)}
.bld-chip .rec{color:#8fcc8f;font-size:.62rem;letter-spacing:1px;text-transform:uppercase}
.bld-fills{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:10px}
.bld-fill{background:var(--bg3);border:1px solid var(--bdr);cursor:pointer;padding:0;text-align:left;color:var(--tx0);font:.82rem 'Raleway',sans-serif;transition:.2s}
.bld-fill span{display:block;height:100px;background:#111 center/cover no-repeat;display:flex;align-items:center;justify-content:center;font-size:2rem}
.bld-fill div{padding:8px 10px}.bld-fill small{display:block;color:var(--tx2);font-size:.7rem}
.bld-fill.on{border-color:var(--gold);box-shadow:inset 0 0 0 1px var(--gold)}
.bld-in{background:var(--bg3);border:1px solid var(--bdr);color:var(--tx0);padding:10px 12px;font:.9rem 'Raleway',sans-serif;outline:none;width:100%}
.bld-in:focus{border-color:var(--gold)}
.bld-guests{display:flex;gap:12px;align-items:center;flex-wrap:wrap}.bld-guests .bld-in{width:110px}
.bld-hint{font-size:.74rem;color:var(--tx2);margin-top:6px}
.bld-photo{display:flex;align-items:center;gap:12px;flex-wrap:wrap}.bld-photo img{height:80px;border:1px solid var(--bdr)}
.bld-ghost{background:none;border:1px solid var(--bdr);color:var(--tx1);padding:9px 14px;cursor:pointer;font:.8rem 'Raleway',sans-serif}
.bld-sum{margin-top:26px;padding-top:20px;border-top:1px solid var(--bdr);display:flex;justify-content:space-between;align-items:flex-end;gap:16px;flex-wrap:wrap}
.bld-price{font-family:'Playfair Display',serif;font-size:2rem;color:var(--gold)}
.bld-price small{display:block;font-family:'Raleway',sans-serif;font-size:.7rem;letter-spacing:2px;text-transform:uppercase;color:var(--tx2)}
.bld-notes{font-size:.76rem;color:var(--tx2);line-height:1.6;margin-top:12px}
.bld-msg{font-size:.82rem;color:#e08080;margin-top:8px;min-height:1em}.bld-msg.ok{color:#8fcc8f}
@media(max-width:600px){ .bld-box{padding:20px} .bld-box h2{font-size:1.4rem} }`;
  const st = document.createElement('style'); st.textContent = css; document.head.appendChild(st);

  let cfg = null, ov = null;
  const sel = {occasion: '', size: '', filling: '', decor: [], text: '', photo: '', guests: ''};

  async function loadCfg(){
    if (cfg) return cfg;
    try{ const r = await fetch('/api/builder'); if (r.ok) cfg = await r.json(); }catch{}
    return cfg;
  }

  function price(){
    const size = cfg.sizes.find(s => s.id === sel.size), fill = cfg.fillings.find(f => f.id === sel.filling);
    if (!size || !fill) return null;
    return size.price + fill.extra + cfg.decor.filter(d => sel.decor.includes(d.id)).reduce((a, d) => a + d.price, 0);
  }
  const minPrice = () => Math.min(...cfg.sizes.map(s => s.price)) + Math.min(0, ...cfg.fillings.map(f => f.extra));

  function render(){
    if (!ov) return;
    const n = parseInt(sel.guests) || 0;
    const rec = n ? (cfg.sizes.find(s => n >= s.min_guests && n <= s.max_guests) || (n > Math.max(...cfg.sizes.map(s => s.max_guests)) ? cfg.sizes[cfg.sizes.length - 1] : null)) : null;
    const p = price();
    const earliest = new Date(); earliest.setDate(earliest.getDate() + cfg.lead_days);
    const pref = cfg.price_mode === 'from' ? tr('from') + ' ' : '';
    ov.querySelector('.bld-box').innerHTML = `
      <button type="button" class="bld-x" aria-label="${tr('close')}">×</button>
      <h2>${tr('ttl')}</h2>
      ${cfg.occasions.length ? `<div class="bld-step"><h4>1 · ${tr('occasion')}</h4><div class="bld-chips">${cfg.occasions.map(o =>
        `<button type="button" class="bld-chip${sel.occasion === o.id ? ' on' : ''}" data-occ="${esc(o.id)}">${esc(nm(o))}</button>`).join('')}</div></div>` : ''}
      <div class="bld-step"><h4>2 · ${tr('guests')} / ${tr('size')}</h4>
        <div class="bld-guests"><input class="bld-in" type="number" min="1" max="300" value="${esc(sel.guests)}" data-guests><span class="bld-hint">${tr('guests_hint')}</span></div>
        <div class="bld-chips" style="margin-top:10px">${cfg.sizes.map(s =>
          `<button type="button" class="bld-chip${sel.size === s.id ? ' on' : ''}" data-size="${esc(s.id)}">${esc(s.label)}${rec && rec.id === s.id ? ` <span class="rec">✓ ${tr('recommended')}</span>` : ''}<small>${s.max_guests ? tr('guests_n', {a: s.min_guests, b: s.max_guests}) + ' · ' : ''}${s.price} Kč</small></button>`).join('')}</div></div>
      <div class="bld-step"><h4>3 · ${tr('filling')}</h4><div class="bld-fills">${cfg.fillings.map(f =>
        `<button type="button" class="bld-fill${sel.filling === f.id ? ' on' : ''}" data-fill="${esc(f.id)}"><span style="${f.img ? `background-image:url('${esc(f.img)}')` : ''}">${f.img ? '' : '🎂'}</span><div>${esc(nm(f))}${f.extra ? `<small>+ ${f.extra} Kč</small>` : ''}</div></button>`).join('')}</div></div>
      <div class="bld-step"><h4>4 · ${tr('decor')}</h4><div class="bld-chips">${cfg.decor.map(d =>
        `<button type="button" class="bld-chip${sel.decor.includes(d.id) ? ' on' : ''}" data-dec="${esc(d.id)}">${sel.decor.includes(d.id) ? '✓ ' : ''}${esc(nm(d))}<small>${d.price ? '+ ' + d.price + ' Kč' : '0 Kč'}</small></button>`).join('')}</div>
        <div class="bld-step" style="margin-top:16px"><h4 style="color:var(--tx1)">${tr('text')}</h4><input class="bld-in" maxlength="60" data-text value="${esc(sel.text)}" placeholder="${esc(tr('text_ph'))}"></div>
        <div class="bld-step" style="margin-top:16px"><h4 style="color:var(--tx1)">${tr('photo')}</h4><div class="bld-photo">
          <button type="button" class="bld-ghost" data-photo>${tr('photo_btn')}</button>${sel.photo ? `<img src="${sel.photo}" alt=""><button type="button" class="bld-ghost" data-photo-rm>${tr('photo_rm')}</button>` : ''}</div></div></div>
      <div class="bld-sum">
        <div class="bld-price"><small>${tr('total')}</small>${p != null ? pref + p + ' Kč' : tr('from') + ' ' + minPrice() + ' Kč'}</div>
        <button type="button" class="bld-open" data-add>${tr('add')}</button>
      </div>
      <div class="bld-msg"></div>
      <div class="bld-notes">${tr('earliest', {d: earliest.toLocaleDateString(LOCALE[L()], {day:'numeric', month:'long'}), n: cfg.lead_days})}<br>${tr('deposit')}${cfg.price_mode === 'from' ? '<br>' + tr('from_note') : ''}</div>`;
    bind(rec);
  }

  function bind(rec){
    const box = ov.querySelector('.bld-box');
    box.querySelector('.bld-x').onclick = close;
    box.querySelectorAll('[data-occ]').forEach(b => b.onclick = () => { sel.occasion = b.dataset.occ; render(); });
    box.querySelectorAll('[data-size]').forEach(b => b.onclick = () => { sel.size = b.dataset.size; render(); });
    box.querySelectorAll('[data-fill]').forEach(b => b.onclick = () => { sel.filling = b.dataset.fill; render(); });
    box.querySelectorAll('[data-dec]').forEach(b => b.onclick = () => {
      const id = b.dataset.dec; sel.decor = sel.decor.includes(id) ? sel.decor.filter(x => x !== id) : [...sel.decor, id]; render(); });
    const g = box.querySelector('[data-guests]');
    g.onchange = () => { sel.guests = g.value; const n = parseInt(g.value) || 0;
      const r = cfg.sizes.find(s => n >= s.min_guests && n <= s.max_guests) || (n > Math.max(...cfg.sizes.map(s => s.max_guests)) ? cfg.sizes[cfg.sizes.length - 1] : null);
      if (r) sel.size = r.id; render(); };
    box.querySelector('[data-text]').oninput = e => { sel.text = e.target.value; };
    box.querySelector('[data-photo]').onclick = () => {
      const inp = document.createElement('input'); inp.type = 'file'; inp.accept = 'image/*';
      inp.onchange = () => { const f = inp.files[0]; if (!f) return; const img = new Image();
        img.onload = () => { const k = Math.min(1, 1280 / Math.max(img.width, img.height)), c = document.createElement('canvas');
          c.width = Math.round(img.width * k); c.height = Math.round(img.height * k); c.getContext('2d').drawImage(img, 0, 0, c.width, c.height);
          sel.photo = c.toDataURL('image/jpeg', .8); URL.revokeObjectURL(img.src); render(); };
        img.src = URL.createObjectURL(f); };
      inp.click();
    };
    const rm = box.querySelector('[data-photo-rm]'); if (rm) rm.onclick = () => { sel.photo = ''; render(); };
    box.querySelector('[data-add]').onclick = () => addToCart(box);
  }

  function addToCart(box){
    const p = price(), msg = box.querySelector('.bld-msg');
    if (p == null){ msg.className = 'bld-msg'; msg.textContent = tr('need'); return; }
    const size = cfg.sizes.find(s => s.id === sel.size), fill = cfg.fillings.find(f => f.id === sel.filling);
    const cart = getCart();
    cart.push({id: 'b' + Date.now(), gi: -1, names: {cs: BT.cs.name, uk: BT.uk.name, en: BT.en.name}, price: p,
      sizeLabel: `${size.label} · ${nm(fill)}`, qty: 1,
      builder: {occasion: sel.occasion, size: sel.size, filling: sel.filling, decor: sel.decor.slice(), text: sel.text.trim(), photo: sel.photo}});
    try{ saveCart(cart); }catch{ msg.textContent = 'Storage full'; return; }
    Object.assign(sel, {occasion: '', size: '', filling: '', decor: [], text: '', photo: '', guests: ''});
    close();
    if (typeof updateCartUI === 'function') updateCartUI();
    const panel = document.getElementById('cartPanel'); if (panel) panel.classList.add('open');
  }

  async function open(){
    await loadCfg();
    if (!cfg || !cfg.enabled) return;
    ov = document.createElement('div'); ov.className = 'bld-ov'; ov.innerHTML = '<div class="bld-box"></div>';
    ov.addEventListener('click', e => { if (e.target === ov) close(); });
    document.body.appendChild(ov); document.body.style.overflow = 'hidden';
    render();
  }
  function close(){ if (ov){ ov.remove(); ov = null; document.body.style.overflow = ''; } }

  // Buttons: any element with data-builder-open gets the label and opens the dialog
  async function mount(){
    await loadCfg();
    document.querySelectorAll('[data-builder-open]').forEach(el => {
      el.style.display = cfg && cfg.enabled ? '' : 'none';
      el.innerHTML = `<button type="button" class="bld-open">${tr('open')}</button>`;
      el.querySelector('button').onclick = open;
    });
  }
  window.CakeBuilder = {open, refresh(){ mount(); if (ov) render(); }};
  mount();
})();

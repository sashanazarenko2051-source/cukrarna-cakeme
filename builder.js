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
      name:'Dort na zakázku', close:'Zavřít', full:'Fotka je příliš velká — vyberte prosím menší.', recommended:'doporučeno', free:'zdarma', number:'Jaké číslo?', number_ph:'např. 30', photo_print:'Fotka pro jedlý tisk', photo_hint:'Ukažte dort, který se vám líbí — cukrář se jím inspiruje.', banner_ttl:'Dort přesně podle vás', banner_sub:'Vyberte velikost, náplň a zdobení — cenu uvidíte hned.', steps:['Příležitost','Velikost','Náplň','Zdobení'], banner_btn:'Sestavit dort', bday_ttl:'🎉 Připomínka narozenin', bday_optin:'Pošlete mi e-mail {d} dní před mými narozeninami — s nabídkou dortu', bday_email:'Váš e-mail', bday_day:'Den', bday_month:'Měsíc', bday_note:'Jeden e-mail ročně, odhlásit se můžete kdykoli. Rok nepotřebujeme.', bday_need:'Vyplňte e-mail a datum narozenin (nebo zrušte připomínku).'},
    en: {open:'🎂 Build your own cake', ttl:'Custom cake', occasion:'Occasion', guests:'Number of guests',
      guests_hint:'Enter the number of guests — we’ll suggest a size.', size:'Size', filling:'Filling', decor:'Decor',
      text:'Inscription (optional)', text_ph:'e.g. Happy birthday, Jana!', photo:'Example picture (optional)',
      photo_btn:'📷 Upload “I want this”', photo_rm:'✕ Remove', guests_n:'{a}–{b} guests', from:'from', total:'Price',
      earliest:'Earliest pickup {d} (order {n} days ahead).', deposit:'You pay a 50 % deposit by card when ordering.',
      from_note:'The pastry chef confirms the final price depending on the decor.', add:'Add to cart', need:'Choose a size and a filling.',
      name:'Custom cake', close:'Close', full:'The photo is too large — please choose a smaller one.', recommended:'recommended', free:'free', number:'Which number?', number_ph:'e.g. 30', photo_print:'Photo for the edible print', photo_hint:'Show us a cake you like — the pastry chef will take it as inspiration.', banner_ttl:'Your dream cake', banner_sub:'Pick the size, filling and decor — see the price right away.', steps:['Occasion','Size','Filling','Decor'], banner_btn:'Build my cake', bday_ttl:'🎉 Birthday reminder', bday_optin:'E-mail me {d} days before my birthday — with a cake offer', bday_email:'Your e-mail', bday_day:'Day', bday_month:'Month', bday_note:'One e-mail a year, unsubscribe any time. We don’t need the year.', bday_need:'Fill in the e-mail and birthday (or untick the reminder).'},
    uk: {open:'🎂 Зібрати свій торт', ttl:'Торт на замовлення', occasion:'Привід', guests:'Кількість гостей',
      guests_hint:'Вкажіть кількість гостей — підкажемо розмір.', size:'Розмір', filling:'Начинка', decor:'Декор',
      text:'Напис на торті (необов’язково)', text_ph:'напр. З днем народження, Яно!', photo:'Картинка-приклад (необов’язково)',
      photo_btn:'📷 Завантажити «хочу як тут»', photo_rm:'✕ Прибрати', guests_n:'{a}–{b} гостей', from:'від', total:'Ціна',
      earliest:'Найраніше отримання {d} (замовлення за {n} днів).', deposit:'При оформленні — передоплата 50 % карткою.',
      from_note:'Остаточну ціну кондитер підтвердить залежно від складності декору.', add:'До кошика', need:'Оберіть розмір і начинку.',
      name:'Торт на замовлення', close:'Закрити', full:'Фото завелике — будь ласка, оберіть менше.', recommended:'рекомендовано', free:'безкоштовно', number:'Яке число?', number_ph:'напр. 30', photo_print:'Фото для їстівного друку', photo_hint:'Покажіть торт, який вам подобається, — кондитер надихнеться ним.', banner_ttl:'Торт вашої мрії', banner_sub:'Оберіть розмір, начинку й декор — ціну побачите одразу.', steps:['Привід','Розмір','Начинка','Декор'], banner_btn:'Зібрати торт', bday_ttl:'🎉 Нагадування про день народження', bday_optin:'Надішліть мені лист за {d} днів до мого дня народження — з пропозицією торта', bday_email:'Ваш e-mail', bday_day:'День', bday_month:'Місяць', bday_note:'Один лист на рік, відписатися можна будь-коли. Рік не потрібен.', bday_need:'Вкажіть e-mail і дату народження (або зніміть галочку).'},
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
.bld-fill{position:relative}
.bld-fill span.ph{font-family:'Playfair Display',serif;font-size:2.6rem;color:rgba(255,255,255,.55)}
.bld-fill-ok{position:absolute;top:8px;right:8px;width:24px;height:24px;border-radius:50%;background:var(--gold);color:var(--bg0);font:700 .8rem/24px 'Raleway',sans-serif;text-align:center;font-style:normal}
.bld-decor{display:grid;grid-template-columns:repeat(auto-fill,minmax(190px,1fr));gap:8px}
.bld-dec{display:flex;align-items:center;gap:12px;background:var(--bg3);border:1px solid var(--bdr);color:var(--tx0);padding:12px 14px;cursor:pointer;font:.86rem 'Raleway',sans-serif;text-align:left;transition:.2s}
.bld-dec:hover{border-color:var(--gold-d)}
.bld-dec.on{border-color:var(--gold);background:rgba(201,169,110,.1)}
.bld-dec-ic{font-size:1.4rem;width:28px;text-align:center;flex-shrink:0}
.bld-dec-t{flex:1;min-width:0}.bld-dec-t small{display:block;color:var(--tx2);font-size:.72rem;margin-top:2px}
.bld-dec.on .bld-dec-t small{color:var(--gold)}
.bld-tick{width:22px;height:22px;border:1px solid var(--bdr);flex-shrink:0;display:flex;align-items:center;justify-content:center;color:var(--bg0);font-weight:700;font-size:.8rem}
.bld-dec.on .bld-tick{background:var(--gold);border-color:var(--gold)}
.bld-sub{margin-top:14px;padding:14px;border-left:2px solid var(--gold-d);background:rgba(255,255,255,.015)}
.bld-bday{border:1px dashed var(--gold-d);padding:16px;background:rgba(201,169,110,.05)}
.bld-bday-chk{display:flex;gap:10px;align-items:flex-start;cursor:pointer;color:var(--tx0);font-size:.88rem;line-height:1.45}
.bld-bday-chk input{width:18px;height:18px;accent-color:var(--gold);flex-shrink:0;margin-top:1px}
.bld-bday-f{display:grid;grid-template-columns:minmax(0,2fr) minmax(0,.8fr) minmax(0,1.2fr);gap:8px;margin-top:12px}
@media(max-width:600px){ .bld-bday-f{grid-template-columns:1fr 1fr} .bld-bday-f [data-bday-email]{grid-column:1/-1} }
.bld-sub h5{font-size:.74rem;letter-spacing:1px;text-transform:uppercase;color:var(--tx1);margin-bottom:8px;font-weight:600}
/* Invitation banner under the menu title */
.bld-banner{position:relative;overflow:hidden;display:grid;grid-template-columns:auto minmax(0,1fr) auto;gap:28px;align-items:center;max-width:920px;margin:0 auto;padding:26px 32px;text-align:left;
  border:1px solid var(--gold-d);background:linear-gradient(120deg,rgba(201,169,110,.16),rgba(201,169,110,.03) 45%,rgba(201,169,110,.12))}
.bld-banner::before{content:'';position:absolute;inset:0;pointer-events:none;background:linear-gradient(110deg,transparent 35%,rgba(232,213,163,.13) 50%,transparent 65%);transform:translateX(-100%);animation:bldShine 6s ease-in-out infinite}
@keyframes bldShine{0%,55%{transform:translateX(-100%)}100%{transform:translateX(100%)}}
.bld-banner-ic{width:86px;height:86px;border-radius:50%;border:1px solid var(--gold-d);background:radial-gradient(circle,rgba(201,169,110,.25),rgba(10,10,10,.6));display:flex;align-items:center;justify-content:center;font-size:2.6rem}
.bld-banner h3{font-family:'Playfair Display',serif;font-weight:400;font-size:1.7rem;color:var(--tx0);margin-bottom:6px}
.bld-banner p{color:var(--tx1);font-size:.88rem;margin-bottom:12px;line-height:1.5}
.bld-steps{display:flex;flex-wrap:wrap;gap:6px}
.bld-steps span{font-size:.64rem;letter-spacing:1.5px;text-transform:uppercase;color:var(--gold);border:1px solid rgba(201,169,110,.35);padding:4px 9px;background:rgba(10,10,10,.35)}
.bld-banner-cta{display:flex;flex-direction:column;align-items:center;gap:10px}
.bld-banner-price{font-family:'Playfair Display',serif;color:var(--gold);font-size:1.5rem;white-space:nowrap}
.bld-banner-price small{font-family:'Raleway',sans-serif;font-size:.7rem;letter-spacing:2px;text-transform:uppercase;color:var(--tx2)}
@media(prefers-reduced-motion:reduce){ .bld-banner::before{animation:none} }
@media(max-width:760px){ .bld-banner{grid-template-columns:1fr;text-align:center;padding:24px 18px;gap:16px} .bld-banner-ic{margin:0 auto;width:70px;height:70px;font-size:2.1rem}
  .bld-steps{justify-content:center} .bld-banner h3{font-size:1.4rem} }
@media(max-width:600px){ .bld-box{padding:20px} .bld-box h2{font-size:1.4rem} .bld-decor{grid-template-columns:1fr} }`;
  const st = document.createElement('style'); st.textContent = css; document.head.appendChild(st);

  let cfg = null, ov = null, bdayDays = 0;
  const bday = {on: false, email: '', d: '', m: ''};
  const sel = {occasion: '', size: '', filling: '', decor: [], text: '', number: '', photo: '', guests: ''};
  const DECOR_IC = {text: '✍️', number: '🔢', flowers: '💐', figures: '🧸', photo: '📷'};

  async function loadCfg(){
    if (cfg) return cfg;
    try{ const r = await fetch('/api/builder'); if (r.ok) cfg = await r.json(); }catch{}
    try{ const r = await fetch('/api/bday/status'); const j = r.ok ? await r.json() : {}; bdayDays = j.on ? j.days : 0; }catch{}
    try{ Object.assign(bday, JSON.parse(localStorage.getItem('cakeme_bday') || '{}')); }catch{}
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
        `<button type="button" class="bld-fill${sel.filling === f.id ? ' on' : ''}" data-fill="${esc(f.id)}">${f.img
          ? `<span style="background-image:url('${esc(f.img)}')"></span>`
          : `<span class="ph" style="${phBg(f.id)}">${esc(nm(f).charAt(0))}</span>`}${sel.filling === f.id ? '<i class="bld-fill-ok">✓</i>' : ''}<div>${esc(nm(f))}${f.extra ? `<small>+ ${f.extra} Kč</small>` : ''}</div></button>`).join('')}</div></div>
      <div class="bld-step"><h4>4 · ${tr('decor')}</h4><div class="bld-decor">${cfg.decor.map(d => { const on = sel.decor.includes(d.id);
        return `<button type="button" class="bld-dec${on ? ' on' : ''}" data-dec="${esc(d.id)}"><span class="bld-dec-ic">${DECOR_IC[d.id] || '✨'}</span>
          <span class="bld-dec-t">${esc(nm(d))}<small>${d.price ? '+ ' + d.price + ' Kč' : tr('free')}</small></span><span class="bld-tick">${on ? '✓' : ''}</span></button>`; }).join('')}</div>
        ${decorExtras()}
        <div class="bld-sub"><h5>${sel.decor.includes('photo') ? tr('photo_print') : tr('photo')}</h5><p class="bld-hint" style="margin:0 0 8px">${tr('photo_hint')}</p><div class="bld-photo">
          <button type="button" class="bld-ghost" data-photo>${tr('photo_btn')}</button>${sel.photo ? `<img src="${sel.photo}" alt=""><button type="button" class="bld-ghost" data-photo-rm>${tr('photo_rm')}</button>` : ''}</div></div></div>
      ${bdayHtml()}
      <div class="bld-sum">
        <div class="bld-price"><small>${tr('total')}</small>${p != null ? pref + p + ' Kč' : tr('from') + ' ' + minPrice() + ' Kč'}</div>
        <button type="button" class="bld-open" data-add>${tr('add')}</button>
      </div>
      <div class="bld-msg"></div>
      <div class="bld-notes">${tr('earliest', {d: earliest.toLocaleDateString(LOCALE[L()], {day:'numeric', month:'long'}), n: cfg.lead_days})}<br>${tr('deposit')}${cfg.price_mode === 'from' ? '<br>' + tr('from_note') : ''}</div>`;
    bind(rec);
  }

  // Fields that belong to a chosen decor appear right under the choices
  function decorExtras(){
    const has = id => cfg.decor.some(d => d.id === id);
    const out = [];
    if (sel.decor.includes('text') || !has('text'))
      out.push(`<div class="bld-sub"><h5>✍️ ${tr('text')}</h5><input class="bld-in" maxlength="60" data-text value="${esc(sel.text)}" placeholder="${esc(tr('text_ph'))}"></div>`);
    if (sel.decor.includes('number'))
      out.push(`<div class="bld-sub"><h5>🔢 ${tr('number')}</h5><input class="bld-in" style="width:120px" inputmode="numeric" maxlength="3" data-number value="${esc(sel.number || '')}" placeholder="${esc(tr('number_ph'))}"></div>`);
    return out.join('');
  }
  // Optional birthday reminder: saved locally, the order form sends it with the order
  function bdayHtml(){
    if (!bdayDays) return '';
    const loc = LOCALE[L()];
    const opt = (v, t, cur) => `<option value="${v}"${v === cur ? ' selected' : ''}>${t}</option>`;
    return `<div class="bld-step bld-bday"><h4>${tr('bday_ttl')}</h4>
      <label class="bld-bday-chk"><input type="checkbox" data-bday-on${bday.on ? ' checked' : ''}> <span>${tr('bday_optin', {d: bdayDays})}</span></label>
      ${bday.on ? `<div class="bld-bday-f">
        <input class="bld-in" type="email" maxlength="254" autocomplete="email" data-bday-email value="${esc(bday.email)}" placeholder="${esc(tr('bday_email'))}">
        <select class="bld-in" data-bday-d>${opt('', tr('bday_day'), bday.d)}${[...Array(31)].map((_, i) => opt(String(i + 1).padStart(2, '0'), i + 1, bday.d)).join('')}</select>
        <select class="bld-in" data-bday-m>${opt('', tr('bday_month'), bday.m)}${[...Array(12)].map((_, i) => opt(String(i + 1).padStart(2, '0'), new Date(2024, i, 1).toLocaleDateString(loc, {month: 'long'}), bday.m)).join('')}</select>
      </div><p class="bld-hint">${tr('bday_note')}</p>` : ''}</div>`;
  }
  const saveBday = () => { try{ localStorage.setItem('cakeme_bday', JSON.stringify(bday)); }catch{} };

  // Soft colour block with the first letter for a filling without a photo
  function phBg(id){
    let h = 0; for (const ch of String(id)) h = (h * 31 + ch.charCodeAt(0)) % 360;
    return `background:linear-gradient(135deg,hsl(${h} 32% 26%),hsl(${(h + 40) % 360} 38% 12%))`;
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
    const txt = box.querySelector('[data-text]'); if (txt) txt.oninput = e => { sel.text = e.target.value; };
    const num = box.querySelector('[data-number]'); if (num) num.oninput = e => { e.target.value = e.target.value.replace(/\D/g, ''); sel.number = e.target.value; };
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
    const bon = box.querySelector('[data-bday-on]'); if (bon) bon.onchange = () => { bday.on = bon.checked; saveBday(); render(); };
    [['[data-bday-email]', 'email'], ['[data-bday-d]', 'd'], ['[data-bday-m]', 'm']].forEach(([q, k]) => {
      const e = box.querySelector(q); if (e) e[e.tagName === 'SELECT' ? 'onchange' : 'oninput'] = () => { bday[k] = e.value.trim(); saveBday(); }; });
    box.querySelector('[data-add]').onclick = () => addToCart(box);
  }

  function addToCart(box){
    const p = price(), msg = box.querySelector('.bld-msg');
    if (p == null){ msg.className = 'bld-msg'; msg.textContent = tr('need'); return; }
    if (bdayDays && bday.on && (!/^[^@\s]+@[^@\s]+\.[^@\s]{2,}$/.test(bday.email) || !bday.d || !bday.m)){ msg.className = 'bld-msg'; msg.textContent = tr('bday_need'); return; }
    const size = cfg.sizes.find(s => s.id === sel.size), fill = cfg.fillings.find(f => f.id === sel.filling);
    const cart = getCart();
    cart.push({id: 'b' + Date.now(), gi: -1, names: {cs: BT.cs.name, uk: BT.uk.name, en: BT.en.name}, price: p,
      sizeLabel: `${size.label} · ${nm(fill)}`, qty: 1,
      builder: {occasion: sel.occasion, size: sel.size, filling: sel.filling, decor: sel.decor.slice(), text: sel.text.trim(),
                number: sel.decor.includes('number') ? sel.number : '', photo: sel.photo}});
    try{ saveCart(cart); }catch{ msg.textContent = tr('full'); return; }
    Object.assign(sel, {occasion: '', size: '', filling: '', decor: [], text: '', number: '', photo: '', guests: ''});
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
      if (!cfg || !cfg.enabled) return;
      // data-builder-open="banner": the big invitation under the menu title; otherwise a plain button
      el.innerHTML = el.dataset.builderOpen === 'banner' ? `
        <div class="bld-banner">
          <div class="bld-banner-ic">🎂</div>
          <div class="bld-banner-txt">
            <h3>${tr('banner_ttl')}</h3>
            <p>${tr('banner_sub')}</p>
            <div class="bld-steps">${BT[L()].steps.map((s, i) => `<span>${i + 1} · ${s}</span>`).join('')}</div>
          </div>
          <div class="bld-banner-cta">
            <div class="bld-banner-price"><small>${tr('from')}</small> ${minPrice()} Kč</div>
            <button type="button" class="bld-open">${tr('banner_btn')} →</button>
          </div>
        </div>` : `<button type="button" class="bld-open">${tr('open')}</button>`;
      el.querySelector('button').onclick = open;
    });
  }
  window.CakeBuilder = {open, refresh(){ mount(); if (ov) render(); }};
  mount();
})();

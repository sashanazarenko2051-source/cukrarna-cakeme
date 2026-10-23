/* Customer reviews: full block (home page) and a one-line rating (menu page).
   Uses the page's global `lang` (cs / en / uk) and its CSS variables.
   Usage: <div data-reviews="full"></div> or <div data-reviews="summary"></div>,
   then CakeReviews.refresh() after a language change. */
(function(){
  const RT = {
    cs: {lbl:'Co říkají zákazníci', ttl:'Recenze', none:'Zatím žádné recenze — buďte první!', reviews:['recenze','recenze','recenzí'],
      write:'Napsat recenzi', more:'Zobrazit další', verified:'Ověřený zákazník', reply:'Odpověď cukrárny',
      f_stars:'Vaše hodnocení', f_name:'Jméno', f_text:'Vaše recenze', f_item:'Co jste si objednali (nepovinné)',
      f_phone:'Telefon z objednávky (nepovinné)', f_phone_hint:'Jen pro označení „Ověřený zákazník“. Nikde se nezobrazuje.',
      f_photo:'Fotka (nepovinné)', f_photo_btn:'📷 Přidat fotku', f_photo_rm:'✕ Odebrat', f_send:'Odeslat recenzi',
      f_need:'Vyberte hvězdičky, vyplňte jméno a text recenze.', f_big:'Fotka je příliš velká (max 10 MB).',
      f_ok:'Děkujeme! Recenze se zobrazí po kontrole.', f_err:'Nepodařilo se odeslat. Zkuste to prosím znovu.', f_limit:'Příliš mnoho recenzí za krátkou dobu. Zkuste to později.',
      honest:'Recenze zveřejňujeme po kontrole spamu, negativní recenze nemažeme a hodnocení neupravujeme. Označení „Ověřený zákazník“ znamená, že telefon souhlasí s objednávkou.'},
    en: {lbl:'What customers say', ttl:'Reviews', none:'No reviews yet — be the first!', reviews:['review','reviews','reviews'],
      write:'Write a review', more:'Show more', verified:'Verified customer', reply:'Reply from the shop',
      f_stars:'Your rating', f_name:'Name', f_text:'Your review', f_item:'What did you order (optional)',
      f_phone:'Phone used for the order (optional)', f_phone_hint:'Only for the “Verified customer” badge. Never shown.',
      f_photo:'Photo (optional)', f_photo_btn:'📷 Add a photo', f_photo_rm:'✕ Remove', f_send:'Send review',
      f_need:'Choose the stars and fill in your name and review.', f_big:'The photo is too large (max 10 MB).',
      f_ok:'Thank you! Your review will appear after a check.', f_err:'Could not send. Please try again.', f_limit:'Too many reviews in a short time. Please try later.',
      honest:'Reviews are published after a spam check; we don’t delete negative reviews or change ratings. “Verified customer” means the phone matches an order.'},
    uk: {lbl:'Що кажуть клієнти', ttl:'Відгуки', none:'Поки що немає відгуків — будьте першим!', reviews:['відгук','відгуки','відгуків'],
      write:'Залишити відгук', more:'Показати ще', verified:'Перевірений покупець', reply:'Відповідь кондитерської',
      f_stars:'Ваша оцінка', f_name:'Ім’я', f_text:'Ваш відгук', f_item:'Що ви замовляли (необов’язково)',
      f_phone:'Телефон із замовлення (необов’язково)', f_phone_hint:'Лише для позначки «Перевірений покупець». Ніде не показується.',
      f_photo:'Фото (необов’язково)', f_photo_btn:'📷 Додати фото', f_photo_rm:'✕ Прибрати', f_send:'Надіслати відгук',
      f_need:'Оберіть зірки, вкажіть ім’я та напишіть відгук.', f_big:'Фото завелике (макс. 10 МБ).',
      f_ok:'Дякуємо! Відгук з’явиться після перевірки.', f_err:'Не вдалося надіслати. Спробуйте ще раз.', f_limit:'Забагато відгуків за короткий час. Спробуйте пізніше.',
      honest:'Відгуки публікуються після перевірки на спам; ми не видаляємо негативні відгуки й не змінюємо оцінки. «Перевірений покупець» — телефон збігається із замовленням.'},
  };
  const LOCALE = {cs:'cs-CZ', en:'en-GB', uk:'uk-UA'};
  const L = () => (typeof lang !== 'undefined' && RT[lang]) ? lang : 'cs';
  const tr = k => RT[L()][k];
  const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const starsHtml = (n, cls='') => `<span class="rv-stars ${cls}" aria-label="${n}/5">${'★'.repeat(Math.round(n))}<span>${'★'.repeat(5 - Math.round(n))}</span></span>`;
  const plural = n => { const f = tr('reviews'); if (L() === 'en') return n === 1 ? f[0] : f[1];
    if (L() === 'uk') { const m10 = n % 10, m100 = n % 100; return m10 === 1 && m100 !== 11 ? f[0] : m10 >= 2 && m10 <= 4 && (m100 < 10 || m100 >= 20) ? f[1] : f[2]; }
    return n === 1 ? f[0] : n >= 2 && n <= 4 ? f[1] : f[2]; };
  const fmtAvg = a => a.toLocaleString(LOCALE[L()], {minimumFractionDigits: 1, maximumFractionDigits: 1});

  const css = `
.rv-stars{color:var(--gold);letter-spacing:2px}.rv-stars span{color:#3a3a3a}
.rv-sum{display:grid;grid-template-columns:auto minmax(0,1fr) auto;gap:32px;align-items:center;background:var(--bg3,#1c1c1c);border:1px solid var(--bdr,#242424);padding:28px 32px;margin-bottom:28px}
.rv-avg{text-align:center}.rv-avg b{display:block;font-family:'Playfair Display',serif;font-size:3.2rem;font-weight:400;color:var(--tx0,#f5f0e8);line-height:1}
.rv-avg .rv-stars{font-size:1.1rem}.rv-avg small{display:block;color:var(--tx2,#777);font-size:.78rem;margin-top:6px}
.rv-bars{display:flex;flex-direction:column;gap:5px}
.rv-bar{display:grid;grid-template-columns:28px minmax(0,1fr) 28px;gap:10px;align-items:center;font-size:.72rem;color:var(--tx2,#777)}
.rv-bar i{display:block;height:6px;background:#2a2a2a;position:relative}.rv-bar i em{position:absolute;inset:0 auto 0 0;background:var(--gold)}
.rv-btn{background:var(--gold);color:var(--bg0,#0a0a0a);border:none;padding:13px 24px;font:700 .74rem 'Raleway',sans-serif;letter-spacing:2px;text-transform:uppercase;cursor:pointer;white-space:nowrap}
.rv-btn:hover{background:var(--gold-l,#e8d5a3)}
.rv-list{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:18px}
.rv-card{background:var(--bg3,#1c1c1c);border:1px solid var(--bdr,#242424);padding:22px;display:flex;flex-direction:column;gap:10px}
.rv-head{display:flex;justify-content:space-between;gap:10px;align-items:flex-start}
.rv-name{color:var(--tx0,#f5f0e8);font-weight:600;font-size:.92rem}.rv-date{color:var(--tx2,#777);font-size:.72rem}
.rv-ver{display:inline-block;font-size:.62rem;letter-spacing:1px;text-transform:uppercase;color:#8fcc8f;border:1px solid #3d5a3d;padding:2px 7px;margin-top:4px}
.rv-text{color:var(--tx1,#c8b898);font-size:.86rem;line-height:1.65;white-space:pre-line;overflow-wrap:anywhere}
.rv-item{font-size:.7rem;color:var(--gold);letter-spacing:.5px}
.rv-photo{width:100%;max-height:260px;object-fit:cover;cursor:zoom-in;border:1px solid var(--bdr,#242424)}
.rv-reply{border-left:2px solid var(--gold-d,#9a7a4a);padding:6px 0 6px 12px;font-size:.8rem;color:var(--tx2,#999)}.rv-reply b{display:block;color:var(--gold);font-size:.7rem;letter-spacing:1px;text-transform:uppercase;margin-bottom:3px}
.rv-more{display:block;margin:22px auto 0;background:none;border:1px solid var(--gold-d,#9a7a4a);color:var(--gold);padding:10px 22px;cursor:pointer;font:.72rem 'Raleway',sans-serif;letter-spacing:1.5px;text-transform:uppercase}
.rv-none{text-align:center;color:var(--tx2,#777);padding:20px 0}
.rv-honest{text-align:center;color:var(--tx2,#666);font-size:.72rem;margin-top:22px;line-height:1.6}
.rv-form{background:var(--bg3,#1c1c1c);border:1px solid var(--gold-d,#9a7a4a);padding:26px;margin-bottom:28px;display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:16px}
.rv-form .full{grid-column:1/-1}
.rv-form label{display:flex;flex-direction:column;gap:7px;font-size:.7rem;letter-spacing:1.5px;text-transform:uppercase;color:var(--tx1,#c8b898)}
.rv-form input,.rv-form textarea{background:var(--bg2,#161616);border:1px solid var(--bdr,#242424);color:var(--tx0,#f5f0e8);padding:11px 13px;font:.9rem 'Raleway',sans-serif;outline:none;text-transform:none;letter-spacing:0}
.rv-form input:focus,.rv-form textarea:focus{border-color:var(--gold)}
.rv-form textarea{min-height:110px;resize:vertical}
.rv-form small{text-transform:none;letter-spacing:0;color:var(--tx2,#777);font-size:.72rem}
.rv-pick{display:flex;gap:4px}.rv-pick button{background:none;border:none;font-size:2rem;color:#3a3a3a;cursor:pointer;padding:0 2px;line-height:1;transition:.15s}
.rv-pick button.on{color:var(--gold)}
.rv-photo-row{display:flex;align-items:center;gap:12px;flex-wrap:wrap}
.rv-photo-row img{height:70px;border:1px solid var(--bdr,#242424)}
.rv-ghost{background:none;border:1px solid var(--bdr,#333);color:var(--tx1,#c8b898);padding:9px 14px;cursor:pointer;font:.78rem 'Raleway',sans-serif}
.rv-msg{font-size:.85rem}.rv-msg.ok{color:#8fcc8f}.rv-msg.err{color:#e08080}
.rv-hp{position:absolute;left:-9999px;width:1px;height:1px;opacity:0}
.rv-lb{position:fixed;inset:0;background:rgba(0,0,0,.88);z-index:3000;display:flex;align-items:center;justify-content:center;cursor:zoom-out;padding:20px}
.rv-lb img{max-width:100%;max-height:100%}
.rv-line{display:inline-flex;align-items:center;gap:8px;color:var(--tx1,#c8b898);font-size:.85rem;text-decoration:none;border-bottom:1px solid transparent}
.rv-line:hover{border-bottom-color:var(--gold)}.rv-line b{color:var(--tx0,#f5f0e8)}
@media(max-width:700px){ .rv-sum{grid-template-columns:1fr;gap:18px;padding:22px} .rv-form{grid-template-columns:1fr;padding:18px} .rv-list{grid-template-columns:1fr} }`;
  const style = document.createElement('style'); style.textContent = css; document.head.appendChild(style);

  let data = null, shown = 6, formOpen = false, rating = 0, photoData = '', msg = null;

  async function load(){
    try{ const r = await fetch('/api/reviews'); if (r.ok) data = await r.json(); }catch{}
    render();
    // Coming from the menu's rating link: the block was empty when the browser tried to scroll
    if (location.hash === '#reviews'){ const t = document.getElementById('reviews'); if (t) t.scrollIntoView(); }
  }

  function cardHtml(rv){
    const date = new Date(rv.ts).toLocaleDateString(LOCALE[L()], {day:'numeric', month:'long', year:'numeric'});
    return `<div class="rv-card">
      <div class="rv-head"><div><div class="rv-name">${esc(rv.name)}</div>${rv.verified ? `<span class="rv-ver">✓ ${tr('verified')}</span>` : ''}</div>
        <div style="text-align:right">${starsHtml(rv.stars)}<div class="rv-date">${esc(date)}</div></div></div>
      ${rv.item ? `<div class="rv-item">${esc(rv.item)}</div>` : ''}
      <div class="rv-text">${esc(rv.text)}</div>
      ${rv.photo ? `<img class="rv-photo" src="${esc(rv.photo)}" alt="" loading="lazy">` : ''}
      ${rv.reply ? `<div class="rv-reply"><b>${tr('reply')}</b>${esc(rv.reply)}</div>` : ''}
    </div>`;
  }

  function formHtml(){
    return `<form class="rv-form" novalidate>
      <label class="full">${tr('f_stars')}<div class="rv-pick">${[1,2,3,4,5].map(n=>`<button type="button" data-n="${n}" class="${n <= rating ? 'on' : ''}">★</button>`).join('')}</div></label>
      <label>${tr('f_name')}<input name="name" maxlength="60" autocomplete="name"></label>
      <label>${tr('f_item')}<input name="ordered" maxlength="120"></label>
      <label class="full">${tr('f_text')}<textarea name="text" maxlength="1500"></textarea></label>
      <label>${tr('f_phone')}<input name="phone" type="tel" maxlength="20" autocomplete="tel"><small>${tr('f_phone_hint')}</small></label>
      <label>${tr('f_photo')}<div class="rv-photo-row"><button type="button" class="rv-ghost rv-add-photo">${tr('f_photo_btn')}</button><input type="file" accept="image/*" hidden></div></label>
      <input class="rv-hp" name="website" tabindex="-1" autocomplete="off">
      <div class="full" style="display:flex;gap:16px;align-items:center;flex-wrap:wrap"><button class="rv-btn" type="submit">${tr('f_send')}</button><span class="rv-msg"></span></div>
    </form>`;
  }

  function render(){
    document.querySelectorAll('[data-reviews]').forEach(el => el.dataset.reviews === 'summary' ? renderLine(el) : renderFull(el));
  }

  function renderLine(el){
    const s = data && data.summary;
    if (!s || !s.count){ el.innerHTML = ''; return; }
    el.innerHTML = `<a class="rv-line" href="index.html#reviews">${starsHtml(s.avg)} <b>${fmtAvg(s.avg)}</b> · ${s.count} ${plural(s.count)}</a>`;
  }

  function renderFull(el){
    const s = (data && data.summary) || {count:0, avg:0, dist:{}}, list = (data && data.reviews) || [];
    const max = Math.max(1, ...Object.values(s.dist || {}));
    el.innerHTML = `
      <div class="sec-hd fi show"><span class="sec-lbl">${tr('lbl')}</span><h2 class="sec-ttl">${tr('ttl')}</h2><div class="sec-div"></div></div>
      <div class="rv-sum">
        <div class="rv-avg"><b>${s.count ? fmtAvg(s.avg) : '—'}</b>${starsHtml(s.avg)}<small>${s.count} ${plural(s.count)}</small></div>
        <div class="rv-bars">${[5,4,3,2,1].map(n=>`<div class="rv-bar"><span>${n} ★</span><i><em style="width:${Math.round((s.dist[n]||0)/max*100)}%"></em></i><span>${s.dist[n]||0}</span></div>`).join('')}</div>
        <button type="button" class="rv-btn rv-open">${tr('write')}</button>
      </div>
      <div class="rv-form-box">${formOpen ? formHtml() : ''}</div>
      ${list.length ? `<div class="rv-list">${list.slice(0, shown).map(cardHtml).join('')}</div>` : `<p class="rv-none">${tr('none')}</p>`}
      ${list.length > shown ? `<button type="button" class="rv-more">${tr('more')}</button>` : ''}
      <p class="rv-honest">${tr('honest')}</p>`;
    el.querySelector('.rv-open').onclick = () => { formOpen = !formOpen; render(); if (formOpen) el.querySelector('.rv-form').scrollIntoView({behavior:'smooth', block:'center'}); };
    const more = el.querySelector('.rv-more'); if (more) more.onclick = () => { shown += 6; render(); };
    el.querySelectorAll('.rv-photo').forEach(img => img.onclick = () => {
      const lb = document.createElement('div'); lb.className = 'rv-lb'; lb.innerHTML = `<img src="${esc(img.src)}" alt="">`;
      lb.onclick = () => lb.remove(); document.body.appendChild(lb);
    });
    if (formOpen) bindForm(el.querySelector('.rv-form'));
  }

  function bindForm(form){
    const msgEl = form.querySelector('.rv-msg');
    if (msg){ msgEl.className = 'rv-msg ' + msg[0]; msgEl.textContent = tr(msg[1]); }
    form.querySelectorAll('.rv-pick button').forEach(b => b.onclick = () => {
      rating = +b.dataset.n; form.querySelectorAll('.rv-pick button').forEach(x => x.classList.toggle('on', +x.dataset.n <= rating));
    });
    const file = form.querySelector('input[type=file]'), row = form.querySelector('.rv-photo-row');
    const showPhoto = () => {
      row.querySelectorAll('img,.rv-rm').forEach(x => x.remove());
      if (!photoData) return;
      row.insertAdjacentHTML('beforeend', `<img src="${photoData}" alt=""><button type="button" class="rv-ghost rv-rm">${tr('f_photo_rm')}</button>`);
      row.querySelector('.rv-rm').onclick = () => { photoData = ''; showPhoto(); };
    };
    showPhoto();
    form.querySelector('.rv-add-photo').onclick = () => file.click();
    file.onchange = () => {
      const f = file.files[0]; if (!f) return;
      if (f.size > 10 * 1024 * 1024){ msgEl.className = 'rv-msg err'; msgEl.textContent = tr('f_big'); return; }
      const img = new Image();
      img.onload = () => {  // shrink to max 1280 px, JPEG: a phone photo becomes ~150–300 KB
        const k = Math.min(1, 1280 / Math.max(img.width, img.height));
        const c = document.createElement('canvas'); c.width = Math.round(img.width * k); c.height = Math.round(img.height * k);
        c.getContext('2d').drawImage(img, 0, 0, c.width, c.height);
        photoData = c.toDataURL('image/jpeg', 0.8); URL.revokeObjectURL(img.src); showPhoto();
      };
      img.src = URL.createObjectURL(f);
    };
    form.onsubmit = async e => {
      e.preventDefault();
      // querySelector, not form.elements[n]: names like "item" clash with built-in form methods
      const v = n => (form.querySelector(`[name="${n}"]`) || {value: ''}).value.trim();
      if (!rating || !v('name') || v('text').length < 3){ msgEl.className = 'rv-msg err'; msgEl.textContent = tr('f_need'); return; }
      const btn = form.querySelector('button[type=submit]'); btn.disabled = true;
      try{
        const r = await fetch('/api/reviews', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({
          stars: rating, name: v('name'), text: v('text'), item: v('ordered'), phone: v('phone'), photo: photoData, website: v('website')})});
        if (r.ok){ rating = 0; photoData = ''; form.reset(); showPhoto(); form.querySelectorAll('.rv-pick button').forEach(x => x.classList.remove('on')); msg = ['ok', 'f_ok']; }
        else msg = ['err', r.status === 429 ? 'f_limit' : 'f_err'];
      }catch{ msg = ['err', 'f_err']; }
      btn.disabled = false; msgEl.className = 'rv-msg ' + msg[0]; msgEl.textContent = tr(msg[1]);
    };
  }

  window.CakeReviews = {refresh: render, reload: load};
  load();
})();

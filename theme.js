/* Seasonal look of the site (New Year, Christmas, Halloween, Valentine's, Easter), switched on in the admin.
   Adds a light garland under the menu bar, a small emoji on the logo, falling snow / leaves / hearts
   and a greeting card. ?theme=<id> previews a theme without saving it (used by the admin). */
(() => {
  const THEMES = {
    new_year: {logo: '🥂', fx: 'snow', bulbs: ['#f5d67a', '#ffffff', '#c9a96e', '#9fd3ff'], icon: '🎆',
      greet: {cs: 'Šťastný nový rok!', uk: 'З Новим роком!', en: 'Happy New Year!'},
      sub: {cs: 'Oslavte ho s dortem od nás — objednejte včas.', uk: 'Святкуйте з нашим тортом — замовляйте завчасно.', en: 'Celebrate with one of our cakes — order in good time.'}},
    christmas: {logo: '🎄', fx: 'snow', bulbs: ['#e5484d', '#f5d67a', '#3fa66b', '#6fb7ff'], icon: '🎄',
      greet: {cs: 'Veselé Vánoce!', uk: 'Веселого Різдва!', en: 'Merry Christmas!'},
      sub: {cs: 'Vánoční cukroví a dorty — objednejte si včas.', uk: 'Різдвяне печиво й торти — замовляйте завчасно.', en: 'Christmas cookies and cakes — order in good time.'}},
    halloween: {logo: '🎃', fx: ['🍂', '🦇', '🍁'], bulbs: ['#ff8a1f', '#8e4bd6', '#ffb347', '#5a2a82'], icon: '🎃',
      greet: {cs: 'Strašidelný Halloween!', uk: 'Моторошного Хелловіну!', en: 'Happy Halloween!'},
      sub: {cs: 'Sladkosti, nebo psota? U nás rozhodně sladkosti.', uk: 'Солодощі чи капость? У нас — точно солодощі.', en: 'Trick or treat? Here it’s definitely treats.'}},
    valentine: {logo: '💝', fx: ['❤️', '💕', '💗'], bulbs: ['#ff5d8f', '#ffd1dc', '#e5484d', '#ff9eb5'], icon: '💝',
      greet: {cs: 'Šťastného Valentýna!', uk: 'З Днем закоханих!', en: 'Happy Valentine’s Day!'},
      sub: {cs: 'Sladký dárek pro vaše nejbližší.', uk: 'Солодкий подарунок для найрідніших.', en: 'A sweet gift for your loved ones.'}},
    easter: {logo: '🐣', fx: ['🌸', '🌼', '🌷'], bulbs: ['#ffd36e', '#a8e6a1', '#ffb3c7', '#9fd3ff'], icon: '🐣',
      greet: {cs: 'Veselé Velikonoce!', uk: 'Світлого Великодня!', en: 'Happy Easter!'},
      sub: {cs: 'Velikonoční dobroty z naší cukrárny.', uk: 'Великодні смаколики з нашої кондитерської.', en: 'Easter treats from our patisserie.'}},
  };
  const UI = {cs: {menu: 'Do menu', fx: 'Efekty', close: 'Zavřít'}, uk: {menu: 'До меню', fx: 'Ефекти', close: 'Закрити'},
              en: {menu: 'See the menu', fx: 'Effects', close: 'Close'}};
  const L = () => { try { return localStorage.getItem('cakeme_lang') || 'cs'; } catch { return 'cs'; } };
  const store = (k, v) => { try { if (v === undefined) return localStorage.getItem(k); localStorage.setItem(k, v); } catch { return null; } };
  const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]));

  function css(th) {
    const b = th.bulbs;
    return `
.th-garland{position:absolute;left:0;right:0;bottom:-11px;height:14px;pointer-events:none;display:flex;justify-content:space-around;overflow:hidden;z-index:1}
.th-garland::before{content:'';position:absolute;left:0;right:0;top:2px;height:1px;background:rgba(255,255,255,.18)}
.th-garland i{position:relative;width:7px;height:10px;border-radius:50% 50% 45% 45%;margin-top:2px;animation:thGlow 2.4s infinite ease-in-out}
.th-garland i:nth-child(4n+1){background:${b[0]};color:${b[0]}}
.th-garland i:nth-child(4n+2){background:${b[1]};color:${b[1]};animation-delay:.6s}
.th-garland i:nth-child(4n+3){background:${b[2]};color:${b[2]};animation-delay:1.2s}
.th-garland i:nth-child(4n+4){background:${b[3]};color:${b[3]};animation-delay:1.8s}
@keyframes thGlow{0%,100%{opacity:.45;box-shadow:none}50%{opacity:1;box-shadow:0 0 8px 2px currentColor}}
.nav-logo{position:relative}
.th-logo{position:absolute;left:-8px;top:-10px;font-size:1.05rem;transform:rotate(-14deg);pointer-events:none;filter:drop-shadow(0 2px 3px rgba(0,0,0,.5))}
#thFx{position:fixed;inset:0;width:100%;height:100%;pointer-events:none;z-index:1500}
.th-card{position:fixed;left:18px;bottom:18px;z-index:1600;display:flex;gap:14px;align-items:center;max-width:380px;
  background:linear-gradient(135deg,rgba(28,24,18,.97),rgba(18,18,18,.97));border:1px solid ${b[0]};padding:14px 40px 14px 16px;
  box-shadow:0 14px 40px rgba(0,0,0,.6),0 0 0 1px rgba(255,255,255,.03) inset;font-family:'Raleway',sans-serif;animation:thIn .6s ease-out}
.th-card .th-ic{font-size:2.2rem;line-height:1}
.th-card b{display:block;font:400 1.15rem 'Playfair Display',serif;color:#f3ead9;margin-bottom:3px}
.th-card p{font-size:.78rem;color:#b9ad97;margin:0 0 8px;line-height:1.45}
.th-card a{display:inline-block;font-size:.68rem;letter-spacing:1.5px;text-transform:uppercase;color:#0b0b0b;background:${b[0]};padding:6px 12px;text-decoration:none;font-weight:700}
.th-card .th-x{position:absolute;top:6px;right:8px;background:none;border:none;color:#8d8270;font-size:1rem;cursor:pointer;padding:4px}
.th-card .th-x:hover{color:#fff}
.th-fxbtn{position:fixed;right:14px;bottom:14px;z-index:1600;width:38px;height:38px;border-radius:50%;border:1px solid rgba(255,255,255,.15);
  background:rgba(15,15,15,.85);color:#fff;font-size:1rem;cursor:pointer;opacity:.75}
.th-fxbtn:hover{opacity:1}
.th-fxbtn.off{filter:grayscale(1);opacity:.4}
@keyframes thIn{from{opacity:0;transform:translateY(20px)}to{opacity:1;transform:none}}
@media(max-width:600px){.th-card{left:10px;right:60px;bottom:10px;max-width:none;padding:12px 34px 12px 12px}.th-card .th-ic{font-size:1.7rem}.th-card b{font-size:1rem}}
@media print{.th-garland,.th-logo,#thFx,.th-card,.th-fxbtn{display:none}}`;
  }

  // Falling snow (dots) or emoji; light on the CPU, paused when the tab is hidden
  let fxRun = null;
  function startFx(th) {
    stopFx();
    if (store('cm_fx_off') === '1' || matchMedia('(prefers-reduced-motion: reduce)').matches) return;
    const cv = document.createElement('canvas'); cv.id = 'thFx'; document.body.appendChild(cv);
    const ctx = cv.getContext('2d'), dpr = Math.min(2, devicePixelRatio || 1);
    const emoji = Array.isArray(th.fx) ? th.fx : null;
    let W, H, parts = [];
    const size = () => { W = innerWidth; H = innerHeight; cv.width = W * dpr; cv.height = H * dpr; ctx.setTransform(dpr, 0, 0, dpr, 0, 0); };
    size(); addEventListener('resize', size);
    const n = Math.round(Math.min(W, 1400) / (emoji ? 60 : 22));
    const make = top => ({x: Math.random() * W, y: top ? -20 : Math.random() * H, r: emoji ? 12 + Math.random() * 10 : 1 + Math.random() * 2.4,
      vy: emoji ? .4 + Math.random() * .7 : .5 + Math.random() * 1.1, sw: Math.random() * 6.28, rot: Math.random() * 6.28,
      e: emoji ? emoji[Math.floor(Math.random() * emoji.length)] : '', a: .45 + Math.random() * .5});
    for (let i = 0; i < n; i++) parts.push(make(false));
    let raf = 0;
    const tick = () => {
      ctx.clearRect(0, 0, W, H);
      for (const p of parts) {
        p.y += p.vy; p.sw += .012; p.x += Math.sin(p.sw) * (emoji ? .5 : .35); p.rot += .005;
        if (p.y > H + 30) Object.assign(p, make(true));
        ctx.globalAlpha = p.a;
        if (emoji) { ctx.save(); ctx.translate(p.x, p.y); ctx.rotate(Math.sin(p.rot) * .6); ctx.font = p.r + 'px serif'; ctx.fillText(p.e, -p.r / 2, p.r / 2); ctx.restore(); }
        else { ctx.beginPath(); ctx.arc(p.x, p.y, p.r, 0, 6.28); ctx.fillStyle = '#fff'; ctx.fill(); }
      }
      raf = requestAnimationFrame(tick);
    };
    const vis = () => { cancelAnimationFrame(raf); if (!document.hidden) raf = requestAnimationFrame(tick); };
    document.addEventListener('visibilitychange', vis); vis();
    fxRun = () => { cancelAnimationFrame(raf); removeEventListener('resize', size); document.removeEventListener('visibilitychange', vis); cv.remove(); };
  }
  function stopFx() { if (fxRun) { fxRun(); fxRun = null; } }

  function card(id, th, banner, preview) {
    document.querySelector('.th-card')?.remove();
    const key = 'cm_th_seen_' + id + '_' + new Date().getFullYear();
    if (!preview && store(key) === '1') return;
    const l = L(), ui = UI[l] || UI.cs;
    const own = banner && (banner[l] || banner.cs);
    const el = document.createElement('div');
    el.className = 'th-card';
    el.innerHTML = `<div class="th-ic">${th.icon}</div><div><b>${esc(th.greet[l] || th.greet.cs)}</b><p>${esc(own || th.sub[l] || th.sub.cs)}</p>`
      + (/menu\.html$/.test(location.pathname) ? '' : `<a href="menu.html">${esc(ui.menu)}</a>`)
      + `</div><button type="button" class="th-x" aria-label="${esc(ui.close)}">✕</button>`;
    el.querySelector('.th-x').onclick = () => { store(key, '1'); el.remove(); };
    document.body.appendChild(el);
  }

  function apply(id, cfg, preview) {
    const th = THEMES[id];
    if (!th) return;
    document.documentElement.dataset.theme = id;
    const st = document.createElement('style'); st.id = 'thCss'; st.textContent = css(th); document.head.appendChild(st);
    const nav = document.getElementById('nav');
    if (nav) {
      const g = document.createElement('div'); g.className = 'th-garland'; g.innerHTML = '<i></i>'.repeat(Math.ceil(innerWidth / 34));
      nav.appendChild(g);
      const logo = nav.querySelector('.nav-logo');
      if (logo) { const s = document.createElement('span'); s.className = 'th-logo'; s.textContent = th.logo; logo.appendChild(s); }
    }
    if (cfg.effects !== false) {
      startFx(th);
      const b = document.createElement('button'); b.type = 'button'; b.className = 'th-fxbtn';
      b.textContent = th.fx === 'snow' ? '❄️' : th.fx[0];
      const upd = () => { const off = store('cm_fx_off') === '1'; b.classList.toggle('off', off); b.title = (UI[L()] || UI.cs).fx + (off ? ' ✕' : ' ✓'); };
      b.onclick = () => { const off = store('cm_fx_off') !== '1'; store('cm_fx_off', off ? '1' : '0'); off ? stopFx() : startFx(th); upd(); };
      upd(); document.body.appendChild(b);
    }
    card(id, th, cfg.banner, preview);
    // language buttons re-render the greeting in the new language
    document.addEventListener('click', e => { if (e.target.closest('.lang-btn') && document.querySelector('.th-card')) setTimeout(() => card(id, th, cfg.banner, true), 30); });
  }

  const preview = new URLSearchParams(location.search).get('theme');
  if (preview && THEMES[preview]) { apply(preview, {effects: true}, true); return; }
  fetch('/api/theme', {cache: 'no-store'}).then(r => r.ok ? r.json() : null).then(cfg => { if (cfg && cfg.theme) apply(cfg.theme, cfg, false); }).catch(() => {});
})();

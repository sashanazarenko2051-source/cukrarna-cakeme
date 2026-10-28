/* Seasonal look of the site (New Year, Christmas, Halloween, Valentine's, Easter), switched on in the admin.
   A live 3D light scene at the top of the page: holiday figures made of glowing particles (a spiral tree of lights,
   the year in sparks and a bauble, a jack-o'-lantern under the moon, beating hearts, painted eggs) that turn
   with the mouse, plus a holiday atmosphere (snow, fireworks, embers and fog, rising hearts, petals).
   Also a garland under the menu bar, cards with a running light rim, glare and a slight 3D tilt, a cursor trail
   and click sparks, a ribbon on the home page and a greeting card with a live countdown.
   ?theme=<id> previews a theme without saving it (used by the admin). */
(() => {
  const THEMES = {
    new_year: {bulbs: ['#f5d67a', '#ffffff', '#c9a96e', '#9fd3ff'], glyph: 'spark', objs: ['bauble', 'year'], atm: ['snow', 'fireworks'],
      glow: ['rgba(245,214,122,.14)', 'rgba(159,211,255,.09)'], date: y => new Date(y + 1, 0, 1), hold: 7,
      greet: {cs: 'Šťastný nový rok!', uk: 'З Новим роком!', en: 'Happy New Year!'},
      sub: {cs: 'Oslavte ho s dortem od nás — objednejte včas.', uk: 'Святкуйте з нашим тортом — замовляйте завчасно.', en: 'Celebrate with one of our cakes — order in good time.'},
      to: {cs: 'Do Nového roku', uk: 'До Нового року', en: 'New Year in'}, ribbon: {cs: 'Novoroční dorty', uk: 'Новорічні торти', en: 'New Year cakes'}},
    christmas: {bulbs: ['#e5484d', '#f5d67a', '#3fa66b', '#6fb7ff'], glyph: 'snow', objs: ['tree', 'tree'], atm: ['snow'],
      glow: ['rgba(229,72,77,.11)', 'rgba(63,166,107,.10)'], date: y => new Date(y, 11, 24), hold: 3,
      greet: {cs: 'Veselé Vánoce!', uk: 'Веселого Різдва!', en: 'Merry Christmas!'},
      sub: {cs: 'Vánoční cukroví a dorty — objednejte si včas.', uk: 'Різдвяне печиво й торти — замовляйте завчасно.', en: 'Christmas cookies and cakes — order in good time.'},
      to: {cs: 'Do Štědrého dne', uk: 'До Святвечора', en: 'Christmas Eve in'}, ribbon: {cs: 'Vánoční cukroví a dorty', uk: 'Різдвяне печиво й торти', en: 'Christmas cookies & cakes'}},
    halloween: {bulbs: ['#ff8a1f', '#8e4bd6', '#ffb347', '#5a2a82'], glyph: 'pumpkin', objs: ['moon', 'pumpkin'], atm: ['fog', 'embers'],
      glow: ['rgba(255,138,31,.12)', 'rgba(142,75,214,.12)'], date: y => new Date(y, 9, 31), hold: 1,
      greet: {cs: 'Strašidelný Halloween!', uk: 'Моторошного Хелловіну!', en: 'Happy Halloween!'},
      sub: {cs: 'Sladkosti, nebo psota? U nás rozhodně sladkosti.', uk: 'Солодощі чи капость? У нас — точно солодощі.', en: 'Trick or treat? Here it’s definitely treats.'},
      to: {cs: 'Do Halloweenu', uk: 'До Хелловіну', en: 'Halloween in'}, ribbon: {cs: 'Halloweenské sladkosti', uk: 'Солодощі на Хелловін', en: 'Halloween treats'}},
    valentine: {bulbs: ['#ff5d8f', '#ffd1dc', '#e5484d', '#ff9eb5'], glyph: 'heart', objs: ['heart', 'heart'], atm: ['hearts'],
      glow: ['rgba(255,93,143,.13)', 'rgba(229,72,77,.09)'], date: y => new Date(y, 1, 14), hold: 1,
      greet: {cs: 'Šťastného Valentýna!', uk: 'З Днем закоханих!', en: 'Happy Valentine’s Day!'},
      sub: {cs: 'Sladký dárek pro vaše nejbližší.', uk: 'Солодкий подарунок для найрідніших.', en: 'A sweet gift for your loved ones.'},
      to: {cs: 'Do Valentýna', uk: 'До Дня закоханих', en: 'Valentine’s Day in'}, ribbon: {cs: 'Sladké dárky z lásky', uk: 'Солодкі подарунки з любов’ю', en: 'Sweet gifts with love'}},
    easter: {bulbs: ['#ffd36e', '#a8e6a1', '#ffb3c7', '#9fd3ff'], glyph: 'egg', objs: ['egg', 'egg2'], atm: ['petals'],
      glow: ['rgba(255,211,110,.11)', 'rgba(168,230,161,.09)'], date: y => easter(y), hold: 2,
      greet: {cs: 'Veselé Velikonoce!', uk: 'Світлого Великодня!', en: 'Happy Easter!'},
      sub: {cs: 'Velikonoční dobroty z naší cukrárny.', uk: 'Великодні смаколики з нашої кондитерської.', en: 'Easter treats from our patisserie.'},
      to: {cs: 'Do Velikonoc', uk: 'До Великодня', en: 'Easter in'}, ribbon: {cs: 'Velikonoční dobroty', uk: 'Великодні смаколики', en: 'Easter treats'}},
  };
  // page / card colours per holiday (override the site's --bg* and --bdr variables)
  const PAL = {
    new_year:  {bg: ['#070b14', '#0b111d', '#101827', '#151e30'], bdr: '#26324c', tint: 'rgba(159,211,255,.07)'},
    christmas: {bg: ['#07100c', '#0b1611', '#101d16', '#15241c'], bdr: '#24402f', tint: 'rgba(229,72,77,.06)'},
    halloween: {bg: ['#0d0812', '#120b18', '#18101f', '#1f1428'], bdr: '#38234a', tint: 'rgba(255,138,31,.07)'},
    valentine: {bg: ['#12070b', '#180a10', '#1f0e15', '#27121b'], bdr: '#45202f', tint: 'rgba(255,93,143,.08)'},
    easter:    {bg: ['#0f0e09', '#15140d', '#1b1a12', '#222117'], bdr: '#3a3829', tint: 'rgba(168,230,161,.07)'},
  };
  // the order page keeps only the static decorations: no scene, no sparks over the form
  const QUIET = /delivery\.html$/.test(location.pathname);
  const CARDS = '.m-card,.pop-card,.rv-card,.step,.di,.celeb-card';
  const UI = {cs: {menu: 'Do menu', fx: 'Efekty', close: 'Zavřít', today: 'Je to dnes! 🎉', u: ['dny', 'hod', 'min', 's']},
              uk: {menu: 'До меню', fx: 'Ефекти', close: 'Закрити', today: 'Це сьогодні! 🎉', u: ['дн', 'год', 'хв', 'с']},
              en: {menu: 'See the menu', fx: 'Effects', close: 'Close', today: 'It’s today! 🎉', u: ['days', 'hrs', 'min', 'sec']}};
  const L = () => { try { return localStorage.getItem('cakeme_lang') || 'cs'; } catch { return 'cs'; } };
  const store = (k, v) => { try { if (v === undefined) return localStorage.getItem(k); localStorage.setItem(k, v); } catch { return null; } };
  const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]));
  const calm = () => store('cm_fx_off') === '1' || matchMedia('(prefers-reduced-motion: reduce)').matches;
  let effects = true;
  const animOn = () => effects && !calm();
  const rnd = (a, b) => a + Math.random() * (b - a);
  const prng = seed => () => (seed = (seed * 16807) % 2147483647) / 2147483647;
  const TAU = Math.PI * 2, GA = Math.PI * (3 - Math.sqrt(5));

  function easter(y) {
    const a = y % 19, b = Math.floor(y / 100), c = y % 100, d = Math.floor(b / 4), e = b % 4, f = Math.floor((b + 8) / 25),
      g = Math.floor((b - f + 1) / 3), h = (19 * a + b - d - g + 15) % 30, i = Math.floor(c / 4), k = c % 4,
      l = (32 + 2 * e + 2 * i - h - k) % 7, m = Math.floor((a + 11 * h + 22 * l) / 451);
    return new Date(y, Math.floor((h + l - 7 * m + 114) / 31) - 1, ((h + l - 7 * m + 114) % 31) + 1);
  }
  // the nearest holiday that is not over yet (last year's, this year's or next year's): its start and whether it is on now
  function nextDate(th) {
    const now = new Date(), y = now.getFullYear();
    for (const k of [y - 1, y, y + 1]) {
      const d = th.date(k), end = new Date(d.getFullYear(), d.getMonth(), d.getDate() + th.hold + 1);
      if (end > now) return {d, on: d <= now};
    }
    return null;
  }

  // ── glowing sprites (drawn once per colour, then stamped) ──
  const hexA = (h, a) => { const n = parseInt(h.slice(1), 16); return `rgba(${n >> 16},${n >> 8 & 255},${n & 255},${a})`; };
  const SPR = {};
  const mk = (w, h, fn) => { const c = document.createElement('canvas'); c.width = w; c.height = h; fn(c.getContext('2d')); return c; };
  const glow = c => SPR['g' + c] || (SPR['g' + c] = mk(64, 64, g => {
    const r = g.createRadialGradient(32, 32, 0, 32, 32, 32);
    r.addColorStop(0, 'rgba(255,255,255,.95)'); r.addColorStop(.12, hexA(c, .95)); r.addColorStop(.35, hexA(c, .32)); r.addColorStop(1, hexA(c, 0));
    g.fillStyle = r; g.fillRect(0, 0, 64, 64);
  }));
  const soft = c => SPR['s' + c] || (SPR['s' + c] = mk(64, 64, g => {
    const r = g.createRadialGradient(32, 32, 0, 32, 32, 32);
    r.addColorStop(0, hexA(c, .9)); r.addColorStop(.5, hexA(c, .35)); r.addColorStop(1, hexA(c, 0));
    g.fillStyle = r; g.fillRect(0, 0, 64, 64);
  }));
  const HEART = (g, s) => { g.beginPath(); g.moveTo(0, s * .35); g.bezierCurveTo(-s * 1.1, -s * .3, -s * .55, -s * 1.05, 0, -s * .45); g.bezierCurveTo(s * .55, -s * 1.05, s * 1.1, -s * .3, 0, s * .35); g.closePath(); };
  const heartSpr = c => SPR['h' + c] || (SPR['h' + c] = mk(64, 64, g => {
    g.translate(32, 36); g.shadowColor = c; g.shadowBlur = 14; g.fillStyle = c; HEART(g, 16); g.fill();
    g.shadowBlur = 0; g.fillStyle = 'rgba(255,255,255,.55)'; g.beginPath(); g.ellipse(-7, -9, 3.5, 2.2, -.6, 0, TAU); g.fill();
  }));
  const petalSpr = c => SPR['p' + c] || (SPR['p' + c] = mk(48, 48, g => {
    g.translate(24, 24); const r = g.createLinearGradient(0, -16, 0, 16); r.addColorStop(0, '#ffffff'); r.addColorStop(1, c);
    g.fillStyle = r; g.beginPath(); g.moveTo(0, 16); g.bezierCurveTo(-14, 4, -10, -14, -2, -16); g.lineTo(0, -12); g.lineTo(2, -16);
    g.bezierCurveTo(10, -14, 14, 4, 0, 16); g.fill();
  }));

  // ── 3D figures made of points: {pts: [{x, y, z, c, s, tw}], spin | sway} in a box about [-1, 1] ──
  const OBJ = {
    tree(R) {  // two spirals of lights round a cone of needles, baubles that twinkle and a star on top
      const P = [];
      for (let k = 0; k < 2; k++) for (let i = 0, N = 380; i < N; i++) {
        const t = i / N, a = t * TAU * 6.5 + k * Math.PI, r = .64 * t + .02;
        P.push({x: r * Math.cos(a), y: -1 + 2 * t, z: r * Math.sin(a), c: k ? '#ff5560' : '#ffd36e', s: 1.05});
      }
      for (let i = 0; i < 560; i++) {
        const t = Math.pow(R(), .62), r = .62 * t * Math.sqrt(R()), a = R() * TAU;
        P.push({x: r * Math.cos(a), y: -1 + 2 * t, z: r * Math.sin(a), c: ['#1f8a4c', '#2fb36a', '#6fe0a0'][i % 3], s: .75});
      }
      for (let i = 0; i < 38; i++) {
        const t = .12 + .88 * R(), r = .64 * t, a = R() * TAU;
        P.push({x: r * Math.cos(a), y: -1 + 2 * t, z: r * Math.sin(a), c: ['#ff4d5a', '#6fb7ff', '#ffd36e', '#ffffff'][i % 4], s: 2.3, tw: R() * TAU});
      }
      for (let i = 0; i < 26; i++) P.push({x: (R() - .5) * .14, y: 1.04 + R() * .16, z: (R() - .5) * .14, c: '#a8743c', s: .8});
      return {pts: P, spin: .45, star: -1.1};
    },
    bauble(R) {  // a glass bauble with bands, hanging on a thread
      const P = [], N = 900;
      for (let i = 0; i < N; i++) {
        const y = 1 - 2 * (i + .5) / N, r = Math.sqrt(1 - y * y), a = i * GA, lon = a % TAU;
        const c = Math.abs(y) < .1 ? '#ffffff' : Math.abs(Math.abs(y) - .42 - .05 * Math.sin(lon * 8)) < .05 ? '#9fd3ff' : ['#f5d67a', '#e0b75a', '#fff1c4'][i % 3];
        P.push({x: r * Math.cos(a) * .78, y: y * .78 + .14, z: r * Math.sin(a) * .78, c, s: .95});
      }
      for (let i = 0; i < 70; i++) { const a = R() * TAU, h = R(); P.push({x: Math.cos(a) * .15, y: -.62 - h * .14, z: Math.sin(a) * .15, c: '#c9a96e', s: .9}); }
      for (let i = 0; i < 24; i++) { const a = i / 24 * TAU; P.push({x: Math.cos(a) * .07, y: -.83 + Math.sin(a) * .07, z: 0, c: '#c9a96e', s: .7}); }
      return {pts: P, spin: .55, hang: -.9};
    },
    year() {  // the coming year written in sparks, with an orbit ring
      const now = new Date(), yr = now.getFullYear() + (now.getMonth() >= 6 ? 1 : 0);
      const W = 360, H = 150, P = [];
      const c = mk(W, H, g => { g.fillStyle = '#fff'; g.font = 'bold 128px Georgia, "Playfair Display", serif'; g.textAlign = 'center'; g.textBaseline = 'middle'; g.fillText(String(yr), W / 2, H / 2 + 6); });
      const d = c.getContext('2d').getImageData(0, 0, W, H).data;
      for (let y = 0; y < H; y += 5) for (let x = (y / 5 % 2) * 2.5; x < W; x += 5) if (d[(y * W + Math.round(x)) * 4 + 3] > 140) {
        const nx = (x - W / 2) / (W / 2), ny = (y - H / 2) / (W / 2);
        P.push({x: nx, y: ny, z: (Math.random() - .5) * .14, c: ny < -.1 ? '#fff4d0' : ny < .1 ? '#f5d67a' : '#e0a94a', s: .75});
      }
      for (let i = 0; i < 150; i++) { const a = i / 150 * TAU; P.push({x: Math.cos(a) * 1.12, y: Math.sin(a) * .1 + .02, z: Math.sin(a) * .55, c: '#9fd3ff', s: .8, tw: a * 3}); }
      return {pts: P, sway: .55};
    },
    pumpkin(R) {  // a ribbed jack-o'-lantern; the carved face lets the candle light through
      const P = [], N = 1300;
      const hole = (u, v) => {
        const eye = cx => Math.abs(u - cx) < .17 - (v + .32) * .9 && v > -.32 && v < -.08;
        const nose = Math.abs(u) < .09 - (v - .02) * .9 && v > .0 && v < .1;
        const mz = .32 + .05 * Math.sign(Math.sin(u * 22));
        const mouth = Math.abs(u) < .48 - Math.abs(v - .32) && Math.abs(v - mz) < .085;
        return eye(-.3) || eye(.3) || nose || mouth;
      };
      for (let i = 0; i < N; i++) {
        const y0 = 1 - 2 * (i + .5) / N, r0 = Math.sqrt(1 - y0 * y0), a = i * GA, lon = a % TAU;
        const m = .84 + .16 * Math.pow(Math.abs(Math.cos(lon * 4)), .55);
        const x = r0 * Math.cos(a) * m, z = r0 * Math.sin(a) * m, y = y0 * .76;
        if (z < -.35 && hole(x, y)) { P.push({x: x * .8, y: y * .8, z: z * .8, c: '#fff2a8', s: 1.9, tw: R() * TAU}); continue; }
        P.push({x, y, z, c: m < .9 ? '#b8500f' : ['#ff8a1f', '#ffa040', '#f07a12'][i % 3], s: .95});
      }
      for (let i = 0; i < 46; i++) { const h = R(); P.push({x: (R() - .5) * .1 + h * .08, y: -.74 - h * .26, z: (R() - .5) * .1, c: '#5f8a2a', s: .9}); }
      return {pts: P, sway: .75, core: '#ffb347'};
    },
    heart(R) {  // a 3D heart in layers; it beats
      const P = [];
      const pt = t => [16 * Math.pow(Math.sin(t), 3) / 17, -(13 * Math.cos(t) - 5 * Math.cos(2 * t) - 2 * Math.cos(3 * t) - Math.cos(4 * t)) / 17 - .12];
      for (let l = 0; l < 15; l++) {
        const zz = -1 + 2 * l / 14, s = Math.sqrt(1 - zz * zz * .92), n = Math.round(64 * s) + 6;
        for (let i = 0; i < n; i++) { const [x, y] = pt(i / n * TAU + l * .4); P.push({x: x * s, y: y * s, z: zz * .4, c: zz < -.6 ? '#ff9ec0' : zz > .4 ? '#c81d4e' : '#ff5d8f', s: 1}); }
      }
      for (let i = 0; i < 260; i++) { const [x, y] = pt(R() * TAU), k = Math.sqrt(R()) * .9; P.push({x: x * k, y: y * k, z: (R() - .5) * .5 * (1 - k * .6), c: '#ff3d7a', s: .7}); }
      for (let i = 0; i < 16; i++) { const [x, y] = pt(R() * TAU); P.push({x: x * .9, y: y * .9, z: (R() - .5) * .3, c: '#ffffff', s: 1.8, tw: R() * TAU}); }
      return {pts: P, sway: .7, beat: true};
    },
    egg: R => egg(R, ['#fff1c9', '#ff6f91', '#5cc99a', '#6fb7ff']),
    egg2: R => egg(R, ['#e6f3ff', '#ffb347', '#b58cff', '#ff6f91']),
    moon() {  // drawn flat: a big moon with bats crossing it
      const bats = Array.from({length: 3}, (_, i) => ({ph: i / 3, sp: .055 + i * .012, dy: (i - 1) * .35, k: .75 + i * .2}));
      return {flat(g, cx, cy, S, t, al) {
        const r = S * .78;
        g.globalAlpha = al * .55; g.drawImage(soft('#ffcf8a'), cx - r * 2.6, cy - r * 2.6, r * 5.2, r * 5.2);
        g.globalCompositeOperation = 'source-over'; g.globalAlpha = al;
        const m = g.createRadialGradient(cx - r * .3, cy - r * .35, r * .1, cx, cy, r);
        m.addColorStop(0, '#fff6dc'); m.addColorStop(.7, '#f3d79a'); m.addColorStop(1, '#d9a95c');
        g.fillStyle = m; g.beginPath(); g.arc(cx, cy, r, 0, TAU); g.fill();
        g.fillStyle = 'rgba(160,110,50,.22)';
        for (const [dx, dy, rr] of [[-.3, -.2, .18], [.25, .15, .24], [-.05, .45, .12], [.38, -.38, .1], [-.45, .25, .09]]) { g.beginPath(); g.arc(cx + dx * r, cy + dy * r, rr * r, 0, TAU); g.fill(); }
        g.fillStyle = '#0b0610';
        for (const b of bats) {  // a bat silhouette flying across, wings flapping
          const p = (t * b.sp + b.ph) % 1, x = cx + (p * 2 - 1) * r * 2.2, y = cy + b.dy * r + Math.sin(p * 9) * r * .12, s = r * .2 * b.k, f = Math.sin(t * 14 + b.ph * 9);
          g.save(); g.translate(x, y); g.scale(s / 10, s / 10); g.beginPath();
          g.moveTo(0, -1); g.quadraticCurveTo(-6, -6 - f * 6, -14, -2 - f * 8); g.quadraticCurveTo(-11, 1, -9, 3); g.quadraticCurveTo(-6, 0, -4, 3); g.quadraticCurveTo(-2, 1, 0, 4);
          g.quadraticCurveTo(2, 1, 4, 3); g.quadraticCurveTo(6, 0, 9, 3); g.quadraticCurveTo(11, 1, 14, -2 - f * 8); g.quadraticCurveTo(6, -6 - f * 6, 0, -1); g.fill();
          g.beginPath(); g.ellipse(0, 0, 2.2, 3.4, 0, 0, TAU); g.fill(); g.restore();
        }
        g.globalCompositeOperation = 'lighter';
      }};
    },
  };
  function egg(R, pal) {  // a painted egg: zigzag band, rings and dots
    const P = [], N = 1300;
    for (let i = 0; i < N; i++) {
      const y0 = 1 - 2 * (i + .5) / N, r0 = Math.sqrt(1 - y0 * y0), a = i * GA, lon = a % TAU, f = (1 + .13 * y0) * .72;
      let c = pal[0];
      if (Math.abs(y0 - .1 * Math.sin(lon * 7)) < .075) c = pal[1];
      else if (Math.abs(Math.abs(y0) - .45) < .04) c = pal[2];
      else if (Math.sin(lon * 6) * Math.sin(y0 * 9) > .82) c = pal[3];
      P.push({x: r0 * Math.cos(a) * f, y: y0 * .98, z: r0 * Math.sin(a) * f, c, s: .95});
    }
    return {pts: P, spin: .5};
  }

  // draws one figure centred at (cx, cy); S = half its height in px; rx/ry = tilt from the mouse
  function drawObj(g, O, cx, cy, S, t, rx, ry, al, dir) {
    if (O.flat) return O.flat(g, cx, cy, S, t, al);
    const ang = (O.spin ? t * O.spin * dir : Math.sin(t * .45) * O.sway) + ry, ca = Math.cos(ang), sa = Math.sin(ang), cb = Math.cos(rx), sb = Math.sin(rx);
    let sc = S;
    if (O.beat) { const b = (t * 1.05) % 1; sc *= 1 + .07 * Math.exp(-((b - .1) ** 2) / .003) + .045 * Math.exp(-((b - .3) ** 2) / .003); }
    const F = 3.4, base = Math.max(1, S * .03);
    const proj = (x, y, z) => { const x1 = x * ca - z * sa, z1 = x * sa + z * ca, y2 = y * cb - z1 * sb, z2 = y * sb + z1 * cb, k = F / (F + z2); return [cx + x1 * sc * k, cy + y2 * sc * k, z2, k]; };
    if (O.hang) {  // the thread up to the top of the scene
      const [hx, hy] = proj(0, O.hang, 0); g.globalAlpha = al * .5; g.strokeStyle = '#c9a96e'; g.lineWidth = 1; g.beginPath(); g.moveTo(hx, 0); g.lineTo(hx, hy); g.stroke();
    }
    if (O.core) { const f = .75 + .25 * Math.sin(t * 9) * Math.sin(t * 5.3); g.globalAlpha = al * .55 * f; const r = sc * .9; g.drawImage(soft(O.core), cx - r, cy - r, r * 2, r * 2); }
    for (const p of O.pts) {
      const [px, py, z, k] = proj(p.x, p.y, p.z);
      let r = p.s * k * base; if (p.tw != null) r *= .55 + .55 * Math.sin(t * 3 + p.tw);
      if (r <= .2) continue;
      g.globalAlpha = al * (.18 + .42 * (1 - (z + 1) / 2));
      g.drawImage(glow(p.c), px - r * 2, py - r * 2, r * 4, r * 4);
    }
    if (O.star != null) {  // a shining star on top of the tree
      const [sx, sy] = proj(0, O.star, 0), r = S * .13 * (1 + .08 * Math.sin(t * 4));
      g.globalAlpha = al * .8; g.drawImage(glow('#ffe9a0'), sx - r * 3, sy - r * 3, r * 6, r * 6);
      g.save(); g.translate(sx, sy); g.rotate(Math.sin(t) * .15); g.fillStyle = '#fff3c4'; g.globalAlpha = al; g.beginPath();
      for (let i = 0; i < 10; i++) { const rr = i % 2 ? r * .42 : r, a = i / 10 * TAU - Math.PI / 2; g.lineTo(Math.cos(a) * rr, Math.sin(a) * rr); }
      g.fill(); g.restore();
    }
  }

  // ── the scene at the top of the page (hero on the home page, a band behind the heading elsewhere) ──
  const KICK = [];
  let mx = 0, my = 0;
  addEventListener('pointermove', e => { mx = e.clientX / innerWidth * 2 - 1; my = e.clientY / innerHeight * 2 - 1; }, {passive: true});
  function scene(host, th, hero) {
    const cv = document.createElement('canvas'); cv.className = 'th-scene' + (hero ? '' : ' band');
    if (!hero) { if (getComputedStyle(host).position === 'static') host.style.position = 'relative'; host.style.isolation = 'isolate'; }
    host.prepend(cv);
    const g = cv.getContext('2d');
    const objs = th.objs.map((k, i) => OBJ[k](prng(31 + i * 17)));
    let W = 0, H = 0, dpr = 1, lay = [], bok = [], parts = [], fw = [], nextFw = 0, sx = 0, sy = 0;
    const has = a => th.atm.includes(a);
    function layout() {
      if (hero) {
        const hr = host.getBoundingClientRect(), lb = host.querySelector('.logo-block'), r = lb && lb.getBoundingClientRect();
        const side = r ? r.left - hr.left : 0, cy = r ? r.top - hr.top + r.height / 2 : H / 2, S = Math.min(H * .3, side * .4, 240);
        lay = S >= 80 ? [{o: objs[0], x: side / 2, y: cy, S, a: 1, dir: -1}, {o: objs[1], x: W - side / 2, y: cy, S, a: 1, dir: 1}]
                      : [{o: objs[1], x: W / 2, y: H * .47, S: Math.min(W * .42, H * .27), a: .3, dir: 1}];
      } else {
        const S = Math.min(118, W * .075);
        lay = W >= 1100 ? [{o: objs[0], x: W * .1, y: 250, S, a: .9, dir: -1}, {o: objs[1], x: W * .9, y: 250, S, a: .9, dir: 1}] : [];
      }
    }
    function seed() {
      const R = Math.random, area = W * H;
      bok = Array.from({length: 9}, (_, i) => ({x: R() * W, y: R() * H, r: rnd(50, 150), z: rnd(.2, 1), c: th.bulbs[i % 4], a: rnd(.05, .12), vx: rnd(-6, 6), vy: rnd(-4, 4)}));
      parts = [];
      const n = k => Math.round(Math.min(k * area / 1e6, k * 1.6));
      if (has('snow')) for (let i = 0; i < n(110); i++) parts.push({k: 'snow', x: R() * W, y: R() * H, z: rnd(.25, 1), ph: R() * TAU});
      if (has('embers')) for (let i = 0; i < n(55); i++) parts.push({k: 'ember', x: R() * W, y: R() * H, z: rnd(.3, 1), ph: R() * TAU, c: ['#ff8a1f', '#ffb347', '#ff5a1f'][i % 3]});
      if (has('fog')) for (let i = 0; i < 5; i++) parts.push({k: 'fog', x: R() * W, y: H * rnd(.45, 1), z: rnd(.5, 1), c: ['#6a2fa8', '#3a1d5c', '#8e4bd6'][i % 3]});
      if (has('hearts')) for (let i = 0; i < n(32); i++) parts.push({k: 'heart', x: R() * W, y: R() * H, z: rnd(.3, 1), ph: R() * TAU, c: ['#ff5d8f', '#ff9eb5', '#e5484d', '#ffd1dc'][i % 4]});
      if (has('petals')) for (let i = 0; i < n(40); i++) parts.push({k: 'petal', x: R() * W, y: R() * H, z: rnd(.35, 1), ph: R() * TAU, rot: R() * TAU, c: ['#ffb3c7', '#ffd36e', '#ffffff', '#c7f0c0'][i % 4]});
    }
    function resize() {
      dpr = Math.min(1.5, devicePixelRatio || 1); W = host.clientWidth; H = hero ? host.clientHeight : Math.min(480, host.clientHeight);
      cv.width = W * dpr; cv.height = H * dpr; cv.style.height = H + 'px'; layout(); seed();
    }
    function boom() {
      const x = rnd(.08, .92) * W, y = rnd(.12, .42) * H, c1 = th.bulbs[Math.floor(rnd(0, 4))], c2 = ['#ff6f91', '#9fd3ff', '#f5d67a'][Math.floor(rnd(0, 3))];
      for (let i = 0, n = 70; i < n; i++) { const a = i / n * TAU + rnd(-.05, .05), v = rnd(50, 150) * (i % 2 ? 1 : .7); fw.push({x, y, vx: Math.cos(a) * v, vy: Math.sin(a) * v, l: rnd(1.2, 1.9), L: 1.9, c: i % 3 ? c1 : c2}); }
    }
    function frame(t, dt) {
      g.setTransform(dpr, 0, 0, dpr, 0, 0); g.clearRect(0, 0, W, H);
      sx += (mx - sx) * .04; sy += (my - sy) * .04;
      g.globalCompositeOperation = 'lighter';
      for (const b of bok) {  // soft out-of-focus lights
        b.x = (b.x + b.vx * dt + W + 300) % (W + 300) ; b.y += b.vy * dt; if (b.y < -150 || b.y > H + 150) b.vy *= -1;
        g.globalAlpha = b.a; const x = b.x - 150 - sx * 30 * b.z, y = b.y - sy * 20 * b.z;
        g.drawImage(soft(b.c), x - b.r, y - b.r, b.r * 2, b.r * 2);
      }
      for (const p of parts) {
        if (p.k === 'fog') {
          p.x += (12 * p.z) * dt; if (p.x > W + 300) p.x = -300;
          g.globalAlpha = .1; const r = W * .32 * p.z; g.drawImage(soft(p.c), p.x - r, p.y - r * .5, r * 2, r);
        } else if (p.k === 'snow') {
          p.y += (16 + 46 * p.z) * dt; p.x += Math.sin(t * .8 + p.ph) * 12 * p.z * dt; if (p.y > H + 6) { p.y = -6; p.x = Math.random() * W; }
          const r = 1.2 + 3.2 * p.z; g.globalAlpha = .25 + .55 * p.z; g.drawImage(glow('#dfefff'), p.x - sx * 14 * p.z - r, p.y - r, r * 2, r * 2);
        } else if (p.k === 'ember') {
          p.y -= (14 + 40 * p.z) * dt; p.x += Math.sin(t * 1.3 + p.ph) * 18 * p.z * dt; if (p.y < -8) { p.y = H + 8; p.x = Math.random() * W; }
          const r = 1 + 2.6 * p.z; g.globalAlpha = (.35 + .5 * p.z) * (.6 + .4 * Math.sin(t * 7 + p.ph)); g.drawImage(glow(p.c), p.x - r * 2, p.y - r * 2, r * 4, r * 4);
        } else if (p.k === 'heart') {
          p.y -= (12 + 30 * p.z) * dt; p.x += Math.sin(t + p.ph) * 14 * p.z * dt; if (p.y < -20) { p.y = H + 20; p.x = Math.random() * W; }
          const r = 5 + 9 * p.z; g.globalAlpha = .18 + .45 * p.z; g.drawImage(heartSpr(p.c), p.x - sx * 12 * p.z - r, p.y - r, r * 2, r * 2);
        } else if (p.k === 'petal') {
          p.y += (14 + 34 * p.z) * dt; p.x += (Math.sin(t * .9 + p.ph) * 22 + 10) * p.z * dt; p.rot += dt * (.6 + p.z); if (p.y > H + 16) { p.y = -16; p.x = Math.random() * W; }
          const r = 5 + 8 * p.z; g.globalCompositeOperation = 'source-over'; g.globalAlpha = .3 + .5 * p.z;
          g.save(); g.translate(p.x - sx * 12 * p.z, p.y); g.rotate(p.rot); g.scale(1, Math.cos(t * 2 + p.ph)); g.drawImage(petalSpr(p.c), -r, -r, r * 2, r * 2); g.restore();
          g.globalCompositeOperation = 'lighter';
        }
      }
      for (const o of lay) drawObj(g, o.o, o.x + sx * 10, o.y + sy * 6, o.S, t + o.dir, .12 + sy * .22, sx * .55, o.a, o.dir);
      if (has('fireworks') && dt) {
        if (t > nextFw) { boom(); nextFw = t + rnd(1.4, 2.8); }
        fw = fw.filter(p => (p.l -= dt) > 0);
        for (const p of fw) {
          p.vx *= .985; p.vy = p.vy * .985 + 55 * dt; p.x += p.vx * dt; p.y += p.vy * dt;
          const k = p.l / p.L, r = 1.6 + 2.4 * k; g.globalAlpha = Math.min(1, k * 1.4) * (.7 + .3 * Math.sin(t * 30 + p.x));
          g.drawImage(glow(p.c), p.x - r * 2, p.y - r * 2, r * 4, r * 4);
        }
      }
      g.globalAlpha = 1; g.globalCompositeOperation = 'source-over';
    }
    resize();
    let raf = 0, vis = true, tp = 0;
    new ResizeObserver(() => { resize(); if (!raf) frame(2.4, 0); }).observe(host);
    const running = () => vis && !document.hidden && animOn();
    const loop = now => { raf = 0; if (!cv.isConnected) return; const dt = Math.min(.05, (now - tp) / 1000); tp = now; frame(now / 1000, dt); if (running()) raf = requestAnimationFrame(loop); };
    const kick = () => { if (running()) { if (!raf) { tp = performance.now(); raf = requestAnimationFrame(loop); } } else if (!raf) frame(2.4, 0); };
    new IntersectionObserver(es => { vis = es[0].isIntersecting; kick(); }).observe(cv);
    document.addEventListener('visibilitychange', kick);
    KICK.push(kick); kick();
  }

  // a small live figure for the greeting card
  function mini(cv, th) {
    const O = OBJ[th.objs[1]](prng(77)), g = cv.getContext('2d'), dpr = Math.min(2, devicePixelRatio || 1), S = 64;
    cv.width = cv.height = S * dpr;
    const draw = t => { g.setTransform(dpr, 0, 0, dpr, 0, 0); g.clearRect(0, 0, S, S); g.globalCompositeOperation = 'lighter'; drawObj(g, O, S / 2, S / 2 + 2, S * .38, t, .15, 0, 1, 1); g.globalAlpha = 1; g.globalCompositeOperation = 'source-over'; };
    let on = false;
    const loop = now => { if (!cv.isConnected) return; draw(now / 1000); if (animOn() && !document.hidden) requestAnimationFrame(loop); else on = false; };
    const kick = () => { if (!cv.isConnected) return; if (animOn() && !document.hidden) { if (!on) { on = true; requestAnimationFrame(loop); } } else if (!on) draw(2.4); };
    document.addEventListener('visibilitychange', kick);
    KICK.push(kick); kick();
  }

  // ── cursor trail and click sparks over the page ──
  function sparks(th) {
    const cv = document.createElement('canvas'); cv.id = 'thFx'; document.body.appendChild(cv);
    const g = cv.getContext('2d'); let P = [], raf = 0, W = 0, H = 0, dpr = 1, tp = 0, lastMove = 0;
    const size = () => { dpr = Math.min(2, devicePixelRatio || 1); W = innerWidth; H = innerHeight; cv.width = W * dpr; cv.height = H * dpr; };
    size(); addEventListener('resize', size);
    const shape = th.glyph === 'heart' ? heartSpr : th.glyph === 'egg' ? petalSpr : null;
    const loop = now => {
      const dt = Math.min(.05, (now - tp) / 1000); tp = now;
      g.setTransform(dpr, 0, 0, dpr, 0, 0); g.clearRect(0, 0, W, H); g.globalCompositeOperation = 'lighter';
      P = P.filter(p => (p.l -= dt) > 0);
      for (const p of P) {
        p.vx *= .97; p.vy = p.vy * .97 + p.gr * dt; p.x += p.vx * dt; p.y += p.vy * dt;
        const k = p.l / p.L, r = p.s * (.4 + .6 * k); g.globalAlpha = Math.min(1, k * 1.5);
        g.drawImage(p.img ? p.img(p.c) : glow(p.c), p.x - r, p.y - r, r * 2, r * 2);
      }
      g.globalAlpha = 1;
      raf = P.length ? requestAnimationFrame(loop) : (g.clearRect(0, 0, W, H), 0);
    };
    const add = (x, y, n, v, life, gr, big) => {
      for (let i = 0; i < n; i++) {
        const a = rnd(0, TAU), s = rnd(.3, 1) * v, fancy = shape && big && i % 3 === 0;
        P.push({x, y, vx: Math.cos(a) * s, vy: Math.sin(a) * s - (big ? 40 : 0), l: life * rnd(.6, 1), L: life, gr, c: th.bulbs[i % 4] === '#ffffff' ? '#fff4d0' : th.bulbs[i % 4], s: fancy ? rnd(7, 11) : big ? rnd(4, 8) : rnd(3, 6), img: fancy ? shape : null});
      }
      if (!raf) { tp = performance.now(); raf = requestAnimationFrame(loop); }
    };
    if (matchMedia('(pointer:fine)').matches) addEventListener('pointermove', e => {
      const now = performance.now(); if (!animOn() || now - lastMove < 28) return; lastMove = now; add(e.clientX, e.clientY, 1, 22, .7, -14);
    }, {passive: true});
    addEventListener('pointerdown', e => {
      if (e.button !== 0 || !animOn() || e.target.closest('a,button,input,select,textarea,label,.th-card')) return;
      add(e.clientX, e.clientY, 30, 230, 1.1, 260, true);
    });
  }

  // ── small line icons ──
  const GLYPH = {
    snow: '<svg viewBox="-12 -12 24 24"><g stroke="currentColor" stroke-width="1.4" fill="none" stroke-linecap="round">' + [0, 60, 120].map(a => `<path transform="rotate(${a})" d="M0-10V10M0-6.5l3-3M0-6.5l-3-3M0 6.5l3 3M0 6.5l-3 3"/>`).join('') + '</g></svg>',
    spark: '<svg viewBox="-12 -12 24 24"><path d="M0-11Q1.6-1.6 11 0Q1.6 1.6 0 11Q-1.6 1.6-11 0Q-1.6-1.6 0-11Z" fill="currentColor"/><circle r="1.7" fill="#fff"/></svg>',
    pumpkin: '<svg viewBox="-12 -12 24 24"><g stroke="currentColor" stroke-width="1.4" fill="none" stroke-linecap="round"><ellipse rx="10" ry="7.5" cy="2.5"/><path d="M0-5Q-5.5 2.5 0 10M0-5Q5.5 2.5 0 10M0-5Q0-8.5 3-10.5"/></g></svg>',
    heart: '<svg viewBox="-12 -12 24 24"><path d="M0 9C-15 0-8-12 0-4.5C8-12 15 0 0 9Z" stroke="currentColor" stroke-width="1.5" fill="none" stroke-linejoin="round"/></svg>',
    egg: '<svg viewBox="-12 -12 24 24"><g stroke="currentColor" stroke-width="1.4" fill="none" stroke-linejoin="round"><path d="M0-10.5C5.5-10.5 8.5-1 8.5 3C8.5 8 5 10.5 0 10.5C-5 10.5-8.5 8-8.5 3C-8.5-1-5.5-10.5 0-10.5Z"/><path d="M-8 1.5l2.7 2.7 2.7-2.7 2.6 2.7 2.7-2.7 2.7 2.7 2.6-2.7"/></g></svg>',
  };

  function css(th, id) {
    const b = th.bulbs, P = PAL[id];
    return `
html[data-theme]{--bg0:${P.bg[0]};--bg1:${P.bg[1]};--bg2:${P.bg[2]};--bg3:${P.bg[3]};--bdr:${P.bdr}}
html[data-theme] body{background-color:${P.bg[0]}}
.th-scene{position:absolute;left:0;top:0;width:100%;height:100%;pointer-events:none;z-index:0}
.th-scene.band{z-index:-1;-webkit-mask-image:linear-gradient(#000 55%,transparent);mask-image:linear-gradient(#000 55%,transparent)}
html[data-theme] :is(${CARDS}){background-image:linear-gradient(180deg,${P.tint},transparent 45%);border-color:${P.bdr};transition:box-shadow .35s,border-color .35s,transform .25s ease-out}
html[data-theme] :is(${CARDS}):hover{border-color:transparent;box-shadow:0 18px 40px -10px ${b[0]}55,0 0 30px -8px ${b[2]}55}
:where(.pop-card,.rv-card,.di,.celeb-card,.step){position:relative}
html[data-theme] .ab-stat{background:linear-gradient(135deg,${P.bg[1]},${P.bg[3]});border-color:${b[0]};box-shadow:0 10px 30px rgba(0,0,0,.55),0 0 24px -6px ${b[0]}66}
@property --tha{syntax:'<angle>';inherits:false;initial-value:0deg}
.th-rim{position:absolute;inset:0;border-radius:inherit;padding:1px;pointer-events:none;z-index:6;opacity:.0;transition:opacity .4s;
  background:conic-gradient(from var(--tha),${b[0]},transparent 22%,${b[2]} 40%,transparent 60%,${b[1]} 78%,${b[0]});
  -webkit-mask:linear-gradient(#000 0 0) content-box,linear-gradient(#000 0 0);-webkit-mask-composite:xor;mask-composite:exclude;animation:thRot 3.6s linear infinite}
:is(${CARDS}):hover>.th-rim{opacity:1}
.th-glare{position:absolute;inset:0;pointer-events:none;z-index:5;opacity:0;transition:opacity .3s;background:radial-gradient(380px circle at var(--mx,50%) var(--my,0%),rgba(255,255,255,.1),transparent 45%)}
:is(${CARDS}):hover>.th-glare{opacity:1}
.th-glyph{position:absolute;top:10px;left:10px;width:20px;height:20px;color:${b[0] === '#ffffff' ? b[1] : b[0]};z-index:6;pointer-events:none;opacity:.9;
  filter:drop-shadow(0 0 5px currentColor) drop-shadow(0 2px 3px rgba(0,0,0,.6));animation:thGlyph 7s ease-in-out infinite}
.th-glyph svg{display:block;width:100%;height:100%}
:is(${CARDS}):hover>.th-glyph{animation-duration:1.6s}
@keyframes thGlyph{0%,100%{transform:rotate(-12deg) scale(1)}50%{transform:rotate(12deg) scale(1.12)}}
@keyframes thRot{to{--tha:360deg}}
.th-glowbg{position:fixed;inset:0;pointer-events:none;z-index:1390;background:radial-gradient(60% 45% at 8% 0%,${th.glow[0]},transparent 70%),radial-gradient(55% 40% at 95% 5%,${th.glow[1]},transparent 70%);mix-blend-mode:screen}
.th-garland{position:absolute;left:0;right:0;bottom:-13px;height:18px;pointer-events:none;display:flex;justify-content:space-around;overflow:hidden;z-index:1}
.th-garland svg{position:absolute;left:0;top:0;width:100%;height:8px}
.th-garland i{position:relative;width:7px;height:11px;border-radius:45% 45% 50% 50%;margin-top:4px;animation:thBulb 2.6s infinite ease-in-out;background:radial-gradient(circle at 35% 30%,#fff 0 14%,currentColor 45%)}
.th-garland i::before{content:'';position:absolute;top:-3px;left:1.5px;width:4px;height:3px;background:#3a3a3a;border-radius:1px}
.th-garland i:nth-child(odd){margin-top:6px}
.th-garland i:nth-child(4n+1){color:${b[0]}}
.th-garland i:nth-child(4n+2){color:${b[1]};animation-delay:.65s}
.th-garland i:nth-child(4n+3){color:${b[2]};animation-delay:1.3s}
.th-garland i:nth-child(4n+4){color:${b[3]};animation-delay:1.95s}
@keyframes thBulb{0%,100%{opacity:.45;box-shadow:none}50%{opacity:1;box-shadow:0 0 10px 3px currentColor}}
html[data-theme] .m-tab{transition:.3s}
html[data-theme] .m-tab:hover{border-color:${b[0]}88;box-shadow:0 0 14px -4px ${b[0]}88}
html[data-theme] .m-tab.on{box-shadow:0 0 18px -2px ${b[0]}88,inset 0 0 14px -4px ${b[0]}66;border-color:${b[0]};color:#fff}
.nav-logo{position:relative}
.th-logo{position:absolute;left:-12px;top:-10px;width:16px;height:16px;color:${b[0] === '#ffffff' ? b[1] : b[0]};pointer-events:none;filter:drop-shadow(0 0 5px currentColor);animation:thGlyph 5s ease-in-out infinite}
.th-logo svg{display:block;width:100%;height:100%}
#thFx{position:fixed;inset:0;width:100%;height:100%;pointer-events:none;z-index:1500}
.th-ribbon{display:inline-flex;align-items:center;gap:10px;margin:0 auto 22px;padding:9px 20px;border:1px solid ${b[0]}aa;border-radius:999px;
  background:rgba(10,10,10,.35);backdrop-filter:blur(6px);-webkit-backdrop-filter:blur(6px);color:#f3ead9;text-decoration:none;
  font:600 .74rem 'Raleway',sans-serif;letter-spacing:2px;text-transform:uppercase;position:relative;overflow:hidden;animation:thIn .8s ease-out;box-shadow:0 0 22px -6px ${b[0]}88}
.th-ribbon i{display:inline-block;width:15px;height:15px;color:${b[0] === '#ffffff' ? b[1] : b[0]};filter:drop-shadow(0 0 4px currentColor)}
.th-ribbon i svg{display:block;width:100%;height:100%}
.th-ribbon::after{content:'';position:absolute;inset:0;background:linear-gradient(100deg,transparent 30%,rgba(255,255,255,.18) 50%,transparent 70%);transform:translateX(-100%);animation:thShine 3.5s ease-in-out infinite}
.th-ribbon:hover{border-color:#fff}
.th-ribbon-wrap{text-align:center;position:relative;z-index:1}
@keyframes thShine{60%,100%{transform:translateX(100%)}}
.th-card{position:fixed;left:18px;bottom:18px;z-index:1600;display:flex;gap:14px;align-items:center;max-width:410px;border-radius:16px;
  background:linear-gradient(135deg,rgba(28,24,20,.72),rgba(12,12,14,.78));backdrop-filter:blur(14px) saturate(1.3);-webkit-backdrop-filter:blur(14px) saturate(1.3);
  border:1px solid rgba(255,255,255,.1);padding:16px 40px 16px 14px;box-shadow:0 22px 60px rgba(0,0,0,.6),0 0 40px -12px ${b[0]}88,inset 0 1px 0 rgba(255,255,255,.08);
  font-family:'Raleway',sans-serif;animation:thIn .8s cubic-bezier(.2,1.2,.4,1)}
.th-card::before{content:'';position:absolute;inset:0;border-radius:inherit;padding:1px;pointer-events:none;background:conic-gradient(from var(--tha),${b[0]},transparent 30%,${b[2]} 50%,transparent 75%,${b[0]});
  -webkit-mask:linear-gradient(#000 0 0) content-box,linear-gradient(#000 0 0);-webkit-mask-composite:xor;mask-composite:exclude;animation:thRot 5s linear infinite}
.th-card canvas{width:64px;height:64px;flex:none}
.th-card b.th-h{display:block;font:400 1.2rem 'Playfair Display',serif;color:#fbf4e6;margin-bottom:3px}
.th-card p{font-size:.78rem;color:#c2b69f;margin:0 0 9px;line-height:1.45}
.th-cd{font-size:.68rem;color:#a99d88;letter-spacing:1px;text-transform:uppercase;margin:0 0 10px}
.th-cd .th-seg{display:flex;gap:6px;margin-top:5px}
.th-cd .th-seg span{min-width:44px;padding:5px 4px 4px;border-radius:8px;text-align:center;background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.08)}
.th-cd .th-seg b{display:block;font:600 1.05rem 'Raleway',sans-serif;color:#fff;font-variant-numeric:tabular-nums;text-shadow:0 0 10px ${b[0]}}
.th-cd .th-seg i{font-style:normal;font-size:.56rem;color:#a99d88;letter-spacing:.5px}
.th-cd.today{font-size:.9rem;color:${b[0] === '#ffffff' ? b[1] : b[0]};text-transform:none;letter-spacing:0}
.th-card a{display:inline-block;font-size:.68rem;letter-spacing:1.5px;text-transform:uppercase;color:#0b0b0b;background:linear-gradient(90deg,${b[0]},${b[2]});padding:8px 15px;border-radius:999px;text-decoration:none;font-weight:700;transition:.2s}
.th-card a:hover{filter:brightness(1.15);transform:translateY(-1px)}
.th-card .th-x{position:absolute;top:8px;right:10px;background:none;border:none;color:#8d8270;font-size:1rem;cursor:pointer;padding:4px}
.th-card .th-x:hover{color:#fff}
.th-fxbtn{position:fixed;right:14px;bottom:14px;z-index:1600;width:42px;height:42px;border-radius:50%;border:1px solid rgba(255,255,255,.16);display:grid;place-items:center;
  background:rgba(15,15,15,.6);backdrop-filter:blur(8px);-webkit-backdrop-filter:blur(8px);color:${b[0] === '#ffffff' ? b[1] : b[0]};cursor:pointer;transition:.25s;box-shadow:0 0 18px -6px currentColor}
.th-fxbtn span{width:18px;height:18px;filter:drop-shadow(0 0 4px currentColor)}
.th-fxbtn svg{display:block;width:100%;height:100%}
.th-fxbtn:hover{transform:scale(1.08) rotate(12deg)}
.th-fxbtn.off{filter:grayscale(1);opacity:.45;box-shadow:none}
@keyframes thIn{from{opacity:0;transform:translateY(24px) scale(.96)}to{opacity:1;transform:none}}
@media(max-width:600px){.th-card{left:10px;right:62px;bottom:10px;max-width:none;padding:12px 32px 12px 10px;gap:10px}.th-card canvas{width:48px;height:48px}.th-card b.th-h{font-size:1rem}.th-cd .th-seg span{min-width:38px}.th-glyph{width:17px;height:17px}}
@media print{.th-glowbg,.th-garland,.th-logo,#thFx,.th-card,.th-fxbtn,.th-ribbon-wrap,.th-scene,.th-rim,.th-glare,.th-glyph{display:none}}`;
  }

  // ── decorations on the cards: a running light rim, a glare that follows the mouse and a small holiday icon ──
  function decorate(th) {
    document.querySelectorAll(CARDS).forEach(c => {
      if (c.querySelector(':scope > .th-rim')) return;
      const add = (cls, html) => { const s = document.createElement('span'); s.className = cls; if (html) s.innerHTML = html; c.appendChild(s); };
      add('th-rim'); add('th-glare'); add('th-glyph', GLYPH[th.glyph]);
    });
  }
  function tilt() {
    if (!matchMedia('(pointer:fine)').matches) return;
    let cur = null;
    const reset = () => { if (cur) { cur.style.transform = ''; cur = null; } };
    addEventListener('pointermove', e => {
      const c = e.target.closest && e.target.closest(CARDS);
      if (c !== cur) reset();
      if (!c) return;
      cur = c; const r = c.getBoundingClientRect(), dx = (e.clientX - r.left) / r.width - .5, dy = (e.clientY - r.top) / r.height - .5;
      c.style.setProperty('--mx', (dx + .5) * 100 + '%'); c.style.setProperty('--my', (dy + .5) * 100 + '%');
      if (animOn()) c.style.transform = `perspective(900px) rotateX(${(-dy * 5).toFixed(2)}deg) rotateY(${(dx * 6).toFixed(2)}deg) translateY(-5px)`;
    }, {passive: true});
    document.addEventListener('pointerleave', reset);
  }

  // greeting card with a live countdown (days / hours / minutes / seconds)
  function card(id, th, banner, preview) {
    document.querySelector('.th-card')?.remove();
    const key = 'cm_th_seen_' + id + '_' + new Date().getFullYear();
    if (!preview && store(key) === '1') return;
    const l = L(), ui = UI[l] || UI.cs, nd = nextDate(th);
    const own = banner && (banner[l] || banner.cs);
    const el = document.createElement('div');
    el.className = 'th-card';
    el.innerHTML = `<canvas></canvas><div><b class="th-h">${esc(th.greet[l] || th.greet.cs)}</b><p>${esc(own || th.sub[l] || th.sub.cs)}</p>`
      + (nd ? (nd.on ? `<div class="th-cd today">${esc(ui.today)}</div>` : `<div class="th-cd">${esc(th.to[l] || th.to.cs)}<div class="th-seg">${ui.u.map(u => `<span><b>0</b><i>${esc(u)}</i></span>`).join('')}</div></div>`) : '')
      + (/menu\.html$/.test(location.pathname) ? '' : `<a href="menu.html">${esc(ui.menu)} →</a>`)
      + `</div><button type="button" class="th-x" aria-label="${esc(ui.close)}">✕</button>`;
    el.querySelector('.th-x').onclick = () => { store(key, '1'); el.style.transition = '.3s'; el.style.opacity = '0'; el.style.transform = 'translateY(20px)'; setTimeout(() => el.remove(), 300); };
    document.body.appendChild(el);
    mini(el.querySelector('canvas'), th);
    const seg = el.querySelectorAll('.th-seg b');
    if (seg.length) {
      const tick = () => {
        if (!el.isConnected) return clearInterval(iv);
        let s = Math.max(0, Math.floor((nd.d - new Date()) / 1000));
        [Math.floor(s / 86400), Math.floor(s / 3600) % 24, Math.floor(s / 60) % 60, s % 60].forEach((v, i) => { seg[i].textContent = i ? String(v).padStart(2, '0') : v; });
      };
      const iv = setInterval(tick, 1000); tick();
    }
  }

  function ribbon(th) {
    document.querySelector('.th-ribbon-wrap')?.remove();
    const hero = document.querySelector('.logo-block');
    if (!hero) return;
    const l = L(), w = document.createElement('div'); w.className = 'th-ribbon-wrap';
    w.innerHTML = `<a class="th-ribbon" href="menu.html"><i>${GLYPH[th.glyph]}</i>${esc(th.ribbon[l] || th.ribbon.cs)} <span>→</span></a>`;
    hero.parentNode.insertBefore(w, hero);
  }

  function apply(id, cfg, preview) {
    const th = THEMES[id];
    if (!th) return;
    effects = cfg.effects !== false;
    document.documentElement.dataset.theme = id;
    const st = document.createElement('style'); st.id = 'thCss'; st.textContent = css(th, id); document.head.appendChild(st);
    const gl = document.createElement('div'); gl.className = 'th-glowbg'; document.body.appendChild(gl);
    const nav = document.getElementById('nav');
    if (nav) {
      const g = document.createElement('div'); g.className = 'th-garland';
      const n = Math.ceil(innerWidth / 30);
      g.innerHTML = `<svg viewBox="0 0 ${n * 30} 8" preserveAspectRatio="none"><path d="${Array.from({length: n}, (_, i) => `M${i * 30} 1 Q${i * 30 + 15} 7 ${i * 30 + 30} 1`).join(' ')}" stroke="rgba(255,255,255,.22)" fill="none"/></svg>` + '<i></i>'.repeat(n);
      nav.appendChild(g);
      const logo = nav.querySelector('.nav-logo');
      if (logo) { const s = document.createElement('span'); s.className = 'th-logo'; s.innerHTML = GLYPH[th.glyph]; logo.appendChild(s); }
    }
    ribbon(th);
    decorate(th);
    let pend = 0;
    new MutationObserver(() => { if (!pend) pend = requestAnimationFrame(() => { pend = 0; decorate(th); }); })
      .observe(document.body, {childList: true, subtree: true});
    tilt();
    if (!QUIET) {
      const host = document.getElementById('hero') || document.querySelector('main section, body > section');
      if (host) scene(host, th, host.id === 'hero');
      sparks(th);
      if (effects) {
        const b = document.createElement('button'); b.type = 'button'; b.className = 'th-fxbtn'; b.innerHTML = `<span>${GLYPH[th.glyph]}</span>`;
        const upd = () => { const off = store('cm_fx_off') === '1'; b.classList.toggle('off', off); b.title = (UI[L()] || UI.cs).fx + (off ? ' ✕' : ' ✓'); };
        b.onclick = () => { store('cm_fx_off', store('cm_fx_off') === '1' ? '0' : '1'); upd(); KICK.forEach(k => k()); };
        upd(); document.body.appendChild(b);
      }
    }
    card(id, th, cfg.banner, preview);
    // language buttons re-render the texts in the new language
    document.addEventListener('click', e => {
      if (!e.target.closest('.lang-btn')) return;
      setTimeout(() => { ribbon(th); if (document.querySelector('.th-card')) card(id, th, cfg.banner, true); }, 30);
    });
  }

  const preview = new URLSearchParams(location.search).get('theme');
  if (preview && THEMES[preview]) { apply(preview, {effects: true}, true); return; }
  fetch('/api/theme', {cache: 'no-store'}).then(r => r.ok ? r.json() : null).then(cfg => { if (cfg && cfg.theme) apply(cfg.theme, cfg, false); }).catch(() => {});
})();

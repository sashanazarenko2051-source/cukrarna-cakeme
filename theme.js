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
      let pic = null;
      return {flat(g, cx, cy, S, t, al) {
        const r = Math.round(S * .78), h = Math.round(r * 2.6);
        if (!pic || pic.r !== r) pic = {r, c: mk(h * 2, h * 2, q => {
          q.globalAlpha = .55; q.drawImage(soft('#ffcf8a'), 0, 0, h * 2, h * 2); q.globalAlpha = 1;
          const m = q.createRadialGradient(h - r * .3, h - r * .35, r * .1, h, h, r);
          m.addColorStop(0, '#fff6dc'); m.addColorStop(.7, '#f3d79a'); m.addColorStop(1, '#d9a95c');
          q.fillStyle = m; q.beginPath(); q.arc(h, h, r, 0, TAU); q.fill();
          q.fillStyle = 'rgba(160,110,50,.22)';
          for (const [dx, dy, rr] of [[-.3, -.2, .18], [.25, .15, .24], [-.05, .45, .12], [.38, -.38, .1], [-.45, .25, .09]]) { q.beginPath(); q.arc(h + dx * r, h + dy * r, rr * r, 0, TAU); q.fill(); }
        })};
        g.globalCompositeOperation = 'source-over'; g.globalAlpha = al; g.drawImage(pic.c, cx - h, cy - h);
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
  function drawObj(g, O, cx, cy, S, t, rx, ry, al, dir, thin) {
    if (O.flat) return O.flat(g, cx, cy, S, t, al);
    const ang = (O.spin ? t * O.spin * dir : Math.sin(t * .45) * O.sway) + ry, ca = Math.cos(ang), sa = Math.sin(ang), cb = Math.cos(rx), sb = Math.sin(rx);
    let sc = S;
    if (O.beat) { const b = (t * 1.05) % 1; sc *= 1 + .07 * Math.exp(-((b - .1) ** 2) / .003) + .045 * Math.exp(-((b - .3) ** 2) / .003); }
    const st = thin || S < 150 ? 2 : 1, F = 3.4, base = Math.max(1, S * .03) * (st > 1 ? 1.3 : 1), pts = O.pts;
    const proj = (x, y, z) => { const x1 = x * ca - z * sa, z1 = x * sa + z * ca, y2 = y * cb - z1 * sb, z2 = y * sb + z1 * cb, k = F / (F + z2); return [cx + x1 * sc * k, cy + y2 * sc * k, z2, k]; };
    if (O.hang) {  // the thread up to the top of the scene
      const [hx, hy] = proj(0, O.hang, 0); g.globalAlpha = al * .5; g.strokeStyle = '#c9a96e'; g.lineWidth = 1; g.beginPath(); g.moveTo(hx, 0); g.lineTo(hx, hy); g.stroke();
    }
    if (O.core) { const f = .75 + .25 * Math.sin(t * 9) * Math.sin(t * 5.3); g.globalAlpha = al * .55 * f; const r = sc * .9; g.drawImage(soft(O.core), cx - r, cy - r, r * 2, r * 2); }
    const ks = sc * F;
    for (let i = 0; i < pts.length; i += st) {  // inlined projection: no garbage per point, so no GC hiccups
      const p = pts[i], x1 = p.x * ca - p.z * sa, z1 = p.x * sa + p.z * ca, y2 = p.y * cb - z1 * sb, z = p.y * sb + z1 * cb, k = 1 / (F + z);
      let r = p.s * F * k * base; if (p.tw != null) r *= .55 + .55 * Math.sin(t * 3 + p.tw);
      if (r <= .2) continue;
      g.globalAlpha = al * (.18 + .42 * (1 - (z + 1) / 2));
      g.drawImage(p.img || (p.img = glow(p.c)), cx + x1 * ks * k - r * 2, cy + y2 * ks * k - r * 2, r * 4, r * 4);
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
    let W = 0, H = 0, dpr = 1, lite = false, lay = [], bok = [], parts = [], fw = [], nextFw = 0, sx = 0, sy = 0;
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
      bok = Array.from({length: 6}, (_, i) => ({x: R() * W, y: R() * H, r: rnd(40, 110), z: rnd(.2, 1), c: th.bulbs[i % 4], a: rnd(.05, .12), vx: rnd(-6, 6), vy: rnd(-4, 4)}));
      parts = [];
      const n = k => Math.round(Math.min(k * area / 1e6, k * 1.6));
      if (has('snow')) for (let i = 0; i < n(110); i++) parts.push({k: 'snow', x: R() * W, y: R() * H, z: rnd(.25, 1), ph: R() * TAU});
      if (has('embers')) for (let i = 0; i < n(55); i++) parts.push({k: 'ember', x: R() * W, y: R() * H, z: rnd(.3, 1), ph: R() * TAU, c: ['#ff8a1f', '#ffb347', '#ff5a1f'][i % 3]});
      if (has('fog')) for (let i = 0; i < 3; i++) parts.push({k: 'fog', x: R() * W, y: H * rnd(.45, 1), z: rnd(.5, 1), c: ['#6a2fa8', '#3a1d5c', '#8e4bd6'][i % 3]});
      if (has('hearts')) for (let i = 0; i < n(32); i++) parts.push({k: 'heart', x: R() * W, y: R() * H, z: rnd(.3, 1), ph: R() * TAU, c: ['#ff5d8f', '#ff9eb5', '#e5484d', '#ffd1dc'][i % 4]});
      if (has('petals')) for (let i = 0; i < n(40); i++) parts.push({k: 'petal', x: R() * W, y: R() * H, z: rnd(.35, 1), ph: R() * TAU, rot: R() * TAU, c: ['#ffb3c7', '#ffd36e', '#ffffff', '#c7f0c0'][i % 4]});
    }
    function resize() {
      dpr = 1; W = host.clientWidth; H = hero ? host.clientHeight : Math.min(480, host.clientHeight); lite = W < 760;
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
        g.drawImage(b.img || (b.img = soft(b.c)), x - b.r, y - b.r, b.r * 2, b.r * 2);
      }
      for (const p of parts) {
        if (p.k === 'fog') {
          p.x += (12 * p.z) * dt; if (p.x > W + 300) p.x = -300;
          g.globalAlpha = .12; const r = W * .22 * p.z; g.drawImage(p.img || (p.img = soft(p.c)), p.x - r, p.y - r * .5, r * 2, r);
        } else if (p.k === 'snow') {
          p.y += (16 + 46 * p.z) * dt; p.x += Math.sin(t * .8 + p.ph) * 12 * p.z * dt; if (p.y > H + 6) { p.y = -6; p.x = Math.random() * W; }
          const r = 1.2 + 3.2 * p.z; g.globalAlpha = .25 + .55 * p.z; g.drawImage(p.img || (p.img = glow('#dfefff')), p.x - sx * 14 * p.z - r, p.y - r, r * 2, r * 2);
        } else if (p.k === 'ember') {
          p.y -= (14 + 40 * p.z) * dt; p.x += Math.sin(t * 1.3 + p.ph) * 18 * p.z * dt; if (p.y < -8) { p.y = H + 8; p.x = Math.random() * W; }
          const r = 1 + 2.6 * p.z; g.globalAlpha = (.35 + .5 * p.z) * (.6 + .4 * Math.sin(t * 7 + p.ph)); g.drawImage(p.img || (p.img = glow(p.c)), p.x - r * 2, p.y - r * 2, r * 4, r * 4);
        } else if (p.k === 'heart') {
          p.y -= (12 + 30 * p.z) * dt; p.x += Math.sin(t + p.ph) * 14 * p.z * dt; if (p.y < -20) { p.y = H + 20; p.x = Math.random() * W; }
          const r = 5 + 9 * p.z; g.globalAlpha = .18 + .45 * p.z; g.drawImage(p.img || (p.img = heartSpr(p.c)), p.x - sx * 12 * p.z - r, p.y - r, r * 2, r * 2);
        } else if (p.k === 'petal') {
          p.y += (14 + 34 * p.z) * dt; p.x += (Math.sin(t * .9 + p.ph) * 22 + 10) * p.z * dt; p.rot += dt * (.6 + p.z); if (p.y > H + 16) { p.y = -16; p.x = Math.random() * W; }
          const r = 5 + 8 * p.z; g.globalCompositeOperation = 'source-over'; g.globalAlpha = .3 + .5 * p.z;
          g.save(); g.translate(p.x - sx * 12 * p.z, p.y); g.rotate(p.rot); g.scale(1, Math.cos(t * 2 + p.ph)); g.drawImage(p.img || (p.img = petalSpr(p.c)), -r, -r, r * 2, r * 2); g.restore();
          g.globalCompositeOperation = 'lighter';
        }
      }
      for (const o of lay) drawObj(g, o.o, o.x + sx * 10, o.y + sy * 6, o.S, t + o.dir, .12 + sy * .22, sx * .55, o.a, o.dir, lite);
      if (has('fireworks') && dt) {
        if (t > nextFw) { boom(); nextFw = t + rnd(1.4, 2.8); }
        fw = fw.filter(p => (p.l -= dt) > 0);
        for (const p of fw) {
          p.vx *= .985; p.vy = p.vy * .985 + 55 * dt; p.x += p.vx * dt; p.y += p.vy * dt;
          const k = p.l / p.L, r = 1.6 + 2.4 * k; g.globalAlpha = Math.min(1, k * 1.4) * (.7 + .3 * Math.sin(t * 30 + p.x));
          g.drawImage(p.img || (p.img = glow(p.c)), p.x - r * 2, p.y - r * 2, r * 4, r * 4);
        }
      }
      g.globalAlpha = 1; g.globalCompositeOperation = 'source-over';
    }
    resize();
    let raf = 0, vis = true, tp = 0;
    new ResizeObserver(() => { resize(); if (!raf) frame(2.4, 0); }).observe(host);
    const running = () => vis && !document.hidden && animOn();
    const loop = now => {
      raf = 0; if (!cv.isConnected) return;
      if (!lite || now - tp > 30) { const dt = Math.min(.06, (now - tp) / 1000); tp = now; frame(now / 1000, dt); }  // phones: ~30 fps
      if (running()) raf = requestAnimationFrame(loop);
    };
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
    const size = () => { dpr = 1; W = innerWidth; H = innerHeight; cv.width = W * dpr; cv.height = H * dpr; };
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
      if (e.button !== 0 || !animOn()) return;
      const buy = e.target.closest('button') && e.target.closest(CARDS);  // a burst on "add to cart" too
      if (!buy && e.target.closest('a,button,input,select,textarea,label,.th-card')) return;
      add(e.clientX, e.clientY, buy ? 22 : 30, buy ? 180 : 230, 1.1, 260, true);
    });
  }

  // ── drawn holiday characters that come to the logo ──
  const GRAD = `<radialGradient id="thBr" cx="35%" cy="30%" r="75%"><stop offset="0" stop-color="#ff9a9a"/><stop offset=".45" stop-color="#d4202c"/><stop offset="1" stop-color="#5a0a10"/></radialGradient>
    <radialGradient id="thBg" cx="35%" cy="30%" r="75%"><stop offset="0" stop-color="#fff4c4"/><stop offset=".45" stop-color="#e0a83a"/><stop offset="1" stop-color="#6b4710"/></radialGradient>
    <radialGradient id="thBb" cx="35%" cy="30%" r="75%"><stop offset="0" stop-color="#cfe6ff"/><stop offset=".45" stop-color="#2f6fd1"/><stop offset="1" stop-color="#0d2554"/></radialGradient>
    <radialGradient id="thBs" cx="35%" cy="30%" r="75%"><stop offset="0" stop-color="#ffffff"/><stop offset=".45" stop-color="#b9c3cf"/><stop offset="1" stop-color="#4a5260"/></radialGradient>
    <linearGradient id="thRib" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#ef4a50"/><stop offset="1" stop-color="#9a141c"/></linearGradient>
    <filter id="thGl" x="-100%" y="-100%" width="300%" height="300%"><feGaussianBlur stdDeviation="2.2"/></filter>`;
  // Santa in his sleigh with two reindeer, facing left (towards the logo)
  const DEER = (x, nose) => `<g transform="translate(${x} 14)"><g class="th-rd">
      ${nose ? '<circle class="th-nose" cx="1.5" cy="23" r="6" fill="#ff2d2d" filter="url(#thGl)"/>' : ''}
      <g class="th-lf"><path d="M21 49 L16 66 M25 49 L25 67" stroke="#5e3a18" stroke-width="3.2" stroke-linecap="round"/></g>
      <g class="th-lb"><path d="M40 49 L46 64 M44 48 L51 62" stroke="#5e3a18" stroke-width="3.2" stroke-linecap="round"/></g>
      <ellipse cx="33" cy="43" rx="20" ry="10" fill="url(#thDeer)"/>
      <path d="M19 42 C12 36 11 28 14 22 L22 23 C20 30 22 36 27 40 Z" fill="url(#thDeer)"/>
      <ellipse cx="12" cy="20" rx="8.5" ry="5.6" fill="#a87442" transform="rotate(-14 12 20)"/>
      <ellipse cx="5" cy="22.5" rx="4.5" ry="3.2" fill="#c49461"/>
      <circle cx="${nose ? 1.6 : 1.8}" cy="22.6" r="${nose ? 2.8 : 1.8}" fill="${nose ? '#ff2d2d' : '#2a1a10'}"/>
      <circle cx="11.5" cy="18.4" r="1.2" fill="#1a1010"/><path d="M17 15 q4 -3 6 1 q-3 1 -6 -1Z" fill="#8a5a2e"/>
      <path d="M13.5 14 C12 8 9 5 5 2 M9.5 7 L4 7.5 M16 13.5 C17 7 20 4 25 1 M19.5 6 L25 7" stroke="#e8d0a8" stroke-width="1.9" stroke-linecap="round" fill="none"/>
      <circle cx="52" cy="39" r="3.2" fill="#f5ead8"/>
      <path d="M20 37 Q33 47 45 37" stroke="#b3202a" stroke-width="3.4" fill="none"/>
      <circle cx="27" cy="42" r="2" fill="url(#thBg)"/><circle cx="33" cy="43.6" r="2" fill="url(#thBg)"/><circle cx="39" cy="42" r="2" fill="url(#thBg)"/>
    </g></g>`;
  const SANTA = `<svg viewBox="0 0 270 112" overflow="visible"><defs>${GRAD}
      <linearGradient id="thDeer" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#b07a45"/><stop offset="1" stop-color="#6e4520"/></linearGradient>
      <linearGradient id="thRed" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#f04a50"/><stop offset="1" stop-color="#a3141d"/></linearGradient>
      <linearGradient id="thSl" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#d9303a"/><stop offset="1" stop-color="#760d14"/></linearGradient>
      <radialGradient id="thSack" cx="40%" cy="35%" r="70%"><stop offset="0" stop-color="#a8773f"/><stop offset="1" stop-color="#55361a"/></radialGradient></defs>
    ${DEER(0, true)}${DEER(64, false)}
    <path d="M45 52 Q64 64 84 52 M109 52 Q132 70 156 68" stroke="#e8c06a" stroke-width="1.4" fill="none"/>
    <g class="th-sleigh">
      <path d="M220 60 C210 34 218 16 233 18 C249 20 253 38 244 60 Z" fill="url(#thSack)"/>
      <rect x="221" y="11" width="13" height="11" rx="1.5" fill="#2f8a4f"/><path d="M227.5 11 v11 M221 16.5 h13" stroke="#f5d67a" stroke-width="1.6"/>
      <rect x="236" y="14" width="11" height="9" rx="1.5" fill="#e5484d"/><path d="M241.5 14 v9 M236 18.5 h11" stroke="#fff" stroke-width="1.4"/>
      <path d="M170 70 C170 46 178 36 191 36 C204 36 211 46 211 70 Z" fill="url(#thRed)"/>
      <path d="M189 37 v30" stroke="#fff" stroke-width="3"/>
      <g class="th-arm"><path d="M183 46 Q170 40 166 27" stroke="url(#thRed)" stroke-width="6.5" stroke-linecap="round" fill="none"/><circle cx="165.5" cy="25" r="4" fill="#2f8a4f"/><path d="M170 34 h7" stroke="#fff" stroke-width="3" transform="rotate(-55 173 34)"/></g>
      <circle cx="190" cy="26" r="9" fill="#ffd9bd"/><circle cx="184.5" cy="28" r="2.4" fill="#ff9e9e" opacity=".7"/>
      <path d="M180 26 C179 40 185 46 190 47 C196 46 201 40 200 26 C196 33 184 33 180 26 Z" fill="#fff"/>
      <path d="M183 29 q4 3 7 0 q3 3 7 0" stroke="#f2f2f2" stroke-width="2.6" fill="none" stroke-linecap="round"/>
      <circle cx="186" cy="23.5" r="1.1" fill="#222"/><circle cx="192.5" cy="23.5" r="1.1" fill="#222"/>
      <path d="M180 20 Q186 3 206 9 Q201 13 199 20 Z" fill="url(#thRed)"/><rect x="178.5" y="17" width="23" height="6" rx="3" fill="#fff"/><circle cx="207" cy="10" r="3.8" fill="#fff"/>
      <path d="M154 64 H236 Q248 64 250 52 L254 34 Q256 29 260 31 L256 62 Q252 84 230 84 H168 Q154 84 154 72 Z" fill="url(#thSl)" stroke="#e8c06a" stroke-width="2"/>
      <path d="M172 74 q10 -8 20 0 q10 8 20 0 q8 -6 16 0" stroke="#e8c06a" stroke-width="1.5" fill="none"/>
      <path d="M176 84 v10 M226 84 v10" stroke="#e8c06a" stroke-width="2.4"/>
      <path d="M146 94 H240 Q256 94 256 84 M146 94 Q132 94 134 86 Q136 79 143 82" stroke="#e8c06a" stroke-width="3.2" fill="none" stroke-linecap="round"/>
    </g></svg>`;
  // ── the witch on her broom with a black cat (Halloween), facing left ──
  const WITCH = `<svg viewBox="0 0 250 122" overflow="visible"><defs>${GRAD}
      <linearGradient id="thWd" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#8a4bd0"/><stop offset="1" stop-color="#3a1866"/></linearGradient>
      <linearGradient id="thWh" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#4a2a6a"/><stop offset="1" stop-color="#140a20"/></linearGradient>
      <linearGradient id="thBroom" x1="0" y1="0" x2="1" y2="0"><stop offset="0" stop-color="#8a5a2e"/><stop offset="1" stop-color="#5a3518"/></linearGradient></defs>
    <g class="th-cape"><path d="M124 50 C152 46 180 52 206 36 C200 62 170 78 132 74 Z" fill="#26103c"/><path d="M128 56 C152 54 172 58 196 48" stroke="#4a2470" stroke-width="1.4" fill="none"/></g>
    <path d="M28 88 L210 98" stroke="url(#thBroom)" stroke-width="5.5" stroke-linecap="round"/>
    <g class="th-bristle">${Array.from({length: 11}, (_, i) => `<path d="M206 97 Q224 ${90 + i * 1.5} 244 ${78 + i * 4}" stroke="${['#e2b04f', '#c48a2c', '#f0c868'][i % 3]}" stroke-width="2.4" fill="none" stroke-linecap="round"/>`).join('')}
      <rect x="201" y="92" width="9" height="11" rx="2" fill="#8a2a2a"/></g>
    <g class="th-cat" transform="translate(176 74)"><path class="th-tail" d="M9 13 C20 10 19 -5 12 -3" stroke="#0d0d0d" stroke-width="3.2" fill="none" stroke-linecap="round"/>
      <ellipse cx="0" cy="13" rx="9.5" ry="7" fill="#0d0d0d"/><circle cx="-8" cy="4" r="5.8" fill="#0d0d0d"/>
      <path d="M-13 1 L-12 -6 L-8 -1 Z M-6 -1 L-3 -7 L-2 1 Z" fill="#0d0d0d"/>
      <circle cx="-10" cy="3.5" r="1.3" fill="#ffd34d"/><circle cx="-6" cy="3.5" r="1.3" fill="#ffd34d"/></g>
    <path d="M110 90 L98 106" stroke="#111" stroke-width="5.4" stroke-linecap="round"/><path d="M110 90 L98 106" stroke="#ff8a1f" stroke-width="5.4" stroke-dasharray="2.4 3"/>
    <path d="M101 105 L89 107 Q85 106 88 102" stroke="#1a1a1a" stroke-width="4.5" fill="none" stroke-linecap="round"/>
    <path d="M102 92 C104 62 114 52 126 52 C140 52 146 66 148 92 Z" fill="url(#thWd)"/>
    <rect x="106" y="70" width="38" height="5" fill="#1a0d28"/><rect x="121" y="69" width="7" height="7" rx="1" fill="none" stroke="#e8c06a" stroke-width="1.6"/>
    <g class="th-arm"><path d="M116 62 Q102 70 98 86" stroke="url(#thWd)" stroke-width="7.5" stroke-linecap="round" fill="none"/><circle cx="98" cy="88" r="3.8" fill="#f3cfae"/></g>
    <path d="M112 34 C104 46 106 58 113 63 C117 52 119 45 119 38 Z M134 36 C143 45 142 57 136 64 C132 53 130 45 130 39 Z" fill="#e8742a"/>
    <circle cx="124" cy="38" r="10.5" fill="#f6d3b2"/><circle cx="118" cy="41" r="2.6" fill="#ff9e9e" opacity=".6"/>
    <circle cx="120" cy="36" r="1.3" fill="#2a1a10"/><circle cx="127" cy="36" r="1.3" fill="#2a1a10"/>
    <path d="M119 43 Q123 46 127 43" stroke="#a03a3a" stroke-width="1.4" fill="none" stroke-linecap="round"/>
    <ellipse cx="124" cy="29" rx="20" ry="4.5" fill="url(#thWh)"/>
    <path d="M110 29 C113 16 119 7 126 -1 C130 -7 139 -9 143 -5 C137 -3 134 5 136 13 C137 20 138 25 138 29 Z" fill="url(#thWh)"/>
    <path d="M111 25 h26 v4 h-26 z" fill="#8a4bd0"/><rect x="120" y="24" width="7" height="6" rx="1" fill="none" stroke="#e8c06a" stroke-width="1.4"/>
    <path d="M133 10 l1.6 3.2 3.4 .4 -2.5 2.3 .7 3.4 -3.2 -1.7 -3 1.7 .6 -3.4 -2.4 -2.3 3.3 -.4 Z" fill="#ffd36e"/>
  </svg>`;
  // ── heart balloons with a gift (Valentine's) ──
  const HEARTP = 'M0 -6 C0 -16 13 -19 17 -8 C21 -19 34 -16 34 -6 C34 8 17 18 17 24 C17 18 0 8 0 -6 Z';
  const BALLOONS = `<svg viewBox="0 0 190 175" overflow="visible"><defs>
      <radialGradient id="thH1" cx="35%" cy="30%" r="80%"><stop offset="0" stop-color="#ffb3c7"/><stop offset=".5" stop-color="#ee2f5f"/><stop offset="1" stop-color="#7d0a28"/></radialGradient>
      <radialGradient id="thH2" cx="35%" cy="30%" r="80%"><stop offset="0" stop-color="#ffd6e0"/><stop offset=".5" stop-color="#ff6f9c"/><stop offset="1" stop-color="#a2204e"/></radialGradient>
      <radialGradient id="thH3" cx="35%" cy="30%" r="80%"><stop offset="0" stop-color="#ffe7ef"/><stop offset=".5" stop-color="#d9406e"/><stop offset="1" stop-color="#6a0d2a"/></radialGradient>
      <linearGradient id="thGift" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#ff7aa2"/><stop offset="1" stop-color="#b3204f"/></linearGradient></defs>
    ${[[40, 44, 1, 'thH1', 0], [94, 26, 1.15, 'thH2', .5], [146, 50, .95, 'thH3', 1]].map(([x, y, sc, g, d]) => `
      <path d="M${x} ${y + 26 * sc} C${x - 4} ${y + 60} ${95 + (x - 94) * .2} ${118} 95 132" stroke="rgba(255,255,255,.55)" stroke-width="1" fill="none"/>
      <g class="th-bal" style="animation-delay:${d}s;transform-origin:95px 132px"><g transform="translate(${x - 17 * sc} ${y}) scale(${sc})">
        <path d="${HEARTP}" fill="url(#${g})"/><ellipse cx="9" cy="-7" rx="4.5" ry="2.6" fill="rgba(255,255,255,.7)" transform="rotate(-30 9 -7)"/>
        <path d="M15 24 L19 24 L17 28 Z" fill="#8a1033"/></g></g>`).join('')}
    <rect x="80" y="132" width="30" height="24" rx="2" fill="url(#thGift)"/><rect x="78" y="128" width="34" height="7" rx="1.5" fill="#ff8fb2"/>
    <path d="M95 128 v28 M78 131 h34" stroke="#ffd36e" stroke-width="3"/>
    <path d="M95 128 C86 118 78 124 86 129 Z M95 128 C104 118 112 124 104 129 Z" fill="#ffd36e"/>
  </svg>`;
  // ── the Easter bunny with a basket of painted eggs, facing left ──
  const EGGG = (x, y, r, c1, c2, rot) => `<g transform="translate(${x} ${y}) rotate(${rot})"><ellipse rx="${r * .78}" ry="${r}" fill="${c1}"/>
    <path d="M${-r * .74} ${-r * .15} L${-r * .4} ${-r * .38} L0 ${-r * .15} L${r * .4} ${-r * .38} L${r * .74} ${-r * .15}" stroke="#fff" stroke-width="1.3" fill="none"/>
    <path d="M${-r * .76} ${r * .25} Q0 ${r * .55} ${r * .76} ${r * .25}" stroke="${c2}" stroke-width="2" fill="none"/>
    <ellipse cx="${-r * .3}" cy="${-r * .45}" rx="${r * .17}" ry="${r * .3}" fill="rgba(255,255,255,.45)"/></g>`;
  const BUNNY = `<svg viewBox="0 0 160 136" overflow="visible"><defs>
      <radialGradient id="thFur" cx="40%" cy="30%" r="80%"><stop offset="0" stop-color="#ffffff"/><stop offset=".6" stop-color="#e9e4dc"/><stop offset="1" stop-color="#b9b0a4"/></radialGradient>
      <linearGradient id="thBas" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#c58a4a"/><stop offset="1" stop-color="#7a4a20"/></linearGradient></defs>
    <circle class="th-tailb" cx="122" cy="84" r="10" fill="#fff"/>
    <ellipse cx="104" cy="114" rx="22" ry="10" fill="url(#thFur)"/>
    <ellipse cx="88" cy="92" rx="34" ry="27" fill="url(#thFur)"/><ellipse cx="74" cy="100" rx="16" ry="15" fill="#fbf8f3"/>
    <g class="th-ear" style="transform-origin:58px 44px"><ellipse cx="50" cy="20" rx="7.5" ry="24" fill="url(#thFur)" transform="rotate(-14 50 20)"/><ellipse cx="50" cy="22" rx="3.8" ry="17" fill="#f6b8c6" transform="rotate(-14 50 22)"/></g>
    <g class="th-ear th-ear2" style="transform-origin:66px 44px"><ellipse cx="68" cy="18" rx="7.5" ry="24" fill="url(#thFur)" transform="rotate(10 68 18)"/><ellipse cx="68" cy="20" rx="3.8" ry="17" fill="#f6b8c6" transform="rotate(10 68 20)"/></g>
    <circle cx="56" cy="58" r="21" fill="url(#thFur)"/><circle cx="46" cy="66" r="5" fill="#ffc2cf" opacity=".7"/>
    <circle cx="48" cy="55" r="3.6" fill="#2a1d1a"/><circle cx="47" cy="53.8" r="1.2" fill="#fff"/>
    <path d="M35 62 q2.4 -2.4 4.8 0 q-2.4 3 -4.8 0 Z" fill="#ff8fa8"/>
    <path d="M37 65 q0 4 -4 4 M37 65 q0 4 4 4" stroke="#b07a7a" stroke-width="1" fill="none"/>
    <path d="M30 60 l-12 -3 M30 63 l-12 1 M30 66 l-11 4" stroke="#c9bfb3" stroke-width=".8"/>
    <path d="M14 100 Q14 128 38 128 Q62 128 62 100 Z" fill="url(#thBas)"/>
    <path d="M16 104 h44 M17 112 h42 M20 120 h36" stroke="#a46b33" stroke-width="1.6"/>
    <path d="M18 100 Q38 70 58 100" stroke="#a46b33" stroke-width="3" fill="none"/>
    ${EGGG(24, 97, 8, '#ff9eb5', '#e5484d', -15)}${EGGG(38, 94, 9, '#9fd3ff', '#2f6fd1', 5)}${EGGG(52, 97, 8, '#ffd36e', '#e08b1a', 18)}
    <ellipse cx="62" cy="104" rx="8" ry="6" fill="url(#thFur)"/><ellipse cx="20" cy="106" rx="7" ry="5.5" fill="url(#thFur)"/>
  </svg>`;
  // who visits the logo on each holiday, how they move and what they say
  const VISITORS = {
    new_year: {svg: () => SANTA, w: 270, h: 112, move: 'fly', spark: ['✨', '⭐'], says: {cs: 'Ho-ho-ho! Šťastný nový rok!', uk: 'Хо-хо-хо! З Новим роком!', en: 'Ho-ho-ho! Happy New Year!'}},
    christmas: {svg: () => SANTA, w: 270, h: 112, move: 'fly', spark: ['✨', '⭐'], says: {cs: 'Ho-ho-ho! Veselé Vánoce!', uk: 'Хо-хо-хо! Веселого Різдва!', en: 'Ho-ho-ho! Merry Christmas!'}},
    halloween: {svg: () => WITCH, w: 250, h: 122, move: 'fly', spark: ['✨', '🦇', '⭐'], says: {cs: 'Sladkosti, nebo psota? 🎃', uk: 'Солодощі чи капость? 🎃', en: 'Trick or treat? 🎃'}},
    valentine: {svg: () => BALLOONS, w: 170, h: 157, move: 'float', spark: ['💕', '✨'], says: {cs: 'S láskou! 💝', uk: 'З любов’ю! 💝', en: 'With love! 💝'}},
    easter: {svg: () => BUNNY, w: 140, h: 119, move: 'hop', spark: ['🌸', '✨'], says: {cs: 'Veselé Velikonoce! 🐣', uk: 'Світлого Великодня! 🐣', en: 'Happy Easter! 🐣'}},
  };
  // ── card extras: a cobweb and a spider on a thread (Halloween) ──
  const WEB = (() => {
    const R = [14, 28, 42, 56], ang = [0, 22.5, 45, 67.5, 90].map(a => a * Math.PI / 180), pt = (r, a) => [60 - Math.sin(a) * r, Math.cos(a) * r];
    let d = ang.map(a => { const [x, y] = pt(60, a); return `M60 0L${x.toFixed(1)} ${y.toFixed(1)}`; }).join('');
    R.forEach(r => { d += ang.map((a, i) => { const [x, y] = pt(r, a); if (!i) return `M${x.toFixed(1)} ${y.toFixed(1)}`;
      const [px, py] = pt(r * .82, (a + ang[i - 1]) / 2); return `Q${px.toFixed(1)} ${py.toFixed(1)} ${x.toFixed(1)} ${y.toFixed(1)}`; }).join(''); });
    return `<svg viewBox="0 0 60 60"><path d="${d}" stroke="rgba(235,235,245,.6)" stroke-width=".7" fill="none"/></svg>`;
  })();
  const SPIDER = `<svg viewBox="0 0 44 40" overflow="visible"><g class="th-legs" stroke="#120d16" stroke-width="2.4" fill="none" stroke-linecap="round">
    <path d="M18 18 Q8 8 2 14 M18 21 Q6 18 1 24 M19 24 Q8 28 4 36 M20 26 Q14 32 12 39"/>
    <path d="M26 18 Q36 8 42 14 M26 21 Q38 18 43 24 M25 24 Q36 28 40 36 M24 26 Q30 32 32 39"/></g>
    <ellipse cx="22" cy="26" rx="8" ry="9" fill="#141014"/><circle cx="22" cy="14" r="5.5" fill="#1d171f"/>
    <circle cx="20" cy="13" r="1.5" fill="#ff5a3a"/><circle cx="24" cy="13" r="1.5" fill="#ff5a3a"/>
    <path d="M18 24 q4 3 8 0" stroke="#8e4bd6" stroke-width="1.4" fill="none"/></svg>`;
  // what floats over the card photo for each holiday
  const AMB = {christmas: ['snow'], new_year: ['snow', 'star'], halloween: ['ember'], valentine: ['heart'], easter: ['petal']};
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
  -webkit-mask:linear-gradient(#000 0 0) content-box,linear-gradient(#000 0 0);-webkit-mask-composite:xor;mask-composite:exclude;animation:thRot 3.6s linear infinite paused}
:is(${CARDS}):hover>.th-rim{opacity:1;animation-play-state:running}
.th-glare{position:absolute;inset:0;pointer-events:none;z-index:5;opacity:0;transition:opacity .3s;background:radial-gradient(380px circle at var(--mx,50%) var(--my,0%),rgba(255,255,255,.1),transparent 45%)}
:is(${CARDS}):hover>.th-glare{opacity:1}
.th-glyph{position:absolute;top:10px;left:10px;width:20px;height:20px;color:${b[0] === '#ffffff' ? b[1] : b[0]};z-index:6;pointer-events:none;opacity:.9;
  filter:drop-shadow(0 0 5px currentColor) drop-shadow(0 2px 3px rgba(0,0,0,.6));animation:thGlyph 7s ease-in-out infinite}
.th-glyph svg{display:block;width:100%;height:100%}
:is(${CARDS}):has(>.th-cg)>.th-glyph{top:22px}
:is(${CARDS}):hover>.th-glyph{animation-duration:1.6s}
@keyframes thGlyph{0%,100%{transform:rotate(-12deg) scale(1)}50%{transform:rotate(12deg) scale(1.12)}}
@keyframes thRot{to{--tha:360deg}}
.th-halo{position:absolute;inset:0;pointer-events:none;z-index:2;box-shadow:inset 0 0 26px -6px ${b[0] === '#ffffff' ? b[1] : b[0]}88;opacity:0;animation:thHalo 5s ease-in-out infinite;animation-delay:var(--bd,0s)}
@keyframes thHalo{50%{opacity:1}}
html.th-calm .th-halo{animation:none}
:is(${CARDS}):not(.th-on) :is(.th-amb i,.th-halo,.th-cg i,.th-spi,.th-fogc,.th-glyph,.th-legs){animation-play-state:paused}
.th-amb{position:absolute;left:0;right:0;top:0;height:240px;max-height:70%;overflow:hidden;pointer-events:none;z-index:4;contain:strict}
.th-amb i{position:absolute;left:var(--x);top:0;display:block;animation:var(--an) var(--t) linear infinite;animation-delay:var(--d)}
html.th-calm .th-amb,html.th-calm .th-spi{display:none}
.th-snow{--an:thFall;width:calc(5px * var(--s));height:calc(5px * var(--s));border-radius:50%;background:radial-gradient(#fff 35%,rgba(220,235,255,.5) 55%,rgba(255,255,255,0) 72%)}
.th-amb i.th-star{--an:thTwinkle;width:calc(12px * var(--s));height:calc(12px * var(--s));top:calc(var(--s) * 90px);background:#ffe9a0;clip-path:polygon(50% 0,60% 40%,100% 50%,60% 60%,50% 100%,40% 60%,0 50%,40% 40%)}
.th-ember{--an:thRise;width:calc(4px * var(--s));height:calc(4px * var(--s));border-radius:50%;background:#ffb347;box-shadow:0 0 6px 2px #ff7a1a}
.th-heart{--an:thRise;width:calc(13px * var(--s));height:calc(12px * var(--s));background:#ff5d8f;
  -webkit-mask:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 22'%3E%3Cpath d='M12 21C-4 10 3-3 12 4c9-7 16 6 0 17z'/%3E%3C/svg%3E") center/contain no-repeat;
  mask:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 22'%3E%3Cpath d='M12 21C-4 10 3-3 12 4c9-7 16 6 0 17z'/%3E%3C/svg%3E") center/contain no-repeat}
.th-amb i.th-heart:nth-child(3n){background:#ffd1dc}.th-amb i.th-heart:nth-child(3n+1){background:#e5484d}
.th-petal{--an:thPetal;width:calc(10px * var(--s));height:calc(13px * var(--s));border-radius:80% 0 80% 0;background:linear-gradient(135deg,#fff,#ffb3c7)}
.th-amb i.th-petal:nth-child(3n){background:linear-gradient(135deg,#fff,#ffd36e)}.th-amb i.th-petal:nth-child(3n+1){background:linear-gradient(135deg,#fff,#c7f0c0)}
@keyframes thFall{0%{transform:translate(0,-12px);opacity:0}8%,75%{opacity:1}100%{transform:translate(var(--dx),250px);opacity:0}}
@keyframes thRise{0%{transform:translate(0,250px);opacity:0}15%{opacity:1}85%{opacity:.9}100%{transform:translate(var(--dx),-10px);opacity:0}}
@keyframes thPetal{0%{transform:translate(0,-14px) rotate(0) rotateX(0);opacity:0}8%,75%{opacity:.9}100%{transform:translate(var(--dx),250px) rotate(320deg) rotateX(540deg);opacity:0}}
@keyframes thTwinkle{0%,100%{transform:scale(0) rotate(0);opacity:0}45%{transform:scale(1) rotate(45deg);opacity:1}60%{transform:scale(.4) rotate(70deg);opacity:.4}}
.th-cg{position:absolute;left:8px;right:8px;top:0;height:16px;z-index:7;pointer-events:none;display:flex;justify-content:space-around}
.th-cg svg{position:absolute;left:0;top:0;width:100%;height:14px}
.th-cg i{position:relative;width:6px;height:9px;margin-top:4px;border-radius:45% 45% 50% 50%;background:radial-gradient(circle at 35% 30%,#fff 0 14%,currentColor 45%);box-shadow:0 0 7px 1px currentColor;animation:thBulb 2.4s ease-in-out infinite}
.th-cg i:nth-child(even){margin-top:7px}
.th-cg i:nth-child(4n+2){color:${b[0]}}.th-cg i:nth-child(4n+3){color:${b[1]};animation-delay:.6s}.th-cg i:nth-child(4n+4){color:${b[2]};animation-delay:1.2s}.th-cg i:nth-child(4n+5){color:${b[3]};animation-delay:1.8s}
.th-web{position:absolute;top:0;right:0;width:64px;height:64px;z-index:3;pointer-events:none;opacity:.55;transition:opacity .3s}
.th-web svg,.th-spi svg{display:block;width:100%;height:100%}
:is(${CARDS}):hover .th-web{opacity:.9}
.th-spi{position:absolute;top:0;right:26px;width:20px;height:18px;z-index:7;pointer-events:none;animation:thSpi 7s ease-in-out infinite;animation-delay:var(--bd,0s);filter:drop-shadow(0 2px 2px rgba(0,0,0,.5))}
.th-spi::before{content:'';position:absolute;left:50%;bottom:60%;width:1px;height:200px;background:linear-gradient(transparent,rgba(235,235,245,.5))}
:is(${CARDS}):hover .th-spi{animation-duration:2.4s}
.th-legs{animation:thLegs .5s ease-in-out infinite alternate;transform-origin:22px 22px}
@keyframes thSpi{0%,100%{transform:translateY(-22px)}35%,55%{transform:translateY(48px)}45%{transform:translateY(40px)}}
@keyframes thLegs{from{transform:scaleX(1)}to{transform:scaleX(.88) translateY(1px)}}
.th-fogc{position:absolute;left:-30%;right:-30%;top:150px;height:90px;z-index:3;pointer-events:none;opacity:.55;
  background:radial-gradient(40% 50% at 30% 60%,rgba(142,75,214,.55),transparent 70%),radial-gradient(35% 45% at 70% 50%,rgba(90,42,130,.6),transparent 70%);animation:thFog 9s ease-in-out infinite alternate}
.pop-card .th-fogc{top:70px}
@keyframes thFog{from{transform:translateX(-12%)}to{transform:translateX(12%)}}
html.th-calm .th-fogc,html.th-calm .th-cg i{animation:none}
.th-glowbg{position:fixed;inset:0;pointer-events:none;z-index:1390;background:radial-gradient(60% 45% at 8% 0%,${th.glow[0]},transparent 70%),radial-gradient(55% 40% at 95% 5%,${th.glow[1]},transparent 70%)}
.th-garland{position:absolute;left:0;right:0;bottom:-13px;height:18px;pointer-events:none;display:flex;justify-content:space-around;overflow:hidden;z-index:1}
.th-garland svg{position:absolute;left:0;top:0;width:100%;height:8px}
.th-garland i{position:relative;width:7px;height:11px;border-radius:45% 45% 50% 50%;margin-top:4px;animation:thBulb 2.6s infinite ease-in-out;background:radial-gradient(circle at 35% 30%,#fff 0 14%,currentColor 45%);box-shadow:0 0 9px 2px currentColor}
.th-garland i::before{content:'';position:absolute;top:-3px;left:1.5px;width:4px;height:3px;background:#3a3a3a;border-radius:1px}
.th-garland i:nth-child(odd){margin-top:6px}
.th-garland i:not(:nth-child(3n)){animation:none;opacity:.85}
.th-garland i:nth-child(4n+1){color:${b[0]}}
.th-garland i:nth-child(4n+2){color:${b[1]};animation-delay:.65s}
.th-garland i:nth-child(4n+3){color:${b[2]};animation-delay:1.3s}
.th-garland i:nth-child(4n+4){color:${b[3]};animation-delay:1.95s}
@keyframes thBulb{0%,100%{opacity:.45}50%{opacity:1}}
html[data-theme] .m-tab{transition:.3s}
html[data-theme] .m-tab:hover{border-color:${b[0]}88;box-shadow:0 0 14px -4px ${b[0]}88}
html[data-theme] .m-tab.on{box-shadow:0 0 18px -2px ${b[0]}88,inset 0 0 14px -4px ${b[0]}66;border-color:${b[0]};color:#fff}
.nav-logo{position:relative}
.th-logo{position:absolute;left:-12px;top:-10px;width:16px;height:16px;color:${b[0] === '#ffffff' ? b[1] : b[0]};pointer-events:none;filter:drop-shadow(0 0 5px currentColor);animation:thGlyph 5s ease-in-out infinite}
.th-logo svg{display:block;width:100%;height:100%}
body:has(.th-vis.below) .th-logo{opacity:0;transition:opacity .4s}
#thFx{position:fixed;inset:0;width:100%;height:100%;pointer-events:none;z-index:1500}
.th-ribbon{display:inline-flex;align-items:center;gap:10px;margin:0 auto 22px;padding:9px 20px;border:1px solid ${b[0]}aa;border-radius:999px;
  background:rgba(10,10,10,.55);color:#f3ead9;text-decoration:none;
  font:600 .74rem 'Raleway',sans-serif;letter-spacing:2px;text-transform:uppercase;position:relative;overflow:hidden;animation:thIn .8s ease-out;box-shadow:0 0 22px -6px ${b[0]}88}
.th-ribbon i{display:inline-block;width:15px;height:15px;color:${b[0] === '#ffffff' ? b[1] : b[0]};filter:drop-shadow(0 0 4px currentColor)}
.th-ribbon i svg{display:block;width:100%;height:100%}
.th-ribbon::after{content:'';position:absolute;inset:0;background:linear-gradient(100deg,transparent 30%,rgba(255,255,255,.18) 50%,transparent 70%);transform:translateX(-100%);animation:thShine 3.5s ease-in-out infinite}
.th-ribbon:hover{border-color:#fff}
.th-ribbon-wrap{text-align:center;position:relative;z-index:1}
@keyframes thShine{60%,100%{transform:translateX(100%)}}
.th-card{position:fixed;left:18px;bottom:18px;z-index:1600;display:flex;gap:14px;align-items:center;max-width:410px;border-radius:16px;
  background:linear-gradient(135deg,rgba(30,26,22,.96),rgba(12,12,14,.97));
  border:1px solid rgba(255,255,255,.1);padding:16px 40px 16px 14px;box-shadow:0 22px 60px rgba(0,0,0,.6),0 0 40px -12px ${b[0]}88,inset 0 1px 0 rgba(255,255,255,.08);
  font-family:'Raleway',sans-serif;animation:thIn .8s cubic-bezier(.2,1.2,.4,1)}
.th-card::before{content:'';position:absolute;inset:0;border-radius:inherit;padding:1px;pointer-events:none;background:conic-gradient(from var(--tha),${b[0]},transparent 30%,${b[2]} 50%,transparent 75%,${b[0]});
  -webkit-mask:linear-gradient(#000 0 0) content-box,linear-gradient(#000 0 0);-webkit-mask-composite:xor;mask-composite:exclude}
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
  background:rgba(15,15,15,.85);color:${b[0] === '#ffffff' ? b[1] : b[0]};cursor:pointer;transition:.25s;box-shadow:0 0 18px -6px currentColor}
.th-fxbtn span{width:18px;height:18px;filter:drop-shadow(0 0 4px currentColor)}
.th-fxbtn svg{display:block;width:100%;height:100%}
.th-fxbtn:hover{transform:scale(1.08) rotate(12deg)}
.th-fxbtn.off{filter:grayscale(1);opacity:.45;box-shadow:none}
@keyframes thIn{from{opacity:0;transform:translateY(24px) scale(.96)}to{opacity:1;transform:none}}
@media(max-width:600px){.th-card{left:10px;right:62px;bottom:10px;max-width:none;padding:12px 32px 12px 10px;gap:10px}.th-card canvas{width:48px;height:48px}.th-card b.th-h{font-size:1rem}.th-cd .th-seg span{min-width:38px}.th-glyph{width:17px;height:17px}}
.th-vis{position:fixed;left:0;top:0;z-index:1480;pointer-events:none;will-change:transform}
.th-vis svg{display:block}
.th-rd{animation:thBob .38s ease-in-out infinite alternate}
.th-lf,.th-lb{transform-box:fill-box;transform-origin:50% 0}
.th-lf{animation:thLeg .38s ease-in-out infinite alternate}
.th-lb{animation:thLeg .38s ease-in-out infinite alternate-reverse}
.th-sleigh{animation:thBob 1.1s ease-in-out infinite alternate}
.th-arm{transform-box:fill-box;transform-origin:100% 100%;animation:thWave .45s ease-in-out infinite alternate}
.th-vis.flying .th-arm{animation-duration:1.4s}
.th-vis.stand .th-lf{animation:thStomp .42s ease-in-out infinite alternate}
.th-vis.stand .th-lb{animation:thStomp .42s ease-in-out infinite alternate-reverse}
.th-vis.stand .th-rd{animation:thBob .84s ease-in-out infinite alternate}
.th-vis.stand .th-sleigh{animation:none}
.th-nose{animation:thGlow2 1s infinite}
.th-cape{transform-box:fill-box;transform-origin:0 50%;animation:thCape .5s ease-in-out infinite alternate}
.th-bristle{transform-box:fill-box;transform-origin:0 50%;animation:thCape .3s ease-in-out infinite alternate}
.th-tail{transform-box:fill-box;transform-origin:0 100%;animation:thWave .6s ease-in-out infinite alternate}
.th-bal{animation:thSway 2.6s ease-in-out infinite alternate}
.th-ear{animation:thEar 2.4s ease-in-out infinite}.th-ear2{animation-delay:.3s}
.th-tailb{transform-box:fill-box;transform-origin:50% 50%;animation:thPuff 1.2s ease-in-out infinite}
.th-say{position:absolute;left:55%;top:-38px;white-space:nowrap;background:#fffaf0;color:#9a1a24;font:600 .86rem 'Playfair Display',serif;
  padding:7px 13px;border-radius:14px;box-shadow:0 6px 18px rgba(0,0,0,.45);opacity:0;transform:scale(.6) translateY(8px);transform-origin:20% 100%;transition:.35s cubic-bezier(.2,1.5,.4,1)}
.th-say::after{content:'';position:absolute;left:24px;bottom:-6px;border:7px solid transparent;border-top-color:#fffaf0;border-bottom:0}
.th-vis.talk .th-say{opacity:1;transform:none}
.th-vis.below .th-say{top:auto;bottom:-34px;left:18%;transform-origin:20% 0}
.th-vis.below .th-say::after{bottom:auto;top:-6px;border-top-color:transparent;border-bottom:7px solid #fffaf0;border-top-width:0}
.th-spark{position:fixed;z-index:1475;pointer-events:none;font-size:.8rem}
@keyframes thBob{from{transform:translateY(0)}to{transform:translateY(-3px)}}
@keyframes thStomp{0%,40%{transform:none}100%{transform:translateY(-3.5px) rotate(-16deg)}}
@keyframes thLeg{from{transform:rotate(28deg)}to{transform:rotate(-24deg)}}
@keyframes thWave{from{transform:rotate(-22deg)}to{transform:rotate(16deg)}}
@keyframes thGlow2{0%,100%{opacity:.5}50%{opacity:1}}
@keyframes thCape{from{transform:skewY(-4deg) scaleX(1)}to{transform:skewY(5deg) scaleX(1.06)}}
@keyframes thSway{from{transform:rotate(-6deg)}to{transform:rotate(6deg)}}
@keyframes thEar{0%,70%,100%{transform:rotate(0)}80%{transform:rotate(-12deg)}90%{transform:rotate(6deg)}}
@keyframes thPuff{50%{transform:scale(1.15)}}
@media(max-width:600px){.th-vis.small .th-say{font-size:.72rem;top:-32px}}
@media print{.th-glowbg,.th-garland,.th-logo,#thFx,.th-card,.th-fxbtn,.th-ribbon-wrap,.th-scene,.th-rim,.th-glare,.th-glyph,.th-halo,.th-vis,.th-spark,.th-amb,.th-cg,.th-web,.th-spi,.th-fogc{display:none}}`;
  }

  // ── decorations on the cards: a running light rim, a glare that follows the mouse and a small holiday icon ──
  let cardN = 0;
  const seen = 'IntersectionObserver' in window ? new IntersectionObserver(es => es.forEach(e => e.target.classList.toggle('th-on', e.isIntersecting)), {rootMargin: '80px'}) : null;
  function decorate(th) {
    document.querySelectorAll(CARDS).forEach(c => {
      if (c.querySelector(':scope > .th-rim')) return;
      const add = (cls, html) => { const s = document.createElement('span'); s.className = cls; if (html) s.innerHTML = html; c.appendChild(s); };
      add('th-rim'); add('th-glare'); add('th-glyph', GLYPH[th.glyph]);
      if (!QUIET) add('th-halo');
      if (seen) seen.observe(c); else c.classList.add('th-on');
      if (QUIET) return;
      const R = prng(1 + (++cardN) * 7919), kinds = AMB[th.id] || [];
      add('th-amb', Array.from({length: 7}, (_, i) => {
        const k = kinds[i % kinds.length];
        return `<i class="th-${k}" style="--x:${(R() * 94 + 3).toFixed(1)}%;--s:${(R() * .8 + .6).toFixed(2)};--t:${(R() * 4 + 5).toFixed(1)}s;--d:-${(R() * 9).toFixed(1)}s;--dx:${((R() - .5) * 40).toFixed(0)}px"></i>`;
      }).join(''));
      if (th.id === 'christmas' || th.id === 'new_year') add('th-cg', '<svg viewBox="0 0 280 14" preserveAspectRatio="none"><path d="M0 2 Q20 12 40 3 T80 3 T120 3 T160 3 T200 3 T240 3 T280 3" stroke="rgba(255,255,255,.35)" stroke-width="1" fill="none"/></svg>' + '<i></i>'.repeat(7));
      if (th.id === 'halloween') { add('th-web', WEB); add('th-spi', SPIDER); add('th-fogc'); }
      c.style.setProperty('--bd', -(R() * 4).toFixed(1) + 's');
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

  function visitor(id) {
    const V = VISITORS[id];
    if (V) {
      // a drawn visitor comes to the logo and says hello. On wide screens it parks in the nav left of the logo
      // and stays there; on narrow ones it waits below the nav and leaves once the page is scrolled
      const fly = instant => {
        const logo = document.querySelector('.nav-logo'), nav = document.getElementById('nav');
        if (!logo || !nav || document.hidden || document.querySelector('.th-vis')) return;
        const lr0 = logo.getBoundingClientRect().left, park = (lr0 - 24) / V.w >= .5;
        if (!park && scrollY > 60) return;
        const sc = park ? Math.min(1, (lr0 - 24) / V.w, 78 / V.h) : innerWidth < 600 ? .62 : 1, w = V.w * sc, h = V.h * sc;
        const el = document.createElement('div'); el.className = 'th-vis flying' + (sc < 1 ? ' small' : '') + (park ? ' below' : '');
        el.innerHTML = V.svg() + `<div class="th-say">${V.says[L()] || V.says.cs}</div>`;
        const svg = el.querySelector('svg'); svg.setAttribute('width', w); svg.setAttribute('height', h);
        document.body.appendChild(el);
        const W = innerWidth, lr = logo.getBoundingClientRect(), nb = nav.getBoundingClientRect().bottom;
        const spot = r => park ? [r.left - w - 12, Math.max(3, r.top + r.height / 2 - h * .55)] : [Math.max(8, Math.min(r.left - 6, W - w - 8)),
          V.move === 'float' ? Math.max(nb - h * .55, 46) : Math.max(nb + 6, r.bottom - h * .25)];
        let [tx, ty] = spot(lr);
        const IN = V.move === 'hop' ? 5200 : 4200, STAY = 4300, OUT = 2600, t0 = performance.now() - (instant ? IN : 0);
        let lastSpark = 0, tl = 0;
        const ease = k => 1 - Math.pow(1 - k, 3);
        const step = t => {
          if (!el.isConnected) return;
          const e = t - t0;
          let x, y, rot = 0, sx = 1, sy = 1, moving = true;
          // stays by the logo while the page is at the top; leaves once the visitor scrolls down
          if (!park && !tl && e >= IN + STAY && (scrollY > 60 || document.hidden)) tl = t;
          if (e < IN) {
            const k = e / IN, q = ease(k);
            if (V.move === 'float') { x = W - w * .3 + (tx - W + w * .3) * q; y = innerHeight * .6 + (ty - innerHeight * .6) * q + Math.sin(k * 6) * 10 * (1 - q); }
            else if (V.move === 'hop') { x = W + 10 + (tx - W - 10) * k; const ph = (k * 7) % 1; y = ty - Math.sin(ph * Math.PI) * 34 * (1 - k * .4); sy = ph < .08 || ph > .92 ? .9 : 1.04; sx = 2 - sy; }
            else { x = W + 20 + (tx - W - 20) * q; y = ty - 60 * (1 - q) + Math.sin(k * 8) * 14 * (1 - q); rot = -6 * (1 - q); }
          } else if (!tl) {
            const s = e - IN;  // the greeting bubble: first 4.5 s, then again for 4 s every 15 s
            if (park) {  // follow the logo as the nav shrinks; re-park if the window was resized
              const r = logo.getBoundingClientRect();
              if (Math.abs(r.left - lr0) > 30) { el.remove(); setTimeout(() => fly(true), 300); return; }
              [tx, ty] = spot(r);
            }
            moving = false; x = tx; y = ty + Math.sin(e / 320) * (V.move === 'float' ? 3 : 1);
            el.classList.remove('flying'); el.classList.add('stand');
            el.classList.toggle('talk', s < 4500 || s % 15000 > 11000);
          } else if (t - tl < OUT) {
            const k = (t - tl) / OUT; el.classList.remove('talk', 'stand'); el.classList.add('flying');
            if (V.move === 'float') { x = tx + Math.sin(k * 5) * 12; y = ty - k * k * (ty + h + 60); }
            else if (V.move === 'hop') { x = tx - k * (tx + w + 30); const ph = (k * 5) % 1; y = ty - Math.sin(ph * Math.PI) * 30; }
            else { x = tx - k * k * (tx + w + 40); y = ty - k * k * (ty + h + 40); rot = 10 * k; }
          } else { el.remove(); return; }
          el.style.transform = `translate(${x}px,${y}px) rotate(${rot}deg) scale(${sx},${sy})`;
          if (moving && t - lastSpark > 90) {  // sparkles behind
            lastSpark = t;
            const sp = document.createElement('span'); sp.className = 'th-spark'; sp.textContent = V.spark[Math.floor(Math.random() * V.spark.length)];
            sp.style.left = (x + w * (V.move === 'float' ? .5 : .92)) + 'px'; sp.style.top = (y + h * rnd(.5, .9)) + 'px'; document.body.appendChild(sp);
            sp.animate([{opacity: 1, transform: 'scale(1)'}, {opacity: 0, transform: `translate(${rnd(10, 40)}px,${rnd(10, 35)}px) scale(.3)`}],
                       {duration: 1100, easing: 'ease-out'}).onfinish = () => sp.remove();
          }
          requestAnimationFrame(step);
        };
        requestAnimationFrame(step);
      };
      setInterval(fly, 5000); setTimeout(() => fly(!animOn()), animOn() ? 2200 : 300);  // comes back soon after the page is scrolled to the top
    }
  }

  function apply(id, cfg, preview) {
    const th = THEMES[id];
    if (!th) return;
    th.id = id;
    effects = cfg.effects !== false;
    document.documentElement.classList.toggle('th-calm', !animOn());
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
      visitor(id);
      if (effects) {
        const b = document.createElement('button'); b.type = 'button'; b.className = 'th-fxbtn'; b.innerHTML = `<span>${GLYPH[th.glyph]}</span>`;
        const upd = () => { const off = store('cm_fx_off') === '1'; b.classList.toggle('off', off); b.title = (UI[L()] || UI.cs).fx + (off ? ' ✕' : ' ✓'); };
        b.onclick = () => { store('cm_fx_off', store('cm_fx_off') === '1' ? '0' : '1'); upd(); document.documentElement.classList.toggle('th-calm', !animOn()); KICK.forEach(k => k()); };
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

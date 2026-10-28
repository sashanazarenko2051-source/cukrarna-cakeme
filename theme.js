/* Seasonal look of the site (New Year, Christmas, Halloween, Valentine's, Easter), switched on in the admin.
   Garland under the menu bar, a glow in the holiday colours, falling or rising particles with depth,
   holiday extras (fireworks, swinging baubles, a spider and bats, hearts, a peeking bunny), a click burst,
   a ribbon on the home page and a greeting card with a countdown.
   ?theme=<id> previews a theme without saving it (used by the admin). */
(() => {
  const THEMES = {
    new_year: {logo: '🥂', fx: 'snow', snowy: true, burst: ['✨', '🎉', '⭐'], bulbs: ['#f5d67a', '#ffffff', '#c9a96e', '#9fd3ff'], icon: '🎆',
      glow: ['rgba(245,214,122,.16)', 'rgba(159,211,255,.10)'], extra: 'fireworks', date: y => new Date(y + 1, 0, 1), hold: 7,
      greet: {cs: 'Šťastný nový rok!', uk: 'З Новим роком!', en: 'Happy New Year!'},
      sub: {cs: 'Oslavte ho s dortem od nás — objednejte včas.', uk: 'Святкуйте з нашим тортом — замовляйте завчасно.', en: 'Celebrate with one of our cakes — order in good time.'},
      to: {cs: 'Do Nového roku', uk: 'До Нового року', en: 'New Year in'}, ribbon: {cs: 'Novoroční dorty', uk: 'Новорічні торти', en: 'New Year cakes'}},
    christmas: {logo: '🎄', fx: 'snow', snowy: true, burst: ['❄️', '⭐', '🎁'], bulbs: ['#e5484d', '#f5d67a', '#3fa66b', '#6fb7ff'], icon: '🎄',
      glow: ['rgba(229,72,77,.13)', 'rgba(63,166,107,.12)'], extra: 'baubles', date: y => new Date(y, 11, 24), hold: 3,
      greet: {cs: 'Veselé Vánoce!', uk: 'Веселого Різдва!', en: 'Merry Christmas!'},
      sub: {cs: 'Vánoční cukroví a dorty — objednejte si včas.', uk: 'Різдвяне печиво й торти — замовляйте завчасно.', en: 'Christmas cookies and cakes — order in good time.'},
      to: {cs: 'Do Štědrého dne', uk: 'До Святвечора', en: 'Christmas Eve in'}, ribbon: {cs: 'Vánoční cukroví a dorty', uk: 'Різдвяне печиво й торти', en: 'Christmas cookies & cakes'}},
    halloween: {logo: '🎃', fx: ['🍂', '🍁', '🍂'], burst: ['🎃', '👻', '🦇', '🍬'], bulbs: ['#ff8a1f', '#8e4bd6', '#ffb347', '#5a2a82'], icon: '🎃',
      glow: ['rgba(255,138,31,.15)', 'rgba(142,75,214,.14)'], extra: 'spooky', date: y => new Date(y, 9, 31), hold: 1,
      greet: {cs: 'Strašidelný Halloween!', uk: 'Моторошного Хелловіну!', en: 'Happy Halloween!'},
      sub: {cs: 'Sladkosti, nebo psota? U nás rozhodně sladkosti.', uk: 'Солодощі чи капость? У нас — точно солодощі.', en: 'Trick or treat? Here it’s definitely treats.'},
      to: {cs: 'Do Halloweenu', uk: 'До Хелловіну', en: 'Halloween in'}, ribbon: {cs: 'Halloweenské sladkosti', uk: 'Солодощі на Хелловін', en: 'Halloween treats'}},
    valentine: {logo: '💝', fx: ['❤️', '💕', '💗', '💖'], rise: true, burst: ['❤️', '💖', '💘'], bulbs: ['#ff5d8f', '#ffd1dc', '#e5484d', '#ff9eb5'], icon: '💝',
      glow: ['rgba(255,93,143,.16)', 'rgba(229,72,77,.10)'], extra: '', date: y => new Date(y, 1, 14), hold: 1,
      greet: {cs: 'Šťastného Valentýna!', uk: 'З Днем закоханих!', en: 'Happy Valentine’s Day!'},
      sub: {cs: 'Sladký dárek pro vaše nejbližší.', uk: 'Солодкий подарунок для найрідніших.', en: 'A sweet gift for your loved ones.'},
      to: {cs: 'Do Valentýna', uk: 'До Дня закоханих', en: 'Valentine’s Day in'}, ribbon: {cs: 'Sladké dárky z lásky', uk: 'Солодкі подарунки з любов’ю', en: 'Sweet gifts with love'}},
    easter: {logo: '🐣', fx: ['🌸', '🌼', '🌷', '🌸'], burst: ['🥚', '🐣', '🌷'], bulbs: ['#ffd36e', '#a8e6a1', '#ffb3c7', '#9fd3ff'], icon: '🐣',
      glow: ['rgba(255,211,110,.13)', 'rgba(168,230,161,.11)'], extra: 'bunny', date: y => easter(y), hold: 2,
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
  // the order page keeps only the static decorations: no snow, no flying Santa, no bursts over the form
  const QUIET = /delivery\.html$/.test(location.pathname);
  const CARDS = '.m-card,.pop-card,.rv-card,.ab-stat,.step,.di,.celeb-card';
  const UI = {cs: {menu: 'Do menu', fx: 'Efekty', close: 'Zavřít', today: 'Je to dnes! 🎉'},
              uk: {menu: 'До меню', fx: 'Ефекти', close: 'Закрити', today: 'Це сьогодні! 🎉'},
              en: {menu: 'See the menu', fx: 'Effects', close: 'Close', today: 'It’s today! 🎉'}};
  const L = () => { try { return localStorage.getItem('cakeme_lang') || 'cs'; } catch { return 'cs'; } };
  const store = (k, v) => { try { if (v === undefined) return localStorage.getItem(k); localStorage.setItem(k, v); } catch { return null; } };
  const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]));
  const calm = () => store('cm_fx_off') === '1' || matchMedia('(prefers-reduced-motion: reduce)').matches;
  const rnd = (a, b) => a + Math.random() * (b - a);

  function easter(y) {
    const a = y % 19, b = Math.floor(y / 100), c = y % 100, d = Math.floor(b / 4), e = b % 4, f = Math.floor((b + 8) / 25),
      g = Math.floor((b - f + 1) / 3), h = (19 * a + b - d - g + 15) % 30, i = Math.floor(c / 4), k = c % 4,
      l = (32 + 2 * e + 2 * i - h - k) % 7, m = Math.floor((a + 11 * h + 22 * l) / 451);
    return new Date(y, Math.floor((h + l - 7 * m + 114) / 31) - 1, ((h + l - 7 * m + 114) % 31) + 1);
  }
  // "5 dní" / "5 днів" / "5 days"
  function days(n, l) {
    if (l === 'cs') return n + ' ' + (n === 1 ? 'den' : n < 5 ? 'dny' : 'dní');
    if (l === 'uk') { const t = n % 10, h = n % 100; return n + ' ' + (t === 1 && h !== 11 ? 'день' : t >= 2 && t <= 4 && (h < 12 || h > 14) ? 'дні' : 'днів'); }
    return n + (n === 1 ? ' day' : ' days');
  }
  function countdown(th) {
    const now = new Date(), today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    // the nearest holiday that is not over yet (last year's, this year's or next year's)
    const y = now.getFullYear();
    const diff = [y - 1, y, y + 1].map(k => Math.round((th.date(k) - today) / 864e5)).find(n => n >= -th.hold);
    if (diff === undefined) return '';
    const l = L();
    return diff <= 0 ? (UI[l] || UI.cs).today : `${th.to[l] || th.to.cs}: <b>${days(diff, l)}</b>`;
  }

  // faint snowflakes on the page background
  const FLAKES_BG = (() => {
    const f = (x, y, r, o) => `<g transform="translate(${x} ${y})" opacity="${o}">` + [0, 60, 120].map(a =>
      `<path transform="rotate(${a})" d="M0 -${r}V${r}M0 -${r * .55}l${r * .25} -${r * .25}M0 -${r * .55}l-${r * .25} -${r * .25}M0 ${r * .55}l${r * .25} ${r * .25}M0 ${r * .55}l-${r * .25} ${r * .25}"/>`).join('') + '</g>';
    const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="260" height="260"><g stroke="#fff" stroke-width="1.1" fill="none" stroke-linecap="round">`
      + f(40, 50, 11, .08) + f(170, 30, 7, .06) + f(120, 140, 14, .07) + f(220, 190, 9, .06) + f(60, 210, 6, .05) + f(230, 95, 5, .05) + '</g></svg>';
    return 'url("data:image/svg+xml,' + encodeURIComponent(svg) + '")';
  })();
  // a white snow cap with soft bumps (cards, menu tabs)
  const CAP = 'linear-gradient(#fff,#f4f8ff) 0 0/100% 5px no-repeat,radial-gradient(ellipse 9px 6px at 9px 4px,#fff 98%,transparent) 0 0/26px 11px repeat-x,radial-gradient(ellipse 6px 4px at 6px 3px,#eef4ff 98%,transparent) 13px 2px/31px 9px repeat-x';
  // ── realistic pine: hundreds of short needles in several greens (seeded, so it looks the same every time) ──
  const prng = seed => () => (seed = (seed * 16807) % 2147483647) / 2147483647;
  const GREENS_D = ['#0b331c', '#104226', '#155230', '#1b6038'], GREENS_L = ['#22703f', '#2a8249', '#349456', '#43a865'];
  function needles(pts, R, len, dens, light) {
    let out = '';
    const cols = light ? GREENS_L : GREENS_D;
    for (const [x, y] of pts) for (let k = 0; k < dens; k++) {
      const a = R() * 6.283, l = len * (.55 + R() * .6);
      out += `<path d="M${x.toFixed(1)} ${y.toFixed(1)}l${(Math.cos(a) * l).toFixed(1)} ${(Math.sin(a) * l).toFixed(1)}" stroke="${cols[Math.floor(R() * cols.length)]}"/>`;
    }
    return `<g stroke-width="${light ? 1.1 : 1.5}" stroke-linecap="round" fill="none">${out}</g>`;
  }
  const quad = (p0, c, p1, n, R, spread) => Array.from({length: n}, (_, i) => {
    const t = i / (n - 1), u = 1 - t;
    return [u * u * p0[0] + 2 * u * t * c[0] + t * t * p1[0] + (R() - .5) * spread, u * u * p0[1] + 2 * u * t * c[1] + t * t * p1[1] + (R() - .5) * spread];
  });
  const GRAD = `<radialGradient id="thBr" cx="35%" cy="30%" r="75%"><stop offset="0" stop-color="#ff9a9a"/><stop offset=".45" stop-color="#d4202c"/><stop offset="1" stop-color="#5a0a10"/></radialGradient>
    <radialGradient id="thBg" cx="35%" cy="30%" r="75%"><stop offset="0" stop-color="#fff4c4"/><stop offset=".45" stop-color="#e0a83a"/><stop offset="1" stop-color="#6b4710"/></radialGradient>
    <radialGradient id="thBb" cx="35%" cy="30%" r="75%"><stop offset="0" stop-color="#cfe6ff"/><stop offset=".45" stop-color="#2f6fd1"/><stop offset="1" stop-color="#0d2554"/></radialGradient>
    <radialGradient id="thBs" cx="35%" cy="30%" r="75%"><stop offset="0" stop-color="#ffffff"/><stop offset=".45" stop-color="#b9c3cf"/><stop offset="1" stop-color="#4a5260"/></radialGradient>
    <linearGradient id="thRib" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#ef4a50"/><stop offset="1" stop-color="#9a141c"/></linearGradient>
    <filter id="thGl" x="-100%" y="-100%" width="300%" height="300%"><feGaussianBlur stdDeviation="2.2"/></filter>`;
  const BALL = (x, y, r, g) => `<line x1="${x}" y1="${y - r - 8}" x2="${x}" y2="${y - r}" stroke="#d9b56a" stroke-width=".7"/>
    <rect x="${x - r * .32}" y="${y - r - 2.6}" width="${r * .64}" height="3.4" rx=".8" fill="#e8c77f"/>
    <circle cx="${x}" cy="${y}" r="${r}" fill="url(#${g})"/>
    <ellipse cx="${x - r * .36}" cy="${y - r * .38}" rx="${r * .3}" ry="${r * .17}" fill="rgba(255,255,255,.8)" transform="rotate(-35 ${x - r * .36} ${y - r * .38})"/>`;
  const CONE = (x, y, rot) => `<g transform="translate(${x} ${y}) rotate(${rot})"><ellipse rx="3.6" ry="6.5" fill="#5c3a1c"/>
    ${[-4, -1.5, 1, 3.5].map(v => `<path d="M-3.4 ${v}q3.4 2.4 6.8 0" stroke="#8a5a2e" stroke-width="1" fill="none"/>`).join('')}</g>`;
  const BOW = (x, y, s) => `<g transform="translate(${x} ${y}) scale(${s})">
    <path d="M0 0 C-14 -12 -20 2 -12 6 C-8 8 -3 4 0 0 Z M0 0 C14 -12 20 2 12 6 C8 8 3 4 0 0 Z" fill="url(#thRib)"/>
    <path d="M-1 1 L-9 18 L-5 16 L-3 20 Z M1 1 L9 18 L5 16 L3 20 Z" fill="url(#thRib)"/><circle r="3.4" fill="#c3202a"/></g>`;
  const LIGHT = (x, y, c, d) => `<g class="th-pl" style="animation-delay:${d}s"><circle cx="${x}" cy="${y}" r="5" fill="${c}" filter="url(#thGl)" opacity=".8"/><circle cx="${x}" cy="${y}" r="1.9" fill="#fffbe8"/></g>`;
  // a pine garland swag over the About photo
  const PINE = (() => {
    const R = prng(7), A = [-6, 10], C1 = [100, 62], M = [200, 12], C2 = [300, 62], B = [406, 10];
    const core = [...quad(A, C1, M, 150, R, 9), ...quad(M, C2, B, 150, R, 9)];
    const top = [...quad(A, C1, M, 110, R, 6), ...quad(M, C2, B, 110, R, 6)];
    const at = (seg, t) => { const [p0, c, p1] = seg ? [M, C2, B] : [A, C1, M], u = 1 - t; return [u * u * p0[0] + 2 * u * t * c[0] + t * t * p1[0], u * u * p0[1] + 2 * u * t * c[1] + t * t * p1[1]]; };
    const balls = [[0, .3, 7, 'thBr'], [0, .52, 8.5, 'thBg'], [0, .74, 6.5, 'thBb'], [1, .26, 6.5, 'thBs'], [1, .48, 8.5, 'thBr'], [1, .7, 7, 'thBg']];
    const cones = [[0, .14, 20], [0, .9, -25], [1, .1, 15], [1, .86, -20]];
    const lights = [];
    for (let seg = 0; seg < 2; seg++) for (let i = 1; i < 10; i++) lights.push([seg, i / 10]);
    const cols = ['#ffd36e', '#ff7b6b', '#9fd3ff', '#ffe9a8'];
    return `<svg viewBox="0 0 400 92" width="100%" preserveAspectRatio="xMidYMin meet" overflow="visible"><defs>${GRAD}</defs>
      ${needles(core, R, 10, 3, false)}${needles(top, R, 7, 3, true)}
      ${cones.map(([sg, t, r]) => { const [x, y] = at(sg, t); return CONE(x, y + 5, r); }).join('')}
      ${lights.map(([sg, t], i) => { const [x, y] = at(sg, t); return LIGHT(x, y - 2 + (i % 2) * 5, cols[i % 4], (i % 4) * .45); }).join('')}
      ${balls.map(([sg, t, r, g]) => { const [x, y] = at(sg, t); return BALL(x, y + 13 + r, r, g); }).join('')}
      ${BOW(0, 8, .9)}${BOW(200, 12, .8)}${BOW(400, 8, .9)}
    </svg>`;
  })();
  // a pine strand tile for the card edge (repeats sideways, used as a CSS background)
  const STRAND = (() => {
    const R = prng(11), pts = Array.from({length: 26}, (_, i) => [i * 2.4, 7 + (R() - .5) * 3]);
    const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="60" height="14" viewBox="0 0 60 14">${needles(pts, R, 6, 4, false)}${needles(pts, R, 4.5, 2, true)}</svg>`;
    return 'url("data:image/svg+xml,' + encodeURIComponent(svg) + '")';
  })();
  // a pine wreath with berries, two baubles and a bow (top-left of the cards)
  const WREATH = (() => {
    const R = prng(23), ring = r => Array.from({length: 70}, (_, i) => { const a = i / 70 * 6.283; return [32 + Math.cos(a) * r + (R() - .5) * 4, 30 + Math.sin(a) * r + (R() - .5) * 4]; });
    const berries = [30, 95, 150, 215, 330].map(d => { const a = d * Math.PI / 180, x = 32 + Math.cos(a) * 17, y = 30 + Math.sin(a) * 17;
      return [0, 1, 2].map(k => `<circle cx="${(x + [-2, 2, 0][k]).toFixed(1)}" cy="${(y + [0, 0, -2.4][k]).toFixed(1)}" r="1.8" fill="url(#thBr)"/>`).join(''); }).join('');
    const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64" viewBox="0 0 64 64"><defs>${GRAD}</defs>
      ${needles(ring(17), R, 7, 4, false)}${needles(ring(17), R, 5, 3, true)}${berries}
      <circle cx="18" cy="38" r="4" fill="url(#thBg)"/><circle cx="46" cy="38" r="3.6" fill="url(#thBb)"/>${BOW(32, 47, .55)}</svg>`;
    return `<img src="data:image/svg+xml,${encodeURIComponent(svg)}" alt="" width="60" height="60">`;
  })();
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
  function snowCss(th) {
    if (!th.snowy) return '';
    const b = th.bulbs;
    return `
html[data-theme] body{background-image:${FLAKES_BG},radial-gradient(ellipse 90% 60% at 50% 20%,rgba(159,211,255,.07),transparent 65%),linear-gradient(rgba(255,255,255,.018) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,.018) 1px,transparent 1px);background-size:260px 260px,100% 100%,55px 55px,55px 55px;background-repeat:repeat,no-repeat,repeat,repeat}
.th-snow{position:absolute;left:-1px;right:-1px;top:-1px;height:13px;z-index:4;pointer-events:none;background:${CAP};
  filter:drop-shadow(0 2px 2px rgba(0,0,0,.35));transform-origin:top;animation:thSnowIn 1s ease-out both}
.th-snow::after{content:'';position:absolute;inset:0;background:radial-gradient(circle,#fff 1px,transparent 1.5px) 0 0/19px 9px;opacity:0;animation:thTwinkle 3s ease-in-out infinite}
@keyframes thSnowIn{from{transform:scaleY(0)}to{transform:none}}
@keyframes thTwinkle{50%{opacity:.9}}
html[data-theme] .m-tabs{padding-top:8px}
html[data-theme] .m-tab{position:relative}
html[data-theme] .m-tab::before{content:'';position:absolute;left:-1px;right:-1px;top:-7px;height:10px;background:${CAP};pointer-events:none;filter:drop-shadow(0 1px 1px rgba(0,0,0,.3))}
html[data-theme] .m-tab:hover::before{animation:thShake .5s}
@keyframes thShake{25%{transform:translateX(-2px)}75%{transform:translateX(2px)}}
html[data-theme] .m-body{position:relative}
.th-cgar{position:absolute;left:0;right:0;top:-7px;height:14px;display:flex;justify-content:space-around;pointer-events:none;z-index:4}
.th-cgar::before{content:'';position:absolute;left:-2px;right:-2px;top:-3px;height:14px;background:${STRAND} 0 0/60px 14px repeat-x;filter:drop-shadow(0 2px 2px rgba(0,0,0,.55))}
.th-cgar i{position:relative;z-index:1}
.th-cgar i{width:6px;height:9px;border-radius:45% 45% 50% 50%;margin-top:3px;animation:thGlow 2.2s infinite ease-in-out}
.th-cgar i:nth-child(odd){margin-top:5px}
.th-cgar i:nth-child(4n+1){background:${b[0]};color:${b[0]}}
.th-cgar i:nth-child(4n+2){background:${b[1]};color:${b[1]};animation-delay:.55s}
.th-cgar i:nth-child(4n+3){background:${b[2]};color:${b[2]};animation-delay:1.1s}
.th-cgar i:nth-child(4n+4){background:${b[3]};color:${b[3]};animation-delay:1.65s}
html[data-theme] .ab-img-wrap{position:relative}
.th-pine{position:absolute;left:-14px;right:-14px;top:-16px;z-index:5;pointer-events:none;filter:drop-shadow(0 6px 8px rgba(0,0,0,.55));animation:thSnowIn 1.2s ease-out both;transform-origin:top}
.th-pine .th-pl{animation:thPl 1.8s ease-in-out infinite}
@keyframes thPl{0%,100%{opacity:.35}50%{opacity:1}}
.th-santa{position:fixed;left:0;top:0;z-index:1480;pointer-events:none;will-change:transform;filter:drop-shadow(0 8px 12px rgba(0,0,0,.55))}
.th-santa svg{display:block;width:270px;height:112px}
.th-rd{animation:thBob .38s ease-in-out infinite alternate}
.th-santa g:nth-of-type(2) .th-rd{animation-delay:.19s}
.th-lf,.th-lb{transform-box:fill-box;transform-origin:50% 0}
.th-lf{animation:thLeg .38s ease-in-out infinite alternate}
.th-lb{animation:thLeg .38s ease-in-out infinite alternate-reverse}
.th-sleigh{animation:thBob 1.1s ease-in-out infinite alternate}
.th-arm{transform-box:fill-box;transform-origin:100% 100%;animation:thWave .45s ease-in-out infinite alternate}
.th-nose{animation:thGlow 1s infinite}
.th-santa.flying .th-arm{animation-duration:1.4s}
.th-say{position:absolute;left:150px;top:-40px;white-space:nowrap;background:#fffaf0;color:#b3202a;font:600 .85rem 'Playfair Display',serif;
  padding:7px 13px;border-radius:14px;box-shadow:0 6px 18px rgba(0,0,0,.45);opacity:0;transform:scale(.6) translateY(8px);transform-origin:20% 100%;transition:.35s cubic-bezier(.2,1.5,.4,1)}
.th-say::after{content:'';position:absolute;left:26px;bottom:-6px;border:7px solid transparent;border-top-color:#fffaf0;border-bottom:0}
.th-santa.talk .th-say{opacity:1;transform:none}
.th-spark{position:fixed;z-index:1475;pointer-events:none;font-size:.8rem}
@keyframes thBob{from{transform:translateY(0)}to{transform:translateY(-3px)}}
@keyframes thLeg{from{transform:rotate(28deg)}to{transform:rotate(-24deg)}}
@keyframes thWave{from{transform:rotate(-22deg)}to{transform:rotate(16deg)}}
@media(max-width:600px){.th-santa svg{width:170px;height:71px}.th-say{left:90px;top:-34px;font-size:.72rem}.th-pine{left:-6px;right:-6px;top:-10px}}`;
  }
  function css(th, id) {
    const b = th.bulbs, P = PAL[id];
    return snowCss(th) + `
html[data-theme]{--bg0:${P.bg[0]};--bg1:${P.bg[1]};--bg2:${P.bg[2]};--bg3:${P.bg[3]};--bdr:${P.bdr}}
html[data-theme] body{background-color:${P.bg[0]}}
html[data-theme] :is(${CARDS}):not(.ab-stat){background-image:linear-gradient(180deg,${P.tint},transparent 45%);border-color:${P.bdr};transition:box-shadow .35s,border-color .35s,transform .35s}
html[data-theme] :is(${CARDS}):hover{border-color:${b[0]};box-shadow:0 0 0 1px ${b[0]}55,0 14px 34px -8px ${b[0]}66,0 0 26px -6px ${b[2]}55}
:where(.pop-card,.rv-card,.di,.celeb-card){position:relative}
html[data-theme] .ab-stat{background:linear-gradient(135deg,${P.bg[1]},${P.bg[3]});border-color:${b[0]};box-shadow:0 10px 30px rgba(0,0,0,.55)}
.th-deco{position:absolute;z-index:3;pointer-events:none;line-height:0}
.th-deco.tr{top:0;right:0}.th-deco.tl{top:5px;left:5px;z-index:6;filter:drop-shadow(0 4px 6px rgba(0,0,0,.6));animation:thWob 5s ease-in-out infinite}.th-deco.lt{top:8px;left:8px;filter:drop-shadow(0 4px 6px rgba(0,0,0,.55));animation:thWob 4s ease-in-out infinite}
.th-deco svg{display:block}
.th-deco.tl img{display:block;width:60px;height:60px}
@media(max-width:600px){.th-deco.tl img{width:46px;height:46px}}
.th-deco.em{font-size:1.35rem;line-height:1;top:8px;right:10px;filter:drop-shadow(0 3px 5px rgba(0,0,0,.55));animation:thWob 4s ease-in-out infinite}
:is(${CARDS}):hover .th-deco.em{animation-duration:1.2s}
.th-deco.web{opacity:.75}
:is(${CARDS}):hover .th-deco.web{opacity:1}
.th-glow{position:fixed;inset:0;pointer-events:none;z-index:1390;background:radial-gradient(60% 45% at 8% 0%,${th.glow[0]},transparent 70%),radial-gradient(55% 40% at 95% 5%,${th.glow[1]},transparent 70%);mix-blend-mode:screen}
.th-garland{position:absolute;left:0;right:0;bottom:-13px;height:18px;pointer-events:none;display:flex;justify-content:space-around;overflow:hidden;z-index:1}
.th-garland svg{position:absolute;left:0;top:0;width:100%;height:8px}
.th-garland i{position:relative;width:7px;height:11px;border-radius:45% 45% 50% 50%;margin-top:4px;animation:thGlow 2.6s infinite ease-in-out}
.th-garland i::before{content:'';position:absolute;top:-3px;left:1.5px;width:4px;height:3px;background:#3a3a3a;border-radius:1px}
.th-garland i:nth-child(odd){margin-top:6px}
.th-garland i:nth-child(4n+1){background:${b[0]};color:${b[0]}}
.th-garland i:nth-child(4n+2){background:${b[1]};color:${b[1]};animation-delay:.65s}
.th-garland i:nth-child(4n+3){background:${b[2]};color:${b[2]};animation-delay:1.3s}
.th-garland i:nth-child(4n+4){background:${b[3]};color:${b[3]};animation-delay:1.95s}
@keyframes thGlow{0%,100%{opacity:.4;box-shadow:none}50%{opacity:1;box-shadow:0 0 10px 3px currentColor}}
.nav-logo{position:relative}
.th-logo{position:absolute;left:-10px;top:-12px;font-size:1.1rem;transform-origin:50% 90%;animation:thWob 3.2s ease-in-out infinite;pointer-events:none;filter:drop-shadow(0 2px 3px rgba(0,0,0,.5))}
@keyframes thWob{0%,100%{transform:rotate(-16deg)}50%{transform:rotate(6deg) scale(1.08)}}
#thFx{position:fixed;inset:0;width:100%;height:100%;pointer-events:none;z-index:1500}
.th-hang{position:fixed;top:0;z-index:1450;pointer-events:none;display:flex;flex-direction:column;align-items:center;transform-origin:50% 0;animation:thSwing 4s ease-in-out infinite}
.th-hang::before{content:'';width:1px;background:linear-gradient(rgba(255,255,255,.1),rgba(255,255,255,.55))}
.th-hang span{font-size:1.6rem;filter:drop-shadow(0 4px 8px rgba(0,0,0,.6))}
@keyframes thSwing{0%,100%{transform:rotate(5deg)}50%{transform:rotate(-5deg)}}
.th-spider{animation:thSpider 7s ease-in-out infinite}
.th-spider span{font-size:1.4rem}
@keyframes thSpider{0%,100%{transform:translateY(-30px)}40%{transform:translateY(40px)}60%{transform:translateY(25px)}}
.th-bat{position:fixed;z-index:1460;font-size:1.6rem;pointer-events:none;will-change:transform}
.th-bat span{display:inline-block;animation:thFlap .18s ease-in-out infinite alternate}
@keyframes thFlap{from{transform:scaleY(1)}to{transform:scaleY(.55)}}
.th-bunny{position:fixed;bottom:-70px;right:70px;z-index:1450;font-size:3.2rem;pointer-events:none;transition:bottom .9s cubic-bezier(.3,1.6,.5,1)}
.th-bunny.up{bottom:-8px}
.th-pop{position:fixed;z-index:1700;pointer-events:none;font-size:1.25rem;will-change:transform,opacity}
.th-ribbon{display:inline-flex;align-items:center;gap:10px;margin:0 auto 22px;padding:9px 20px;border:1px solid ${b[0]};border-radius:999px;
  background:linear-gradient(90deg,rgba(0,0,0,.35),rgba(255,255,255,.04),rgba(0,0,0,.35));color:#f3ead9;text-decoration:none;
  font:600 .74rem 'Raleway',sans-serif;letter-spacing:2px;text-transform:uppercase;position:relative;overflow:hidden;animation:thIn .8s ease-out}
.th-ribbon::after{content:'';position:absolute;inset:0;background:linear-gradient(100deg,transparent 30%,rgba(255,255,255,.18) 50%,transparent 70%);transform:translateX(-100%);animation:thShine 3.5s ease-in-out infinite}
.th-ribbon:hover{border-color:#fff}
.th-ribbon-wrap{text-align:center}
@keyframes thShine{60%,100%{transform:translateX(100%)}}
.th-card{position:fixed;left:18px;bottom:18px;z-index:1600;display:flex;gap:16px;align-items:center;max-width:400px;
  background:radial-gradient(120% 140% at 0% 0%,${th.glow[0].replace(/[\d.]+\)$/, '.35)')},transparent 60%),linear-gradient(135deg,rgba(30,26,20,.98),rgba(16,16,16,.98));
  border:1px solid transparent;border-image:linear-gradient(135deg,${b[0]},${b[1]},${b[2]},${b[3]}) 1;padding:16px 42px 16px 16px;
  box-shadow:0 18px 50px rgba(0,0,0,.65);font-family:'Raleway',sans-serif;animation:thIn .7s cubic-bezier(.2,1.3,.4,1)}
.th-card .th-ic{font-size:2.6rem;line-height:1;animation:thFloat 3s ease-in-out infinite;filter:drop-shadow(0 6px 10px rgba(0,0,0,.5))}
@keyframes thFloat{0%,100%{transform:translateY(0) rotate(-4deg)}50%{transform:translateY(-6px) rotate(4deg)}}
.th-card b.th-h{display:block;font:400 1.22rem 'Playfair Display',serif;color:#fbf4e6;margin-bottom:3px}
.th-card p{font-size:.78rem;color:#c2b69f;margin:0 0 8px;line-height:1.45}
.th-card .th-cd{font-size:.74rem;color:${b[0]};margin:0 0 9px;letter-spacing:.5px}
.th-card .th-cd b{font-size:.95rem}
.th-card a{display:inline-block;font-size:.68rem;letter-spacing:1.5px;text-transform:uppercase;color:#0b0b0b;background:linear-gradient(90deg,${b[0]},${b[2]});padding:7px 14px;text-decoration:none;font-weight:700;transition:.2s}
.th-card a:hover{filter:brightness(1.15);transform:translateY(-1px)}
.th-card .th-x{position:absolute;top:6px;right:8px;background:none;border:none;color:#8d8270;font-size:1rem;cursor:pointer;padding:4px}
.th-card .th-x:hover{color:#fff}
.th-fxbtn{position:fixed;right:14px;bottom:14px;z-index:1600;width:40px;height:40px;border-radius:50%;border:1px solid rgba(255,255,255,.18);
  background:rgba(15,15,15,.85);color:#fff;font-size:1.05rem;cursor:pointer;opacity:.8;transition:.2s}
.th-fxbtn:hover{opacity:1;transform:scale(1.08)}
.th-fxbtn.off{filter:grayscale(1);opacity:.4}
@keyframes thIn{from{opacity:0;transform:translateY(24px) scale(.96)}to{opacity:1;transform:none}}
@media(max-width:600px){.th-card{left:10px;right:60px;bottom:10px;max-width:none;padding:12px 34px 12px 12px;gap:12px}.th-card .th-ic{font-size:2rem}.th-card b.th-h{font-size:1.02rem}.th-hang{display:none}.th-bunny{right:16px;font-size:2.6rem}}
@media print{.th-glow,.th-garland,.th-logo,#thFx,.th-card,.th-fxbtn,.th-hang,.th-bat,.th-bunny,.th-ribbon-wrap{display:none}}`;
  }

  // ── canvas: snow with depth / emoji falling or rising, and New Year fireworks ──
  let fxStop = null, storm = () => {};
  function startFx(th) {
    stopFx();
    if (calm() || QUIET) return;
    const cv = document.createElement('canvas'); cv.id = 'thFx'; document.body.appendChild(cv);
    const ctx = cv.getContext('2d'), dpr = Math.min(2, devicePixelRatio || 1);
    const emoji = Array.isArray(th.fx) ? th.fx : null, rise = !!th.rise;
    let W, H, parts = [], rockets = [], sparks = [], nextBoom = 1200, last = performance.now();
    const size = () => { W = innerWidth; H = innerHeight; cv.width = W * dpr; cv.height = H * dpr; ctx.setTransform(dpr, 0, 0, dpr, 0, 0); };
    size(); addEventListener('resize', size);
    const n = Math.round(Math.min(W, 1500) / (emoji ? 55 : 14));
    // particles come in short storms (on page load and when a menu section is picked), not all the time
    const make = () => {
      const z = Math.random();  // depth: 0 far … 1 near
      return {x: rnd(-W * .35, W), y: rise ? H + rnd(10, 60) : rnd(-60, -10), z,
        r: emoji ? 11 + z * 14 : .8 + z * 3.2, vy: (emoji ? .5 + z * 1 : .8 + z * 2.2) * (rise ? -1 : 1),
        sw: rnd(0, 6.28), sws: rnd(.006, .02), rot: rnd(0, 6.28), e: emoji ? emoji[Math.floor(Math.random() * emoji.length)] : '',
        a: emoji ? .5 + z * .45 : .35 + z * .6, flake: !emoji && z > .82};
    };
    let stormUntil = 0, stormLen = 1;
    const flake = (p) => {  // a real six-arm snowflake for the nearest ones
      ctx.save(); ctx.translate(p.x, p.y); ctx.rotate(p.rot); ctx.strokeStyle = '#fff'; ctx.lineWidth = 1.1;
      const R = p.r * 2.4;
      for (let k = 0; k < 6; k++) { ctx.rotate(Math.PI / 3); ctx.beginPath(); ctx.moveTo(0, 0); ctx.lineTo(0, R); ctx.moveTo(0, R * .55); ctx.lineTo(R * .25, R * .78); ctx.moveTo(0, R * .55); ctx.lineTo(-R * .25, R * .78); ctx.stroke(); }
      ctx.restore();
    };
    const boom = () => {
      const cols = th.bulbs;
      rockets.push({x: rnd(W * .15, W * .85), y: H, ty: rnd(H * .12, H * .4), vy: -rnd(7, 10), c: cols[Math.floor(Math.random() * cols.length)]});
    };
    let raf = 0;
    const tick = t => {
      const dt = Math.min(50, t - last); last = t;
      ctx.clearRect(0, 0, W, H);
      const storming = t < stormUntil, force = storming ? (stormUntil - t) / stormLen : 0;  // 1 → 0 as the storm dies down
      const wind = emoji ? .4 + force * 1.2 : .4 + force * 2.2;
      if (storming && parts.length < n * (emoji ? .9 : 2.2)) for (let k = 0; k < (emoji ? 1 : 5); k++) parts.push(make());
      parts = parts.filter(p => {
        p.y += p.vy * (1 + force * .8); p.sw += p.sws; p.x += Math.sin(p.sw) * (emoji ? .55 : .4) + wind * (.3 + p.z); p.rot += .004;
        if ((!rise && p.y > H + 30) || (rise && p.y < -30) || p.x > W + 40) return false;
        const fade = rise ? 1 : Math.max(0, Math.min(1, (H * .5 - p.y) / (H * .22)));  // gone before the middle of the screen
        if (!fade) return false;
        ctx.globalAlpha = p.a * fade;
        if (emoji) { ctx.save(); ctx.translate(p.x, p.y); ctx.rotate(Math.sin(p.rot) * .7); ctx.font = p.r + 'px serif'; ctx.fillText(p.e, -p.r / 2, p.r / 2); ctx.restore(); }
        else if (p.flake) flake(p);
        else { ctx.beginPath(); ctx.arc(p.x, p.y, p.r, 0, 6.28); ctx.fillStyle = '#fff'; ctx.fill(); }
        return true;
      });
      if (th.extra === 'fireworks') {
        nextBoom -= dt; if (nextBoom <= 0) { boom(); nextBoom = rnd(1400, 3200); }
        ctx.globalAlpha = 1;
        rockets = rockets.filter(r => {
          r.y += r.vy; r.vy *= .985;
          ctx.fillStyle = r.c; ctx.fillRect(r.x - 1, r.y, 2, 7);
          if (r.y <= r.ty || r.vy > -1.5) {
            const k = 46 + Math.floor(Math.random() * 24);
            for (let i = 0; i < k; i++) { const ang = i / k * 6.28, sp = rnd(1.2, 4.2); sparks.push({x: r.x, y: r.y, vx: Math.cos(ang) * sp, vy: Math.sin(ang) * sp, life: 1, c: Math.random() < .3 ? '#ffffff' : r.c}); }
            return false;
          }
          return true;
        });
        sparks = sparks.filter(s => {
          s.x += s.vx; s.y += s.vy; s.vy += .045; s.vx *= .985; s.life -= .012;
          ctx.globalAlpha = Math.max(0, s.life); ctx.fillStyle = s.c; ctx.beginPath(); ctx.arc(s.x, s.y, 1.6, 0, 6.28); ctx.fill();
          return s.life > 0;
        });
      }
      // nothing left on screen and no fireworks: stop drawing until the next storm
      if (!storming && !parts.length && th.extra !== 'fireworks') { ctx.clearRect(0, 0, W, H); raf = 0; return; }
      raf = requestAnimationFrame(tick);
    };
    const run = () => { if (!raf && !document.hidden) { last = performance.now(); raf = requestAnimationFrame(tick); } };
    const vis = () => { cancelAnimationFrame(raf); raf = 0; run(); };
    document.addEventListener('visibilitychange', vis);
    storm = ms => { stormLen = ms; stormUntil = performance.now() + ms; run(); };
    storm(4500); run();
    const extras = startExtras(th);
    fxStop = () => { cancelAnimationFrame(raf); raf = 0; storm = () => {}; removeEventListener('resize', size); document.removeEventListener('visibilitychange', vis); cv.remove(); extras(); };
  }
  function stopFx() { if (fxStop) { fxStop(); fxStop = null; } }

  // ── DOM extras: hanging baubles, a spider and flying bats, a peeking bunny ──
  function startExtras(th) {
    const els = [], timers = [];
    const hang = (emoji, left, len, cls, delay) => {
      const h = document.createElement('div'); h.className = 'th-hang ' + (cls || '');
      h.style.left = left; h.style.animationDelay = delay + 's';
      h.innerHTML = `<span>${emoji}</span>`;
      document.body.appendChild(h); els.push(h);
      h.querySelector('span').before(Object.assign(document.createElement('i'), {style: `display:block;width:1px;height:${len}px;background:linear-gradient(rgba(255,255,255,.08),rgba(255,255,255,.5))`}));
      return h;
    };
    if (QUIET) return () => {};
    if (th.snowy) {
      // Santa flies in from the right, lands by the logo, says hello and flies up and away.
      // Only while the page is at the very top, so he never covers the content.
      const SAYS = {cs: 'Ho-ho-ho! Veselé svátky!', uk: 'Хо-хо-хо! Веселих свят!', en: 'Ho-ho-ho! Happy holidays!'};
      const fly = () => {
        if (document.hidden || scrollY > 60 || document.querySelector('.th-santa')) return;
        const logo = document.querySelector('.nav-logo'), nav = document.getElementById('nav');
        if (!logo || !nav) return;
        const el = document.createElement('div'); el.className = 'th-santa flying';
        el.innerHTML = SANTA + `<div class="th-say">${SAYS[L()] || SAYS.cs}</div>`;
        document.body.appendChild(el); els.push(el);
        const W = innerWidth, w = el.offsetWidth, h = el.offsetHeight;
        const lr = logo.getBoundingClientRect(), nb = nav.getBoundingClientRect().bottom;
        const tx = Math.min(lr.right + 14, W - w - 10), ty = Math.max(nb + 8, lr.bottom - h * .2);
        const IN = 4200, STAY = 4200, OUT = 2600, t0 = performance.now();
        let lastSpark = 0;
        const ease = k => 1 - Math.pow(1 - k, 3);
        const step = t => {
          if (!el.isConnected) return;
          const e = t - t0;
          let x, y, rot = 0, moving = true;
          if (e < IN) { const k = e / IN, q = ease(k); x = W + 20 + (tx - W - 20) * q; y = ty - 60 * (1 - q) + Math.sin(k * 8) * 14 * (1 - q); rot = -6 * (1 - q); }
          else if (e < IN + STAY) { moving = false; x = tx; y = ty + Math.sin(e / 320) * 3; el.classList.remove('flying'); el.classList.add('talk'); }
          else if (e < IN + STAY + OUT) { const k = (e - IN - STAY) / OUT; el.classList.remove('talk'); el.classList.add('flying'); x = tx - k * k * (tx + w + 40); y = ty - k * k * (ty + h + 40); rot = 10 * k; }
          else { el.remove(); return; }
          el.style.transform = `translate(${x}px,${y}px) rotate(${rot}deg)`;
          if (moving && t - lastSpark > 80) {  // golden sparkles behind the sleigh
            lastSpark = t;
            const sp = document.createElement('span'); sp.className = 'th-spark'; sp.textContent = Math.random() < .5 ? '✨' : '⭐';
            sp.style.left = (x + w * .92) + 'px'; sp.style.top = (y + h * rnd(.55, .85)) + 'px'; document.body.appendChild(sp);
            sp.animate([{opacity: 1, transform: 'scale(1)'}, {opacity: 0, transform: `translate(${rnd(10, 40)}px,${rnd(10, 35)}px) scale(.3)`}],
                       {duration: 1100, easing: 'ease-out'}).onfinish = () => sp.remove();
          }
          requestAnimationFrame(step);
        };
        requestAnimationFrame(step);
      };
      timers.push(setInterval(fly, 45000)); setTimeout(fly, 2200);
    }
    if (th.extra === 'spooky') {
      hang('🕷️', '90%', 110, 'th-spider', 0);
      const fly = () => {
        if (document.hidden) return;
        const b = document.createElement('div'); b.className = 'th-bat'; b.innerHTML = '<span>🦇</span>';
        document.body.appendChild(b); els.push(b);
        const W = innerWidth, y0 = rnd(90, innerHeight * .45), ltr = Math.random() < .5, dur = rnd(5000, 8000), t0 = performance.now();
        const step = t => {
          const k = (t - t0) / dur;
          if (k >= 1 || !b.isConnected) { b.remove(); return; }
          const x = ltr ? -60 + k * (W + 120) : W + 60 - k * (W + 120);
          b.style.transform = `translate(${x}px,${y0 + Math.sin(k * 14) * 30}px) scaleX(${ltr ? 1 : -1})`;
          requestAnimationFrame(step);
        };
        requestAnimationFrame(step);
      };
      timers.push(setInterval(fly, 6500)); setTimeout(fly, 1500);
    }
    if (th.extra === 'bunny') {
      const b = document.createElement('div'); b.className = 'th-bunny'; b.textContent = '🐰'; document.body.appendChild(b); els.push(b);
      const peek = () => { b.classList.add('up'); setTimeout(() => b.classList.remove('up'), 2600); };
      timers.push(setInterval(peek, 9000)); setTimeout(peek, 2500);
    }
    return () => { timers.forEach(clearInterval); els.forEach(e => e.remove()); };
  }

  // ── decorations on the cards ──
  const WEB = (() => {  // a cobweb in the top-right corner
    const R = [14, 28, 42, 56], ang = [0, 22.5, 45, 67.5, 90].map(a => a * Math.PI / 180), pt = (r, a) => [60 - Math.sin(a) * r, Math.cos(a) * r];
    let d = ang.map(a => { const [x, y] = pt(60, a); return `M60 0L${x.toFixed(1)} ${y.toFixed(1)}`; }).join('');
    R.forEach(r => { d += ang.map((a, i) => { const [x, y] = pt(r, a); if (!i) return `M${x.toFixed(1)} ${y.toFixed(1)}`;
      const [px, py] = pt(r * .82, (a + ang[i - 1]) / 2); return `Q${px.toFixed(1)} ${py.toFixed(1)} ${x.toFixed(1)} ${y.toFixed(1)}`; }).join(''); });
    return `<svg width="58" height="58" viewBox="0 0 60 60"><path d="${d}" stroke="rgba(235,235,245,.55)" stroke-width=".7" fill="none"/><circle cx="34" cy="30" r="2.6" fill="#111"/><path d="M34 30 L60 0" stroke="rgba(235,235,245,.35)" stroke-width=".5"/></svg>`;
  })();
  const EGG = (c1, c2) => `<svg width="30" height="38" viewBox="0 0 30 38"><ellipse cx="15" cy="21" rx="12" ry="15.5" fill="${c1}"/>
    <path d="M3.6 17 L8 13.5 L12 17 L16 13.5 L20 17 L24 13.5 L26.6 16" stroke="#fff" stroke-width="1.6" fill="none"/>
    <path d="M3.2 25 Q15 30 26.8 25" stroke="${c2}" stroke-width="2.4" fill="none"/>
    <circle cx="9" cy="31" r="1.2" fill="#fff"/><circle cx="15" cy="33" r="1.2" fill="#fff"/><circle cx="21" cy="31" r="1.2" fill="#fff"/>
    <ellipse cx="10" cy="11" rx="2.5" ry="4" fill="rgba(255,255,255,.35)"/></svg>`;
  const PASKA = `<svg width="40" height="44" viewBox="0 0 40 44"><rect x="8" y="19" width="24" height="22" rx="2" fill="#c58646"/>
    <rect x="8" y="35" width="24" height="6" rx="1" fill="#a86d34"/>
    <path d="M6 21 Q20 1 34 21 Q31 26 28 21.5 Q25 27 21 22 Q17 27 13 22 Q10 26 6 21 Z" fill="#fffaf0"/>
    <circle cx="14" cy="13" r="1.3" fill="#e5484d"/><circle cx="20" cy="9" r="1.3" fill="#ffd36e"/><circle cx="26" cy="13" r="1.3" fill="#6fb7ff"/>
    <circle cx="17" cy="16" r="1.1" fill="#a8e6a1"/><circle cx="23" cy="16" r="1.1" fill="#ff9eb5"/>
    <path d="M18 5 h4 M20 3 v6" stroke="#c9a96e" stroke-width="1.4"/></svg>`;
  const EGGS = [['#ff9eb5', '#e5484d'], ['#9fd3ff', '#3b7dd8'], ['#ffd36e', '#e08b1a'], ['#a8e6a1', '#3fa66b'], ['#c9a0ff', '#7d4bd6']];
  function decoFor(id, i, c) {
    if (id === 'halloween') return i % 3 === 2 ? ['em', '🎃'] : ['tr web', WEB];
    if (id === 'christmas' || id === 'new_year') return ['tl', WREATH];
    if (id === 'easter') return i % 3 === 2 ? ['lt', PASKA] : ['lt', EGG(...EGGS[i % EGGS.length])];
    if (id === 'valentine') return ['em', ['💝', '💖', '💘'][i % 3]];
    return ['em', ['✨', '🎁', '🥂'][i % 3]];
  }
  function decorate(id) {
    const th = THEMES[id];
    if (th.snowy) {
      document.querySelectorAll(CARDS).forEach(c => {
        if (c.querySelector(':scope > .th-snow')) return;
        const sn = document.createElement('span'); sn.className = 'th-snow'; c.appendChild(sn);
      });
      document.querySelectorAll('.m-card .m-body').forEach(bd => {
        if (bd.querySelector(':scope > .th-cgar')) return;
        const g = document.createElement('span'); g.className = 'th-cgar'; g.innerHTML = '<i></i>'.repeat(9); bd.prepend(g);
      });
      document.querySelectorAll('.ab-img-wrap').forEach(w => {
        if (w.querySelector(':scope > .th-pine')) return;
        const g = document.createElement('div'); g.className = 'th-pine'; g.innerHTML = PINE; w.appendChild(g);
      });
    }
    document.querySelectorAll(CARDS).forEach((c, i) => {
      if (c.querySelector(':scope > .th-deco')) return;
      const [cls, html] = decoFor(id, i, c), d = document.createElement('span');
      d.className = 'th-deco ' + cls; d.innerHTML = html; c.appendChild(d);
    });
  }

  // a little burst of holiday emoji where the visitor clicks
  function burst(th, x, y) {
    if (calm() || QUIET) return;
    for (let i = 0; i < 7; i++) {
      const s = document.createElement('span'); s.className = 'th-pop'; s.textContent = th.burst[i % th.burst.length];
      s.style.left = x + 'px'; s.style.top = y + 'px'; document.body.appendChild(s);
      const ang = rnd(0, 6.28), dist = rnd(40, 90);
      s.animate([{transform: 'translate(-50%,-50%) scale(.4)', opacity: 1},
                 {transform: `translate(calc(-50% + ${Math.cos(ang) * dist}px), calc(-50% + ${Math.sin(ang) * dist - 30}px)) scale(1.1) rotate(${rnd(-60, 60)}deg)`, opacity: 0}],
                {duration: rnd(700, 1100), easing: 'cubic-bezier(.2,.8,.3,1)'}).onfinish = () => s.remove();
    }
  }

  function card(id, th, banner, preview) {
    document.querySelector('.th-card')?.remove();
    const key = 'cm_th_seen_' + id + '_' + new Date().getFullYear();
    if (!preview && store(key) === '1') return;
    const l = L(), ui = UI[l] || UI.cs, cd = countdown(th);
    const own = banner && (banner[l] || banner.cs);
    const el = document.createElement('div');
    el.className = 'th-card';
    el.innerHTML = `<div class="th-ic">${th.icon}</div><div><b class="th-h">${esc(th.greet[l] || th.greet.cs)}</b><p>${esc(own || th.sub[l] || th.sub.cs)}</p>`
      + (cd ? `<div class="th-cd">⏳ ${cd}</div>` : '')
      + (/menu\.html$/.test(location.pathname) ? '' : `<a href="menu.html">${esc(ui.menu)} →</a>`)
      + `</div><button type="button" class="th-x" aria-label="${esc(ui.close)}">✕</button>`;
    el.querySelector('.th-x').onclick = () => { store(key, '1'); el.style.transition = '.3s'; el.style.opacity = '0'; el.style.transform = 'translateY(20px)'; setTimeout(() => el.remove(), 300); };
    document.body.appendChild(el);
  }

  function ribbon(th) {
    document.querySelector('.th-ribbon-wrap')?.remove();
    const hero = document.querySelector('.logo-block');
    if (!hero) return;
    const l = L(), w = document.createElement('div'); w.className = 'th-ribbon-wrap';
    w.innerHTML = `<a class="th-ribbon" href="menu.html">${th.icon} ${esc(th.ribbon[l] || th.ribbon.cs)} <span>→</span></a>`;
    hero.parentNode.insertBefore(w, hero);
  }

  function apply(id, cfg, preview) {
    const th = THEMES[id];
    if (!th) return;
    document.documentElement.dataset.theme = id;
    const st = document.createElement('style'); st.id = 'thCss'; st.textContent = css(th, id); document.head.appendChild(st);
    const glow = document.createElement('div'); glow.className = 'th-glow'; document.body.appendChild(glow);
    const nav = document.getElementById('nav');
    if (nav) {
      const g = document.createElement('div'); g.className = 'th-garland';
      const n = Math.ceil(innerWidth / 30);
      g.innerHTML = `<svg viewBox="0 0 ${n * 30} 8" preserveAspectRatio="none"><path d="${Array.from({length: n}, (_, i) => `M${i * 30} 1 Q${i * 30 + 15} 7 ${i * 30 + 30} 1`).join(' ')}" stroke="rgba(255,255,255,.22)" fill="none"/></svg>` + '<i></i>'.repeat(n);
      nav.appendChild(g);
      const logo = nav.querySelector('.nav-logo');
      if (logo) { const s = document.createElement('span'); s.className = 'th-logo'; s.textContent = th.logo; logo.appendChild(s); }
    }
    ribbon(th);
    decorate(id);
    let pend = 0;
    new MutationObserver(() => { if (!pend) pend = requestAnimationFrame(() => { pend = 0; decorate(id); }); })
      .observe(document.body, {childList: true, subtree: true});
    if (cfg.effects !== false) {
      startFx(th);
      const b = document.createElement('button'); b.type = 'button'; b.className = 'th-fxbtn';
      b.textContent = th.fx === 'snow' ? '❄️' : th.fx[0];
      const upd = () => { const off = store('cm_fx_off') === '1'; b.classList.toggle('off', off); b.title = (UI[L()] || UI.cs).fx + (off ? ' ✕' : ' ✓'); };
      b.onclick = () => { const off = store('cm_fx_off') !== '1'; store('cm_fx_off', off ? '1' : '0'); off ? stopFx() : startFx(th); upd(); };
      upd(); document.body.appendChild(b);
      // a short storm whenever a menu section is picked
      document.addEventListener('click', e => { if (e.target.closest('.m-tab')) storm(2500); });
      document.addEventListener('pointerdown', e => {
        if (e.button !== 0 || e.target.closest('a,button,input,select,textarea,label,.th-card')) return;
        burst(th, e.clientX, e.clientY);
      });
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

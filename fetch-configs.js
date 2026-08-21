'use strict';
const { execFile, spawn } = require('child_process');
const dns = require('dns').promises;
const fs = require('fs');
const net = require('net');
const os = require('os');
const path = require('path');

const SCRIPT_DIR = __dirname;
const CI = !!process.env.CI;
const PING_LIMIT = parseInt(process.env.PING_LIMIT || '0', 10);
const PROXY_LIMIT = parseInt(process.env.PROXY_LIMIT || '1500', 10);
const TCP_TIMEOUT = parseInt(process.env.TCP_TIMEOUT || '2500', 10);
const SING_BOX_BIN = process.env.SING_BOX_BIN || path.join(SCRIPT_DIR, 'sing-box');
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'fobia-'));

const SOURCES = [
  { id: 'pawdroid',    url: 'https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub' },
  { id: 'igareck',     url: 'https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_VLESS_RUS.txt' },
  { id: 'awesome-vpn', url: 'https://raw.githubusercontent.com/awesome-vpn/awesome-vpn/master/all' },
  { id: 'epodonios',   url: 'https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/All_Configs_Sub.txt' },
  { id: 'barry-far',   url: 'https://raw.githubusercontent.com/barry-far/V2ray-Config/main/All_Configs_Sub.txt' },
  { id: 'barabama',    url: 'https://raw.githubusercontent.com/Barabama/FreeNodes/feat/ai-crawler-v2/nodes/nodev2ray.txt' },
  { id: 'snakem982',   url: 'https://raw.githubusercontent.com/snakem982/proxypool/main/source/v2ray-2.txt' },
];

const MSK_NODES = ['ru1.node.check-host.net', 'ru2.node.check-host.net'];

const GOOGLE_TESTS = {
  google:     'https://www.google.com/generate_204',
  gmail:      'https://mail.google.com/generate_204',
  youtube:    'https://www.youtube.com/generate_204',
  gemini:     'https://gemini.google.com/',
  notebooklm: 'https://notebooklm.google.com/',
  opal:       'https://opal.withgoogle.com/',
};
const MANDATORY = ['google', 'gemini', 'notebooklm', 'opal'];

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function fetchText(url, timeoutMs = 30000) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const r = await fetch(url, { signal: ctrl.signal, redirect: 'follow', headers: { 'User-Agent': 'Mozilla/5.0 fobia' } });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    return await r.text();
  } finally { clearTimeout(t); }
}

function decodeB64(s) {
  return Buffer.from(s.replace(/\s+/g, ''), 'base64').toString('utf8');
}

function extractLinks(text) {
  const out = [];
  const tok = text.split(/\s+/).filter(Boolean);
  for (let t of tok) {
    if (!/(vless|vmess|ss|trojan|tuic|hysteria2|hy2):\/\//.test(t)) continue;
    for (const p of t.split(/(?=(?:vless|vmess|ss|trojan|tuic|hysteria2|hy2):\/\/)/)) {
      if (/^(vless|vmess|ss|trojan|tuic|hysteria2|hy2):\/\/.+\S/.test(p)) out.push(p.trim());
    }
  }
  return out;
}

function splitHostPort(hp) {
  if (!hp) return [null, null];
  hp = hp.replace(/\/$/, '');
  let m = hp.match(/^\[([^\]]+)\]:(\d+)$/);
  if (m) return [m[1], Number(m[2])];
  m = hp.match(/^(.+):(\d+)$/);
  if (m) return [m[0].startsWith('[') ? m[0] : m[1], Number(m[2])];
  return [hp, null];
}

function parseQuery(qs) {
  const out = {};
  if (!qs) return out;
  for (const [k, v] of new URLSearchParams(qs)) out[k.toLowerCase()] = v;
  return out;
}

// ---------------------------------------------------------------------------
// config parsers
// ---------------------------------------------------------------------------
function parseVless(rest) {
  const nameIdx = rest.indexOf('#');
  const name = nameIdx >= 0 ? decodeURIComponent(rest.slice(nameIdx + 1)) : '';
  const body = nameIdx >= 0 ? rest.slice(0, nameIdx) : rest;
  const qIdx = body.indexOf('?');
  const q = parseQuery(qIdx >= 0 ? body.slice(qIdx + 1) : '');
  const hp = qIdx >= 0 ? body.slice(0, qIdx) : body;
  const [uuid, hostPort] = hp.split('@');
  if (!hostPort || !uuid) return null;
  const [host, port] = splitHostPort(hostPort);
  if (!host || !port) return null;
  return { protocol: 'vless', host, port, uuid, name, params: q };
}

function parseTrojan(rest) {
  const nameIdx = rest.indexOf('#');
  const name = nameIdx >= 0 ? decodeURIComponent(rest.slice(nameIdx + 1)) : '';
  const body = nameIdx >= 0 ? rest.slice(0, nameIdx) : rest;
  const qIdx = body.indexOf('?');
  const q = parseQuery(qIdx >= 0 ? body.slice(qIdx + 1) : '');
  const hp = qIdx >= 0 ? body.slice(0, qIdx) : body;
  const [password, hostPort] = hp.split('@');
  if (!hostPort || !password) return null;
  const [host, port] = splitHostPort(hostPort);
  if (!host || !port) return null;
  return { protocol: 'trojan', host, port, password, name, params: q };
}

function parseSS(rest) {
  const nameIdx = rest.indexOf('#');
  const name = nameIdx >= 0 ? decodeURIComponent(rest.slice(nameIdx + 1)) : '';
  let body = nameIdx >= 0 ? rest.slice(0, nameIdx) : rest;
  const qIdx = body.indexOf('?');
  const q = parseQuery(qIdx >= 0 ? body.slice(qIdx + 1) : '');
  if (qIdx >= 0) body = body.slice(0, qIdx);
  let b64, host, port;
  if (body.includes('@')) {
    const [b, hp] = body.split('@');
    b64 = b;
    const h = splitHostPort(hp);
    host = h[0]; port = h[1];
    // vless-style ss:// links (uuid@host:port?security=reality/tls&flow=xtls-rprx-vision...)
    // used by some pools: ss:// prefix, but actually a vless config
    const dec0 = decodeB64(b64);
    if (!dec0.includes(':') && !b64.includes(':')) {
      const c = parseVless(rest);
      if (c) { c.protocol = 'vless'; c._disguised = true; return c; }
    }
  } else {
    const dec = decodeB64(body);
    if (dec.trimStart().startsWith('{')) {
      // vmess JSON disguised as ss:// link
      const c = parseVmess(rest);
      if (c) { c.protocol = 'vmess'; c._disguised = true; return c; }
    }
    const at = dec.lastIndexOf('@');
    if (at < 0) return null;
    b64 = dec.slice(0, at);
    const h = splitHostPort(dec.slice(at + 1));
    host = h[0]; port = h[1];
  }
  if (!host || !port) return null;
  let mp = null;
  {
    const dec = decodeB64(b64);
    if (dec.includes(':')) mp = dec;
    else {
      const ci = b64.indexOf(':');
      if (ci > 0) {
        const mDec = decodeB64(b64.slice(0, ci));
        if (/^[a-z0-9-]+$/i.test(mDec)) mp = mDec + b64.slice(ci);
      }
      if (!mp && b64.includes(':')) mp = b64;
    }
  }
  const ci = mp.indexOf(':');
  if (ci < 0) return null;
  const method = mp.slice(0, ci);
  const password = mp.slice(ci + 1);
  if (!method || !password) return null;
  let plugin = null;
  if (q.plugin) {
    const parts = q.plugin.split(';').filter(Boolean);
    const p = {};
    for (const s of parts) {
      if (s === 'tls') p.tls = true;
      else if (s === 'websocket') p.mode = 'websocket';
      else if (s.startsWith('host=')) p.host = s.slice(5);
      else if (s.startsWith('path=')) p.path = s.slice(5);
      else p.type = s;
    }
    if (p.type === 'v2ray-plugin') plugin = p;
  }
  return { protocol: 'ss', host, port, method, password, name, params: { plugin } };
}

function parseTuic(rest) {
  const nameIdx = rest.indexOf('#');
  const name = nameIdx >= 0 ? decodeURIComponent(rest.slice(nameIdx + 1)) : '';
  const body = nameIdx >= 0 ? rest.slice(0, nameIdx) : rest;
  const qIdx = body.indexOf('?');
  const q = parseQuery(qIdx >= 0 ? body.slice(qIdx + 1) : '');
  const hp = qIdx >= 0 ? body.slice(0, qIdx) : body;
  const [uuidPass, hostPort] = hp.split('@');
  if (!hostPort || !uuidPass) return null;
  const ci = uuidPass.lastIndexOf(':');
  if (ci < 0) return null;
  const uuid = uuidPass.slice(0, ci);
  const password = uuidPass.slice(ci + 1);
  const [host, port] = splitHostPort(hostPort);
  if (!host || !port) return null;
  return { protocol: 'tuic', host, port, uuid, password, name, params: q };
}

function parseHy2(rest) {
  const nameIdx = rest.indexOf('#');
  const name = nameIdx >= 0 ? decodeURIComponent(rest.slice(nameIdx + 1)) : '';
  const body = nameIdx >= 0 ? rest.slice(0, nameIdx) : rest;
  const qIdx = body.indexOf('?');
  const q = parseQuery(qIdx >= 0 ? body.slice(qIdx + 1) : '');
  const hp = qIdx >= 0 ? body.slice(0, qIdx) : body;
  const ci = hp.lastIndexOf('@');
  const password = ci >= 0 ? hp.slice(0, ci) : '';
  const hostPort = ci >= 0 ? hp.slice(ci + 1) : hp;
  const [host, port] = splitHostPort(hostPort);
  if (!host || !port) return null;
  return { protocol: 'hysteria2', host, port, password, name, params: q };
}

function parseVmess(rest) {
  const nameIdx = rest.indexOf('#');
  const name = nameIdx >= 0 ? decodeURIComponent(rest.slice(nameIdx + 1)) : '';
  const body = nameIdx >= 0 ? rest.slice(0, nameIdx) : rest;
  let v;
  if (body.includes('@') && !body.startsWith('{')) {
    const qIdx = body.indexOf('?');
    const q = parseQuery(qIdx >= 0 ? body.slice(qIdx + 1) : '');
    const hp = qIdx >= 0 ? body.slice(0, qIdx) : body;
    const [uuid, hostPort] = hp.split('@');
    const [host, port] = splitHostPort(hostPort || '');
    if (!host || !port) return null;
    return { protocol: 'vmess', host, port, uuid, name, params: { ...q, security: q.scy || q.security || 'auto' } };
  }
  let j = body;
  if (!j.startsWith('{')) j = decodeB64(j);
  v = JSON.parse(j);
  const host = v.add || v.address || v.host;
  const port = Number(v.port);
  if (!host || !port || !v.id) return null;
  return {
    protocol: 'vmess',
    host,
    port,
    uuid: v.id,
    name: (name || v.ps || '').toString(),
    _json: v,
    params: {
      security: v.scy || 'auto',
      type: v.net || 'tcp',
      path: v.path || '',
      host: v.host || v.sni || '',
      sni: v.sni || '',
      tls: v.tls && v.tls !== 'none' ? v.tls : v.security === 'tls' ? 'tls' : '',
      fp: v.fp || '',
      serviceName: v.serviceName || '',
    },
  };
}

// rebuild a correct, client-parseable link (fixes pools that disguise
// vless/vmess configs behind ss:// prefixes)
function buildLink(c) {
  try {
    const q = c.params || {};
    const name = c.name ? '#' + encodeURIComponent(c.name) : '';
    if (c.protocol === 'vless' && c._disguised) {
      const p = ['type=' + encodeURIComponent(q.type || 'tcp'), 'encryption=' + encodeURIComponent(q.encryption || 'none')];
      if (q.security) p.push('security=' + encodeURIComponent(q.security));
      if (q.sni) p.push('sni=' + encodeURIComponent(q.sni));
      if (q.fp) p.push('fp=' + encodeURIComponent(q.fp));
      if (q.pbk) p.push('pbk=' + encodeURIComponent(q.pbk));
      if (q.sid) p.push('sid=' + encodeURIComponent(q.sid));
      if (q.flow) p.push('flow=' + encodeURIComponent(q.flow));
      if (q.host) p.push('host=' + encodeURIComponent(q.host));
      if (q.path) p.push('path=' + encodeURIComponent(q.path));
      if (q.alpn) p.push('alpn=' + encodeURIComponent(q.alpn));
      if (q.headerType) p.push('headerType=' + encodeURIComponent(q.headerType));
      if (q.serviceName) p.push('serviceName=' + encodeURIComponent(q.serviceName));
      return 'vless://' + c.uuid + '@' + c.host + ':' + c.port + '?' + p.join('&') + name;
    }
    if (c.protocol === 'vmess' && c._json) {
      const j = {
        v: '2', ps: c.name || c._json.ps || '', add: c.host, port: String(c.port), id: c.uuid,
        aid: String(c._json.aid != null ? c._json.aid : 0), scy: c._json.scy || 'auto',
        net: c._json.net || 'tcp', type: c._json.type || '', host: c._json.host || '',
        path: c._json.path || '', tls: c._json.tls || '', sni: c._json.sni || '', fp: c._json.fp || '',
      };
      return 'vmess://' + Buffer.from(JSON.stringify(j)).toString('base64');
    }
    return null;
  } catch (e) { return null; }
}

function parseLink(link) {
  try {
    const m = link.match(/^(vless|vmess|ss|trojan|tuic|hysteria2|hy2):\/\/(.+)$/);
    if (!m) return null;
    const proto = m[1];
    let c;
    if (proto === 'hysteria2' || proto === 'hy2') c = parseHy2(m[2]);
    else if (proto === 'vless') c = parseVless(m[2]);
    else if (proto === 'trojan') c = parseTrojan(m[2]);
    else if (proto === 'ss') c = parseSS(m[2]);
    else if (proto === 'tuic') c = parseTuic(m[2]);
    else if (proto === 'vmess') c = parseVmess(m[2]);
    if (c) c.raw = link;
    return c;
  } catch (e) { return null; }
}

// ---------------------------------------------------------------------------
// country detection
// ---------------------------------------------------------------------------
const CITY_MAP = {
  frankfurt: 'de', fra: 'de', berlin: 'de', dusseldorf: 'de', munich: 'de', hamburg: 'de',
  amsterdam: 'nl', ams: 'nl', rotterdam: 'nl',
  paris: 'fr', cdg: 'fr', marseille: 'fr', strasbourg: 'fr',
  london: 'gb', lon: 'gb', lhr: 'gb', manchester: 'gb', uk: 'gb',
  tokyo: 'jp', nrt: 'jp', osaka: 'jp',
  singapore: 'sg', sin: 'sg',
  sydney: 'au', melbourne: 'au', perth: 'au',
  toronto: 'ca', vancouver: 'ca', montreal: 'ca',
  moscow: 'ru', msk: 'ru', 'saintpetersburg': 'ru',
  warsaw: 'waw' ? 'pl' : 'pl', waw: 'pl',
  zurich: 'ch', zrh: 'ch', geneva: 'ch',
  stockholm: 'se', helsinki: 'fi', oslo: 'no', copenhagen: 'dk',
  madrid: 'es', barcelona: 'es', valencia: 'es',
  milan: 'it', roma: 'it', rome: 'it', italy: 'it',
  vienna: 'at', prague: 'cz', bratislava: 'sk', budapest: 'hu',
  istanbul: 'tr', ankara: 'tr', tbilisi: 'ge', baku: 'az', yerevan: 'am',
  dubai: 'ae', abu: 'ae',
  hongkong: 'hk', hkg: 'hk', taiwan: 'tw', taipei: 'tw',
  seoul: 'kr', soul: 'kr', busan: 'kr',
  bangkok: 'th', jakarta: 'id', manila: 'ph', hanoi: 'vn', 'ho chi minh': 'vn', hcm: 'vn',
  mumbai: 'in', delhi: 'in', newdelhi: 'in', bangalore: 'in', chennai: 'in',
  newyork: 'us', nyc: 'us', losangeles: 'us', lax: 'us', sanfrancisco: 'us', sfo: 'us',
  sanjose: 'us', sjc: 'us', seattle: 'us', chicago: 'us', dallas: 'us', dfw: 'us',
  miami: 'us', atlanta: 'us', denver: 'us', phoenix: 'us', houston: 'us', portland: 'us',
  washington: 'us', boston: 'us', 'san diego': 'us',
  saopaulo: 'br', 'sao paulo': 'br', rio: 'br',
  buenosaires: 'ar', mexico: 'mx', mexicocity: 'mx', bogota: 'co', lima: 'pe', santiago: 'cl',
  johannesburg: 'za', lagos: 'ng', nairobi: 'ke',
  telaviv: 'il', 'tel aviv': 'il',
  japan: 'jp', germany: 'de', netherlands: 'nl', holland: 'nl', usa: 'us', america: 'us',
  russia: 'ru', poland: 'pl', turkey: 'tr', ukraine: 'ua', brazil: 'br', canada: 'ca',
  australia: 'au', india: 'in', china: 'cn', korea: 'kr', britain: 'gb', england: 'gb',
  france: 'fr', spain: 'es', italy: 'it', switzerland: 'ch', austria: 'at', sweden: 'se',
  finland: 'fi', norway: 'no', denmark: 'dk', vietnam: 'vn', malaysia: 'my', indonesia: 'id',
  philippines: 'ph', thailand: 'th', argentina: 'ar', mexico: 'mx', chile: 'cl',
  beijing: 'cn', shanghai: 'cn', guangzhou: 'cn', shenzhen: 'cn', chengdu: 'cn', hangzhou: 'cn',
  kualalumpur: 'my', kuala: 'my',
  tehran: 'ir', riga: 'lv', vilnius: 'lt', tallinn: 'ee', kyiv: 'ua', kiev: 'ua', minsk: 'by',
  almaty: 'kz', chisinau: 'md', sofia: 'bg', bucharest: 'ro', belgrade: 'rs', zagreb: 'hr',
  ljubljana: 'si', athens: 'gr', lisbon: 'pt', brussels: 'be', dublin: 'ie', edinburgh: 'gb',
  glasgow: 'gb', reykjavik: 'is', valletta: 'mt', nikosia: 'cy', ramallah: 'ps',
};

const TLD_MAP = {
  ru: 'ru', de: 'de', fr: 'fr', nl: 'nl', jp: 'jp', sg: 'sg', hk: 'hk', tw: 'tw', kr: 'kr',
  uk: 'gb', pl: 'pl', cz: 'cz', ua: 'ua', by: 'by', kz: 'kz', se: 'se', no: 'no', fi: 'fi',
  dk: 'dk', tr: 'tr', ae: 'ae', il: 'il', ir: 'ir', vn: 'vn', th: 'th', id: 'id', my: 'my',
  ph: 'ph', in: 'in', br: 'br', ar: 'ar', mx: 'mx', za: 'za', ch: 'ch', at: 'at', it: 'it',
  es: 'es', pt: 'pt', gr: 'gr', hu: 'hu', ro: 'ro', bg: 'bg', rs: 'rs', hr: 'hr', si: 'si',
  lt: 'lt', lv: 'lv', ee: 'ee', ge: 'ge', am: 'am', az: 'az', md: 'md', cn: 'cn', au: 'au',
  ca: 'ca', nz: 'nz', is: 'is', mt: 'mt', cy: 'cy', sk: 'sk', lu: 'lu', ie: 'ie', be: 'be',
  us: 'us', gb: 'gb',
};

function hostnameCountryHint(host) {
  const h = String(host).toLowerCase();
  for (const [city, cc] of Object.entries(CITY_MAP)) {
    if (h.includes(city)) return cc;
  }
  const m = h.match(/\.([a-z]{2})$/);
  if (m && TLD_MAP[m[1]] && m[1] !== 'us') return TLD_MAP[m[1]];
  const cc = h.match(/(?:^|[\-._])(de|nl|pl|fr|jp|uk|us|ru|sg|hk|tw|kr|se|fi|no|dk|ca|au|it|es|pt|cz|tr|br|za|il|th|vn|id|my|ph|in|gb)(?:\d+)?(?:[\-._]|$)/);
  if (cc && TLD_MAP[cc[1]]) return TLD_MAP[cc[1]];
  return null;
}

// ---------------------------------------------------------------------------
// DNS + TCP + geo
// ---------------------------------------------------------------------------
const ipCache = new Map();
function resolveIpOne(host) {
  if (net.isIP(host)) return Promise.resolve(host);
  return Promise.race([
    dns.lookup(host, { family: 4 }).then((a) => a || null).catch(() => null),
    sleep(3000).then(() => null),
  ]);
}
async function resolveIps(hosts, concurrency = 40) {
  let idx = 0;
  const worker = async () => {
    while (idx < hosts.length) {
      const h = hosts[idx++];
      ipCache.set(h, await resolveIpOne(h));
    }
  };
  await Promise.all(Array.from({ length: concurrency }, worker));
}

function tcpCheck(host, port, timeoutMs = TCP_TIMEOUT) {
  return new Promise((res) => {
    const s = net.connect({ host, port });
    s.setTimeout(timeoutMs);
    s.once('connect', () => { s.destroy(); res(true); });
    s.once('timeout', () => { s.destroy(); res(false); });
    s.once('error', () => res(false));
  });
}

const geoCache = new Map();
async function geoIpBatch(ips) {
  const unique = [...new Set(ips.filter(Boolean))];
  for (let i = 0; i < unique.length; i += 100) {
    const chunk = unique.slice(i, i + 100);
    for (let attempt = 0; attempt < 3; attempt++) {
      try {
        const r = await fetch('http://ip-api.com/batch', {
          method: 'POST',
          body: JSON.stringify(chunk.map((q) => ({ query: q, fields: 'query,status,countryCode' }))),
          headers: { 'Content-Type': 'application/json' },
        });
        const arr = await r.json();
        for (const row of arr) {
          if (row && row.status === 'success' && row.countryCode) geoCache.set(row.query, row.countryCode);
        }
        break;
      } catch (e) {
        if (attempt === 2) break;
        await sleep(1500 * (attempt + 1));
      }
    }
    await sleep(1100);
  }
}

// ---------------------------------------------------------------------------
// check-host.net Moscow ping
// ---------------------------------------------------------------------------
async function mskPing(hostPort) {
  let body;
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      const r = await fetch(`https://check-host.net/check-tcp?host=${encodeURIComponent(hostPort)}&${MSK_NODES.map((n) => `node=${n}`).join('&')}`, {
        headers: { Accept: 'application/json' },
      });
      if (!r.ok) throw new Error('HTTP ' + r.status);
      body = await r.json();
      if (process.env.DEBUG) console.log(`[dbg] POST ${hostPort} -> ${JSON.stringify(body).slice(0, 200)}`);
      break;
    } catch (e) {
      if (process.env.DEBUG) console.log(`[dbg] POST ${hostPort} attempt ${attempt} FAIL: ${e.message}`);
      if (attempt === 2) return { err: true };
      await sleep(1500 * (attempt + 1));
    }
  }
  if (!body) return { err: true };
  const reqId = body.request_id;
  if (!reqId) return { err: true };
  for (let i = 0; i < 12; i++) {
    await sleep(1500);
    try {
      const rr = await fetch(`https://check-host.net/check-result/${reqId}`, { headers: { Accept: 'application/json' } });
      const res = await rr.json();
      let best = null;
      let gotAny = false;
      for (const node of Object.values(res || {})) {
        const arr = Array.isArray(node) ? node : [node];
        for (const x of arr) {
          if (!x) continue;
          if (x.error) { gotAny = true; continue; }
          const t = (typeof x.time_to_connect === 'number') ? x.time_to_connect : (typeof x.time === 'number' ? x.time : null);
          if (t !== null) { gotAny = true; best = best === null ? t : Math.min(best, t); }
        }
      }
      if (gotAny) return { rtt: best === null ? null : Math.round(best * 1000) };
    } catch (e) { /* keep polling */ }
  }
  return { err: true };
}

async function mskPingAll(items, label) {
  const concurrency = 4;
  const out = new Map();
  let idx = 0;
  let apiFailures = 0;
  const worker = async () => {
    while (idx < items.length) {
      const i = idx++;
      const it = items[i];
      const hp = `${it.host}:${it.port}`;
      const r = await mskPing(hp);
      if (r.err) {
        apiFailures++;
        out.set(hp, null);
      } else {
        out.set(hp, r.rtt);
      }
      if ((i + 1) % 200 === 0) console.log(`[ping] ${label}: ${i + 1}/${items.length} (${countLive(out)} live)`);
      await sleep(120);
    }
  };
  await Promise.all(Array.from({ length: concurrency }, worker));
  console.log(`[ping] ${label}: done, checked=${out.size}, live=${countLive(out)}, apiFailures=${apiFailures}`);
  return out;
}

function countLive(map) { let n = 0; for (const v of map.values()) if (v !== null) n++; return n; }

// ---------------------------------------------------------------------------
// sing-box proxy test
// ---------------------------------------------------------------------------
function sbOutbound(c) {
  const q = c.params || {};
  const tlsName = q.sni || q.host || c.host;
  const tlsObj = (reality) => reality
    ? { enabled: true, server_name: tlsName, utls: { enabled: true, fingerprint: q.fp || 'chrome' }, reality: { enabled: true, public_key: q.pbk || '', short_id: q.sid || '' } }
    : { enabled: true, server_name: tlsName, insecure: q.allowInsecure === '1' || q.insecure === '1' || q.allow_insecure === '1', utls: q.fp ? { enabled: true, fingerprint: q.fp } : undefined };
  const transport = (() => {
    const t = (q.type || 'tcp').toLowerCase();
    if (t === 'ws') return { type: 'ws', path: q.path || '/', headers: q.host ? { Host: q.host } : undefined };
    if (t === 'grpc') return { type: 'grpc', service_name: q.serviceName || q.path || '' };
    if (t === 'http') return { type: 'http', host: q.host ? [q.host] : undefined, path: q.path || '/' };
    return undefined;
  })();
  if (c.protocol === 'vless') {
    return {
      type: 'vless', tag: 'p', server: c.host, server_port: c.port, uuid: c.uuid, flow: q.flow || '',
      tls: q.security === 'reality' ? tlsObj(true) : q.security === 'tls' ? tlsObj(false) : undefined,
      transport,
    };
  }
  if (c.protocol === 'vmess') {
    return {
      type: 'vmess', tag: 'p', server: c.host, server_port: c.port, uuid: c.uuid, security: q.security || 'auto',
      tls: q.tls ? tlsObj(false) : undefined, transport,
    };
  }
  if (c.protocol === 'trojan') {
    return {
      type: 'trojan', tag: 'p', server: c.host, server_port: c.port, password: c.password,
      tls: q.security === 'reality' ? tlsObj(true) : tlsObj(false), transport,
    };
  }
  if (c.protocol === 'ss') {
    const p = q.plugin;
    const opts = p ? [p.tls ? 'tls' : null, p.host ? `host=${p.host}` : null, p.path ? `path=${p.path}` : null, p.mode ? `mode=${p.mode}` : null].filter(Boolean).join(';') : '';
    return {
      type: 'shadowsocks', tag: 'p', server: c.host, server_port: c.port, method: c.method, password: c.password,
      plugin: p ? 'v2ray-plugin' : undefined,
      plugin_opts: p ? opts : undefined,
    };
  }
  if (c.protocol === 'tuic') {
    return {
      type: 'tuic', tag: 'p', server: c.host, server_port: c.port, uuid: c.uuid, password: c.password,
      congestion_control: q.congestion_control || 'bbr',
      udp_relay_mode: q.udp_relay_mode || 'native',
      tls: tlsObj(false),
    };
  }
  if (c.protocol === 'hysteria2') {
    return {
      type: 'hysteria2', tag: 'p', server: c.host, server_port: c.port, password: c.password,
      tls: { enabled: true, server_name: tlsName, insecure: q.insecure === '1' || q.allow_insecure === '1' },
      obfs: q.obfs ? { type: 'salamander', password: q['obfs-password'] || '' } : undefined,
    };
  }
  return null;
}

async function curlThrough(proxy, url, args = []) {
  return new Promise((res) => {
    execFile('curl', ['-sS', '-o', '/dev/null', '-w', '%{http_code} %{time_total}', '--max-time', '8', '-x', proxy, ...args, url], { timeout: 12000 }, (err, stdout) => {
      if (err) return res(null);
      const [code, time] = stdout.trim().split(/\s+/);
      const c = parseInt(code, 10);
      if (!c) return res(null);
      return res({ ok: c < 500 && c > 0, code: c, ms: Math.round(parseFloat(time || '0') * 1000) });
    });
  });
}

async function proxyTest(c) {
  const bin = SING_BOX_BIN;
  const port = 20000 + (Math.floor(Math.random() * 1000));
  const conf = { log: { level: 'error', output: path.join(TMP, `sb-${port}.log`) }, inbounds: [{ type: 'mixed', listen: '127.0.0.1', listen_port: port }], outbounds: [sbOutbound(c)], route: { final: 'p' } };
  if (!conf.outbounds[0]) return { ok: false, err: 'unsupported' };
  if (process.env.DEBUG) console.log(`[dbg] test ${c.protocol} ${c.host}:${c.port} uuid=${(c.uuid || c.password || '').slice(0, 8)}... out=${JSON.stringify(conf.outbounds[0]).slice(0, 300)}`);
  const confPath = path.join(TMP, `sb-${port}.json`);
  fs.writeFileSync(confPath, JSON.stringify(conf));
  const child = spawn(bin, ['run', '-c', confPath], { stdio: 'ignore' });
  try {
    let ready = false;
    for (let i = 0; i < 30; i++) {
      if (await tcpCheck('127.0.0.1', port, 200)) { ready = true; break; }
      await sleep(200);
    }
    if (!ready) return { ok: false, err: 'noready' };
    const proxy = `http://127.0.0.1:${port}`;
    const services = {};
    for (const [k, url] of Object.entries(GOOGLE_TESTS)) {
      const r = await curlThrough(proxy, url);
      services[k] = r ? { ok: r.ok, ms: r.ms } : { ok: false };
      if (k === 'google' && !r) break;
    }
    let speed = 0;
    if (services.google && services.google.ok) {
      const sp = await new Promise((res) => {
        execFile('curl', ['-sS', '-o', '/dev/null', '-w', '%{speed_download}', '--max-time', '12', '--range', '0-3145727', '-x', proxy, 'https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb'], { timeout: 15000 }, (err, stdout) => {
          const v = parseFloat(stdout.trim());
          res(v && v > 0 ? Math.round(v / 1048576 * 100) / 100 : 0);
        });
      });
      speed = sp;
    }
    const ok = MANDATORY.every((k) => services[k] && services[k].ok);
    if (process.env.DEBUG && !ok) {
      const log = fs.existsSync(path.join(TMP, `sb-${port}.log`)) ? fs.readFileSync(path.join(TMP, `sb-${port}.log`), 'utf8').slice(-600) : '';
      console.log(`[dbg] FAIL ${c.protocol} ${c.host}:${c.port} svc=${JSON.stringify(services)} log=${log.replace(/\n/g, ' | ')}`);
    }
    return { ok, err: ok ? null : 'mandatory', services, speed };
  } finally {
    child.kill('SIGKILL');
    setTimeout(() => fs.rmSync(confPath, { force: true }), 300);
  }
}

async function proxyTestAll(items, label) {
  const concurrency = Math.min(12, items.length || 1);
  const results = [];
  let idx = 0;
  const worker = async () => {
    while (idx < items.length) {
      const i = idx++;
      const r = await proxyTest(items[i]);
      r.cfg = items[i];
      results.push(r);
      if ((i + 1) % 50 === 0) console.log(`[proxy] ${label}: ${i + 1}/${items.length} passed=${results.filter((x) => x.ok).length}`);
    }
  };
  await Promise.all(Array.from({ length: concurrency }, worker));
  return results;
}

// ---------------------------------------------------------------------------
// sing-box download
// ---------------------------------------------------------------------------
async function ensureSingBox() {
  if (fs.existsSync(SING_BOX_BIN)) return;
  const arch = process.arch === 'arm64' ? 'arm64' : 'amd64';
  const tag = process.env.SING_BOX_VERSION || 'v1.13.19';
  const url = `https://github.com/SagerNet/sing-box/releases/download/${tag}/sing-box-${tag.replace(/^v/, '')}-linux-${arch}.tar.gz`;
  console.log(`[sb] downloading ${url}`);
  await new Promise((res, rej) => {
    execFile('curl', ['-sSL', '--max-time', '120', '-o', path.join(TMP, 'sb.tar.gz'), url], (e) => (e ? rej(e) : res()));
  });
  const tar = path.join(TMP, 'sb.tar.gz');
  execFileSync_('tar', ['-xzf', tar, '-C', TMP]);
  const dir = fs.readdirSync(TMP).find((d) => d.startsWith('sing-box-'));
  fs.copyFileSync(path.join(TMP, dir, 'sing-box'), SING_BOX_BIN);
  fs.chmodSync(SING_BOX_BIN, 0o755);
  console.log(`[sb] ok -> ${SING_BOX_BIN}`);
}
function execFileSync_(cmd, args) {
  const { execFileSync } = require('child_process');
  return execFileSync(cmd, args);
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
(async () => {
  const t0 = Date.now();
  const sourceCount = {};
  const allRaw = [];
  console.log('[fetch] downloading sources...');
  const fetched = await Promise.allSettled(SOURCES.map((s) => fetchText(s.url)));
  for (let i = 0; i < SOURCES.length; i++) {
    const s = SOURCES[i];
    const r = fetched[i];
    if (r.status !== 'fulfilled') { console.log(`[fetch] ${s.id}: FAIL`); continue; }
    let links = extractLinks(r.value);
    if (links.length < 2) {
      const dec = decodeB64(r.value);
      if (dec && dec.length > 20) links = extractLinks(dec);
    }
    const uniq = new Set(links);
    sourceCount[s.id] = uniq.size;
    console.log(`[fetch] ${s.id}: ${uniq.size} raw links`);
    for (const l of uniq) allRaw.push({ src: s.id, link: l });
  }
  console.log(`[parse] total raw: ${allRaw.length}`);

  const parsed = [];
  for (const { src, link } of allRaw) {
    const c = parseLink(link);
    if (c) { c.src = src; c.raw = link; c.link = buildLink(c) || link; parsed.push(c); }
  }
  console.log(`[parse] valid: ${parsed.length}`);

  // dedup by full raw link
  const byRaw = new Map();
  for (const c of parsed) if (!byRaw.has(c.raw)) byRaw.set(c.raw, c);
  const deduped = [...byRaw.values()];
  console.log(`[dedup] by raw link: ${deduped.length}`);

  // dedup by protocol+host+port (keep first)
  const byNode = new Map();
  for (const c of deduped) {
    const key = `${c.protocol}|${c.host}|${c.port}`;
    if (!byNode.has(key)) byNode.set(key, c);
  }
  const configs = [...byNode.values()];
  console.log(`[dedup] by node: ${configs.length}`);

  if (process.env.PARSE_ONLY === '1') {
    // audit: why did raw links fail to parse?
    const parsedKeys = new Set(parsed.map((c) => c.raw));
    const unparsed = allRaw.filter((r) => !parsedKeys.has(r.link));
    const schemeCount = {};
    for (const r of unparsed) {
      const s = (r.link.match(/^(vless|vmess|ss|trojan|tuic|hysteria2|hy2)/) || [])[1];
      schemeCount[s] = (schemeCount[s] || 0) + 1;
    }
    console.log(`[audit] unparsed: ${unparsed.length}, by scheme: ${JSON.stringify(schemeCount)}`);
    console.log('[audit] unparsed samples:');
    for (const r of unparsed.slice(0, 10)) console.log('   ', r.link.slice(0, 130));
    process.exit(0);
  }

  // resolve ips + geo
  console.log('[geo] resolving IPs...');
  await resolveIps([...new Set(configs.map((c) => c.host))]);
  for (const c of configs) c.ip = ipCache.get(c.host);
  const uniqueIps = [...new Set(configs.map((c) => c.ip).filter(Boolean))];
  console.log(`[geo] resolved ${configs.filter((c) => c.ip).length}/${configs.length}, unique IPs: ${uniqueIps.length}`);
  await geoIpBatch([...uniqueIps]);
  for (const c of configs) c.country = geoCache.get(c.ip) || null;
  console.log(`[geo] country known: ${configs.filter((c) => c.country).length}`);

  // local TCP check
  console.log('[tcp] local liveness check...');
  const tcpResults = [];
  {
    let idx = 0;
    const concurrency = 150;
    const worker = async () => { while (idx < configs.length) { const i = idx++; tcpResults[i] = await tcpCheck(configs[i].host, configs[i].port); } };
    await Promise.all(Array.from({ length: concurrency }, worker));
  }
  const alive = configs.filter((c, i) => tcpResults[i]);
  console.log(`[tcp] alive: ${alive.length}/${configs.length}`);

  // Moscow ping (optional, disabled with SKIP_PING=1)
  let pingList = alive;
  let mskLive = alive;
  if (process.env.SKIP_PING !== '1') {
    if (PING_LIMIT > 0) pingList = alive.slice(0, PING_LIMIT);
    console.log(`[ping] Moscow check-host.net for ${pingList.length} configs...`);
    const pingMap = await mskPingAll(pingList, 'msk');
    // drop only VERIFIED-unreachable from Moscow; keep checked-live and api-failed (unknown)
    mskLive = pingList.filter((c) => {
      const v = pingMap.get(`${c.host}:${c.port}`);
      return v === undefined || v !== null;
    });
    console.log(`[ping] reachable from Moscow (verified): ${mskLive.length}/${pingList.length}`);
    for (const c of pingList) c.rtt = pingMap.get(`${c.host}:${c.port}`);
  } else {
    console.log('[ping] SKIP_PING=1 — Moscow check skipped, using local TCP results');
  }

  // proxy test
  let testList = mskLive;
  if (PROXY_LIMIT > 0) testList = mskLive.slice(0, PROXY_LIMIT);
  if (testList.length === 0) {
    console.log('[proxy] nothing to test');
  } else {
    await ensureSingBox();
    console.log(`[proxy] testing ${testList.length} configs via sing-box...`);
    const results = await proxyTestAll(testList, 'test');
    for (let i = 0; i < testList.length; i++) {
      const r = results[i];
      testList[i].proxyOk = r.ok;
      testList[i].proxyErr = r.err;
      testList[i].services = r.services;
      testList[i].speed = r.speed || 0;
    }
    const passed = testList.filter((c) => c.proxyOk);
    console.log(`[proxy] google-pass: ${passed.length}/${testList.length}`);
  }

  // final
  const finalList = configs.filter((c) => c.proxyOk);
  console.log(`[final] configs passing all checks: ${finalList.length}`);

  // country hint + name
  for (const c of finalList) {
    if (!c.country) c.country = '??';
    const hint = hostnameCountryHint(c.host);
    if (hint) c.country = hint;
  }

  // build data.json
  const countries = {};
  for (const c of finalList) {
    const cc = c.country || '??';
    if (!countries[cc]) countries[cc] = {};
    if (!countries[cc][c.protocol]) countries[cc][c.protocol] = [];
    countries[cc][c.protocol].push({
      n: (c.name || '').slice(0, 60),
      p: c.protocol,
      h: c.host,
      pt: c.port,
      rtt: c.rtt ?? null,
      sp: c.speed || 0,
      sv: c.services ? Object.entries(c.services).filter(([k, v]) => v && v.ok).map(([k]) => k) : [],
      link: c.link,
    });
  }
  for (const cc of Object.keys(countries)) {
    for (const proto of Object.keys(countries[cc])) {
      countries[cc][proto].sort((a, b) => (a.rtt ?? 99999) - (b.rtt ?? 99999) || b.sp - a.sp);
    }
  }
  const data = {
    updated: new Date().toISOString(),
    sources: sourceCount,
    stats: {
      fetched: allRaw.length,
      parsed: parsed.length,
      dedup: configs.length,
      alive: alive.length,
      moscow: mskLive.length,
      google: finalList.length,
    },
    countries,
  };
  fs.writeFileSync(path.join(SCRIPT_DIR, 'data.json'), JSON.stringify(data));
  const dt = ((Date.now() - t0) / 1000).toFixed(0);
  console.log(`[done] ${dt}s, countries: ${Object.keys(countries).length}, configs: ${finalList.length}`);
  console.log(`[done] stats: ${JSON.stringify(data.stats)}`);
})();
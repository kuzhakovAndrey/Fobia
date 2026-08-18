const fs = require("fs");
const path = require("path");

const SOURCES = [
  { name: "Pawdroid/Free-servers", stars: 18675, url: "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub", base64: true },
  { name: "igareck/vpn-configs-for-russia", stars: 8169, url: "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_VLESS_RUS.txt", base64: false },
  { name: "awesome-vpn/awesome-vpn", stars: 6104, url: "https://raw.githubusercontent.com/awesome-vpn/awesome-vpn/master/all", base64: true },
  { name: "Epodonios/v2ray-configs", stars: 3194, url: "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/All_Configs_Sub.txt", base64: false },
  { name: "Barabama/FreeNodes", stars: 3060, url: "https://raw.githubusercontent.com/Barabama/FreeNodes/feat/ai-crawler-v2/nodes/nodev2ray.txt", base64: false },
  { name: "barry-far/V2ray-Config", stars: 2323, url: "https://raw.githubusercontent.com/barry-far/V2ray-Config/master/All_Configs_Sub.txt", base64: false },
  { name: "snakem982/proxypool", stars: 2007, url: "https://raw.githubusercontent.com/snakem982/proxypool/main/source/v2ray-2.txt", base64: true },
];

const PROTO_RE = /^(hysteria2|hysteria|vless|vmess|ss|trojan|tuic|wireguard):\/\//;

function extractLinks(text) {
  const links = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line) continue;
    if (PROTO_RE.test(line)) links.push(line);
  }
  return links;
}

function decodeIfNeeded(text, isBase64) {
  if (!isBase64) return text;
  try {
    const decoded = Buffer.from(text.replace(/\s+/g, ""), "base64").toString("utf8");
    if (extractLinks(decoded).length) return decoded;
  } catch {}
  return text;
}

async function fetchText(url) {
  const res = await fetch(url, { headers: { "User-Agent": "happ-hysteria2-filter" } });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.text();
}

const net = require("net");

const PING_TIMEOUT_MS = 2500;
const PING_CONCURRENCY = 25;

function pingHost(host, port) {
  return new Promise((resolve) => {
    const t0 = Date.now();
    const sock = net.connect({ host, port, timeout: PING_TIMEOUT_MS });
    sock.once("connect", () => {
      const rtt = Date.now() - t0;
      sock.destroy();
      resolve(rtt);
    });
    sock.once("timeout", () => {
      sock.destroy();
      resolve(null);
    });
    sock.once("error", () => resolve(null));
  });
}

async function pingAll(targets, concurrency) {
  const results = new Map();
  let idx = 0;
  const workers = Array.from({ length: concurrency }, async () => {
    while (idx < targets.length) {
      const i = idx++;
      const [host, port] = targets[i];
      const rtt = await pingHost(host, port);
      if (rtt !== null) results.set(`${host}:${port}`, rtt);
    }
  });
  await Promise.all(workers);
  return results;
}

const CHECK_HOST = "https://check-host.net";
const MOSCOW_NODES = ["ru1.node.check-host.net", "ru2.node.check-host.net"];
const MOSCOW_POLL_MS = 2000;
const MOSCOW_MAX_POLLS = 8;
const MOSCOW_DELAY_MS = 1000;
const REQ_TIMEOUT_MS = 12000;

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

async function fetchJson(url) {
  const res = await fetch(url, { headers: { Accept: "application/json" }, signal: AbortSignal.timeout(REQ_TIMEOUT_MS) });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

async function checkHostTcp(host, port) {
  const q = `host=${encodeURIComponent(`${host}:${port}`)}&node=${MOSCOW_NODES.join("&node=")}`;
  const data = await fetchJson(`${CHECK_HOST}/check-tcp?${q}`);
  if (!data.ok) throw new Error("запрос отклонён");
  const rid = data.request_id;
  for (let i = 0; i < MOSCOW_MAX_POLLS; i++) {
    await sleep(MOSCOW_POLL_MS);
    const results = await fetchJson(`${CHECK_HOST}/check-result/${rid}`);
    const times = [];
    let failed = false;
    for (const node of MOSCOW_NODES) {
      const r = results[node];
      if (r === null) continue;
      const first = Array.isArray(r) ? r[0] : r;
      if (first && first.time != null) times.push(first.time * 1000);
      else if (first && first.error) failed = true;
    }
    if (times.length) return { ok: true, rtt: Math.round(times.reduce((a, b) => a + b, 0) / times.length) };
    if (failed) return { ok: false };
  }
  return null;
}

async function pingMoscow(targets) {
  const results = new Map();
  let failures = 0;
  for (const [host, port] of targets) {
    try {
      const r = await checkHostTcp(host, port);
      if (r && r.ok) results.set(`${host}:${port}`, { moscow: r.rtt });
      else if (r && !r.ok) results.set(`${host}:${port}`, { moscow: null });
      else results.set(`${host}:${port}`, { moscow: null });
      failures = 0;
    } catch (e) {
      failures++;
      if (failures >= 5) {
        console.log(`check-host.net недоступен (${e.message}), останавливаю московские проверки`);
        break;
      }
    }
    await sleep(MOSCOW_DELAY_MS);
  }
  return results;
}

async function main() {
  const unique = new Set();
  const sources = [];

  await Promise.all(
    SOURCES.map(async (s) => {
      const entry = { name: s.name, stars: s.stars, total: 0, h2: 0, ok: false };
      try {
        const text = await fetchText(s.url);
        const decoded = decodeIfNeeded(text, s.base64);
        const links = extractLinks(decoded);
        entry.total = links.length;
        entry.h2 = links.filter((l) => l.startsWith("hysteria2://")).length;
        entry.ok = true;
        for (const l of links) unique.add(l);
      } catch (e) {
        entry.error = e.message;
      }
      sources.push(entry);
      console.log(`${s.name.padEnd(32)} ${entry.ok ? entry.total + " cfg, " + entry.h2 + " h2" : "ERROR: " + entry.error}`);
    })
  );

  const all = Array.from(unique);
  const h2 = all.filter((l) => l.startsWith("hysteria2://"));
  const outDir = process.env.OUT_DIR || "configs";
  fs.mkdirSync(outDir, { recursive: true });
  fs.writeFileSync(path.join(outDir, "all.txt"), all.join("\n") + "\n");
  fs.writeFileSync(path.join(outDir, "hysteria2.txt"), h2.join("\n") + "\n");

  console.log(`Пинг ${h2.length} hysteria2 серверов (TCP, из GitHub Actions)...`);
  const targets = [];
  for (const l of h2) {
    try {
      const u = new URL(l);
      targets.push([u.hostname, Number(u.port) || 443]);
    } catch {}
  }
  const uniqueTargets = Array.from(new Map(targets.map((t) => [t.join(":"), t])).values());
  const limit = Number(process.env.PING_LIMIT) || uniqueTargets.length;
  const limitedTargets = uniqueTargets.slice(0, limit);
  const pingMap = await pingAll(limitedTargets, PING_CONCURRENCY);
  console.log(`TCP-пинг (GitHub): ${pingMap.size} из ${limitedTargets.length} серверов`);
  console.log(`Проверяю ${limitedTargets.length} серверов с узлов Москвы (check-host.net)...`);
  const moscowMap = await pingMoscow(limitedTargets);
  const merged = {};
  for (const [key, rtt] of pingMap) {
    merged[key] = { server: rtt, moscow: moscowMap.get(key)?.moscow ?? null };
  }
  for (const [key, v] of moscowMap) {
    if (!merged[key]) merged[key] = { server: null, moscow: v.moscow };
  }
  fs.writeFileSync(path.join(outDir, "ping.json"), JSON.stringify(merged, null, 2));
  const moscowOk = Object.values(merged).filter((v) => v.moscow != null).length;
  console.log(`Пинг от Москвы получен для ${moscowOk} из ${limitedTargets.length} серверов`);

  const meta = {
    updated: new Date().toISOString(),
    total: all.length,
    hysteria2: h2.length,
    sources,
  };
  fs.writeFileSync(path.join(outDir, "sources.json"), JSON.stringify(meta, null, 2));

  console.log(`---\nУникальных: ${all.length}, hysteria2: ${h2.length}, файлы в ${outDir}/`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
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
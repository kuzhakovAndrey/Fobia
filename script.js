(() => {
  "use strict";

  const PROTOCOLS = ["hysteria2", "hysteria", "vless", "vmess", "ss", "trojan", "tuic", "wireguard"];

  const SOURCES = [
    { name: "Pawdroid/Free-servers", stars: 18675, url: "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub", base64: true },
    { name: "igareck/vpn-configs-for-russia", stars: 8169, url: "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_VLESS_RUS.txt", base64: false },
    { name: "awesome-vpn/awesome-vpn", stars: 6104, url: "https://raw.githubusercontent.com/awesome-vpn/awesome-vpn/master/all", base64: true },
    { name: "Epodonios/v2ray-configs", stars: 3194, url: "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/All_Configs_Sub.txt", base64: false },
    { name: "Barabama/FreeNodes", stars: 3060, url: "https://raw.githubusercontent.com/Barabama/FreeNodes/feat/ai-crawler-v2/nodes/nodev2ray.txt", base64: false },
    { name: "barry-far/V2ray-Config", stars: 2323, url: "https://raw.githubusercontent.com/barry-far/V2ray-Config/master/All_Configs_Sub.txt", base64: false },
    { name: "snakem982/proxypool", stars: 2007, url: "https://raw.githubusercontent.com/snakem982/proxypool/main/source/v2ray-2.txt", base64: true },
  ];

  const $ = (id) => document.getElementById(id);
  const els = {
    configs: $("configs"),
    subUrl: $("sub-url"),
    btnFetch: $("btn-fetch"),
    search: $("search"),
    btnClear: $("btn-clear"),
    btnRefresh: $("btn-refresh"),
    result: $("result"),
    empty: $("empty"),
    statTotal: $("stat-total"),
    statH2: $("stat-h2"),
    statOther: $("stat-other"),
    statShown: $("stat-shown"),
    btnCopyAll: $("btn-copy-all"),
    btnDownload: $("btn-download"),
    toast: $("toast"),
    sources: $("sources"),
    sourcesStatus: $("sources-status"),
  };

  let allConfigs = [];
  let sourceCounts = new Map();

  function extractLinks(text) {
    const links = [];
    for (const raw of text.split(/\r?\n/)) {
      const line = raw.trim();
      if (!line) continue;
      const m = line.match(/^(hysteria2|hysteria|vless|vmess|ss|trojan|tuic|wireguard):\/\//);
      if (m) links.push(line);
    }
    return links;
  }

  function decodeIfNeeded(text, isBase64) {
    if (!isBase64) return text;
    try {
      const cleaned = text.replace(/\s+/g, "");
      const decoded = atob(cleaned);
      if (extractLinks(decoded).length) return decoded;
    } catch {}
    return text;
  }

  function parseHysteria2(link) {
    try {
      const u = new URL(link);
      const frag = u.hash ? decodeURIComponent(u.hash.slice(1)) : "";
      const name = frag || u.host || "hysteria2";
      return {
        name,
        host: u.hostname,
        port: u.port || "443",
        sni: u.searchParams.get("sni") || u.hostname,
        insecure: u.searchParams.get("insecure") === "1",
        obfs: u.searchParams.get("obfs") || "",
        link,
      };
    } catch {
      return { name: "hysteria2", host: "?", port: "?", link };
    }
  }

  function render() {
    const search = els.search.value.trim().toLowerCase();
    const h2 = allConfigs.filter((l) => l.startsWith("hysteria2://"));
    const h2Items = h2.map(parseHysteria2);
    const filtered = search
      ? h2Items.filter((c) => (c.name + " " + c.host + " " + c.port).toLowerCase().includes(search))
      : h2Items;

    const total = allConfigs.length;
    els.statTotal.textContent = total;
    els.statH2.textContent = h2.length;
    els.statOther.textContent = total - h2.length;
    els.statShown.textContent = filtered.length;

    els.result.innerHTML = "";
    if (filtered.length === 0) {
      els.empty.classList.remove("hidden");
    } else {
      els.empty.classList.add("hidden");
      const frag = document.createDocumentFragment();
      for (const c of filtered) {
        const item = document.createElement("div");
        item.className = "config-item";
        const proto = document.createElement("span");
        proto.className = "proto";
        proto.textContent = "hysteria2";
        const link = document.createElement("span");
        link.className = "link";
        const name = document.createElement("span");
        name.className = "name";
        name.textContent = c.name;
        const host = document.createElement("span");
        host.textContent = ` ${c.host}:${c.port}`;
        if (c.obfs) host.textContent += ` (obfs:${c.obfs})`;
        link.append(name, host);
        const copy = document.createElement("button");
        copy.className = "copy-btn";
        copy.textContent = "Копировать";
        copy.addEventListener("click", () => copyText(c.link, "Конфиг скопирован"));
        item.append(proto, link, copy);
        frag.appendChild(item);
      }
      els.result.appendChild(frag);
    }
  }

  function process(text) {
    allConfigs = extractLinks(text);
    render();
  }

  function renderSources() {
    els.sources.innerHTML = "";
    let loaded = 0;
    let h2total = 0;
    for (const s of SOURCES) {
      const row = document.createElement("div");
      row.className = "source-item";
      const info = sourceCounts.get(s.name);
      const name = document.createElement("span");
      name.className = "source-name";
      name.textContent = `${s.name} ⭐${s.stars}`;
      const status = document.createElement("span");
      status.className = "source-status";
      if (info === undefined) {
        status.textContent = "...";
      } else if (info === null) {
        status.classList.add("err");
        status.textContent = "ошибка";
      } else {
        status.classList.add("ok");
        status.textContent = `${info.total} конфигов, ${info.h2} hysteria2`;
        loaded++;
        h2total += info.h2;
      }
      row.append(name, status);
      els.sources.appendChild(row);
    }
    els.sourcesStatus.textContent = loaded === SOURCES.length
      ? `Все ${SOURCES.length} источников загружены: ${h2total} hysteria2`
      : `Загружено ${loaded} из ${SOURCES.length} источников`;
  }

  function copyText(text, msg) {
    navigator.clipboard.writeText(text).then(
      () => toast(msg || "Скопировано"),
      () => toast("Не удалось скопировать", true)
    );
  }

  function toast(msg, isErr) {
    els.toast.textContent = msg;
    els.toast.classList.remove("err", "hidden");
    if (isErr) els.toast.classList.add("err");
    clearTimeout(toast._t);
    toast._t = setTimeout(() => els.toast.classList.add("hidden"), 3000);
  }

  async function fetchWithFallback(url) {
    const sources = [url, `https://corsproxy.io/?url=${encodeURIComponent(url)}`, `https://api.allorigins.win/raw?url=${encodeURIComponent(url)}`];
    let lastErr = null;
    for (const src of sources) {
      try {
        const res = await fetch(src);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const text = await res.text();
        if (!text.length) throw new Error("пустой ответ");
        return text;
      } catch (e) {
        lastErr = e;
      }
    }
    throw lastErr || new Error("Не удалось загрузить");
  }

  async function loadSources() {
    els.btnRefresh.disabled = true;
    els.btnRefresh.textContent = "Обновление...";
    const unique = new Set();
    let added = 0;
    await Promise.allSettled(
      SOURCES.map(async (s) => {
        try {
          const text = await fetchWithFallback(s.url);
          const decoded = decodeIfNeeded(text, s.base64);
          const links = extractLinks(decoded);
          const h2 = links.filter((l) => l.startsWith("hysteria2://")).length;
          sourceCounts.set(s.name, { total: links.length, h2 });
          for (const l of links) {
            if (!unique.has(l)) {
              unique.add(l);
              added++;
            }
          }
        } catch (e) {
          sourceCounts.set(s.name, null);
        }
        renderSources();
      })
    );
    allConfigs = Array.from(unique);
    render();
    els.btnRefresh.disabled = false;
    els.btnRefresh.textContent = "Обновить источники";
    toast(`Источники обновлены: ${allConfigs.length} уникальных конфигов`);
  }

  els.configs.addEventListener("input", () => process(els.configs.value));
  els.search.addEventListener("input", render);
  els.btnClear.addEventListener("click", () => {
    els.configs.value = "";
    els.search.value = "";
    els.subUrl.value = "";
    allConfigs = [];
    render();
  });

  els.btnFetch.addEventListener("click", async () => {
    const url = els.subUrl.value.trim();
    if (!url) {
      toast("Введи ссылку на подписку", true);
      return;
    }
    els.btnFetch.disabled = true;
    els.btnFetch.textContent = "Загрузка...";
    try {
      const text = await fetchWithFallback(url);
      const links = extractLinks(text);
      const merged = Array.from(new Set([...allConfigs, ...links]));
      allConfigs = merged;
      els.configs.value = allConfigs.join("\n");
      render();
      toast(`Добавлено: ${links.length} конфигов`);
    } catch (e) {
      toast("Ошибка загрузки подписки: " + e.message, true);
    } finally {
      els.btnFetch.disabled = false;
      els.btnFetch.textContent = "Загрузить";
    }
  });

  els.btnRefresh.addEventListener("click", loadSources);

  els.btnCopyAll.addEventListener("click", () => {
    const links = allConfigs.filter((l) => l.startsWith("hysteria2://"));
    if (!links.length) {
      toast("Нет hysteria2 конфигов", true);
      return;
    }
    copyText(links.join("\n"), `Скопировано: ${links.length} конфигов`);
  });

  els.btnDownload.addEventListener("click", () => {
    const links = allConfigs.filter((l) => l.startsWith("hysteria2://"));
    if (!links.length) {
      toast("Нет hysteria2 конфигов", true);
      return;
    }
    const blob = new Blob([links.join("\n")], { type: "text/plain;charset=utf-8" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "hysteria2-configs.txt";
    a.click();
    URL.revokeObjectURL(a.href);
  });

  renderSources();
  render();
  loadSources();
})();
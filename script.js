(() => {
  "use strict";

  const PROTOCOLS = ["hysteria2", "hysteria", "vless", "vmess", "ss", "trojan", "tuic", "wireguard"];

  const $ = (id) => document.getElementById(id);
  const els = {
    configs: $("configs"),
    subUrl: $("sub-url"),
    btnFetch: $("btn-fetch"),
    search: $("search"),
    btnClear: $("btn-clear"),
    result: $("result"),
    empty: $("empty"),
    statTotal: $("stat-total"),
    statH2: $("stat-h2"),
    statOther: $("stat-other"),
    statShown: $("stat-shown"),
    btnCopyAll: $("btn-copy-all"),
    btnDownload: $("btn-download"),
    toast: $("toast"),
  };

  let allConfigs = [];

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
    toast._t = setTimeout(() => els.toast.classList.add("hidden"), 2500);
  }

  async function fetchSubscription(url) {
    const sources = [url, `https://corsproxy.io/?url=${encodeURIComponent(url)}`, `https://api.allorigins.win/raw?url=${encodeURIComponent(url)}`];
    let lastErr = null;
    for (const src of sources) {
      try {
        const res = await fetch(src);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const text = await res.text();
        if (!extractLinks(text).length) throw new Error("нет конфигов");
        return text;
      } catch (e) {
        lastErr = e;
      }
    }
    throw lastErr || new Error("Не удалось загрузить подписку");
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
      const text = await fetchSubscription(url);
      els.configs.value = text;
      process(text);
      toast(`Загружено: ${allConfigs.length} конфигов`);
    } catch (e) {
      toast("Ошибка загрузки подписки: " + e.message, true);
    } finally {
      els.btnFetch.disabled = false;
      els.btnFetch.textContent = "Загрузить";
    }
  });

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

  render();
})();
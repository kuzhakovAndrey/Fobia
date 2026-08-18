(() => {
  "use strict";

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
    statMobile: $("stat-mobile"),
    statH2: $("stat-h2"),
    statShown: $("stat-shown"),
    btnCopyAll: $("btn-copy-all"),
    btnDownload: $("btn-download"),
    toast: $("toast"),
    sources: $("sources"),
    sourcesStatus: $("sources-status"),
    updated: $("updated"),
    sort: $("sort"),
    protoFilter: $("proto-filter"),
  };

  let hysteria2 = [];
  let metaTotal = 0;
  let metaMobile = 0;
  let metaCaveat = 0;
  let pingMap = {};
  let sortMode = "default";
  let filter = "hysteria2";
  let currentList = [];
  const cache = {};

  function extractLinks(text) {
    const links = [];
    for (const raw of text.split(/\r?\n/)) {
      const line = raw.trim();
      if (!line) continue;
      if (/^(hysteria2|hysteria|vless|vmess|ss|trojan|tuic|wireguard):\/\//.test(line)) links.push(line);
    }
    return links;
  }

  function protoInfo(link) {
    if (link.startsWith("hysteria2://")) return { label: "hysteria2", mobile: true };
    if (link.startsWith("trojan://")) return { label: "trojan", mobile: true };
    if (link.startsWith("vless://")) return { label: "vless+Reality", mobile: true };
    if (link.startsWith("ss://")) return { label: "ss", mobile: false };
    if (link.startsWith("vmess://")) return { label: "vmess", mobile: false };
    if (link.startsWith("tuic://")) return { label: "tuic", mobile: false };
    return { label: "?", mobile: false };
  }

  function parseItem(link) {
    const proto = protoInfo(link);
    let host = "?", port = "", name = proto.label;
    try {
      const u = new URL(link.replace("ss://", "https://").replace("vmess://", "https://"));
      if (proto.label === "hysteria2" || proto.label === "trojan" || proto.label === "vless+Reality") {
        host = u.hostname;
        port = u.port || "";
      }
      const frag = u.hash ? decodeURIComponent(u.hash.slice(1)) : "";
      if (frag) name = frag;
    } catch {}
    const p = pingMap[`${host}:${port}`];
    return { proto, host, port, name, link, moscow: p ? p.moscow : null };
  }

  function render() {
    const search = els.search.value.trim().toLowerCase();
    let items = currentList.map(parseItem);
    if (search) items = items.filter((c) => (c.name + " " + c.host + " " + c.port).toLowerCase().includes(search));
    if (sortMode === "ping") items.sort((a, b) => (a.moscow ?? 1e9) - (b.moscow ?? 1e9));

    els.statTotal.textContent = metaTotal || currentList.length;
    els.statMobile.textContent = metaMobile || currentList.filter((l) => protoInfo(l).mobile).length;
    els.statH2.textContent = hysteria2.length;
    els.statShown.textContent = items.length;

    els.result.innerHTML = "";
    if (items.length === 0) {
      els.empty.classList.remove("hidden");
    } else {
      els.empty.classList.add("hidden");
      const frag = document.createDocumentFragment();
      for (const c of items) {
        const item = document.createElement("div");
        item.className = "config-item";
        const proto = document.createElement("span");
        proto.className = "proto-badge " + (c.proto.mobile ? "mobile" : "warn");
        proto.textContent = (c.proto.mobile ? "✅ " : "⚠️ ") + c.proto.label;
        const link = document.createElement("span");
        link.className = "link";
        const name = document.createElement("span");
        name.className = "name";
        name.textContent = c.name;
        const host = document.createElement("span");
        host.textContent = c.host === "?" ? "" : ` ${c.host}${c.port ? ":" + c.port : ""}`;
        link.append(name, host);
        let ping = null;
        if (c.moscow != null) {
          ping = document.createElement("span");
          ping.className = "ping-badge " + (c.moscow < 100 ? "fast" : c.moscow < 300 ? "mid" : "slow");
          ping.textContent = `Мск: ${c.moscow} мс`;
        }
        const copy = document.createElement("button");
        copy.className = "copy-btn";
        copy.textContent = "Копировать";
        copy.addEventListener("click", () => copyText(c.link, "Конфиг скопирован"));
        item.append(proto, link);
        if (ping) item.append(ping);
        item.append(copy);
        frag.appendChild(item);
      }
      els.result.appendChild(frag);
    }
  }

  function renderSources(meta) {
    els.sources.innerHTML = "";
    let loaded = 0;
    let h2total = 0;
    for (const s of meta.sources) {
      const row = document.createElement("div");
      row.className = "source-item";
      const name = document.createElement("span");
      name.className = "source-name";
      name.textContent = `${s.name} ⭐${s.stars}`;
      const status = document.createElement("span");
      status.className = "source-status";
      if (s.ok) {
        status.classList.add("ok");
        status.textContent = `${s.total} конфигов, ${s.h2} hysteria2`;
        loaded++;
        h2total += s.h2;
      } else {
        status.classList.add("err");
        status.textContent = "ошибка: " + (s.error || "?");
      }
      row.append(name, status);
      els.sources.appendChild(row);
    }
    els.sourcesStatus.textContent = loaded === meta.sources.length
      ? `Все ${meta.sources.length} источников загружены: ${h2total} hysteria2`
      : `Загружено ${loaded} из ${meta.sources.length}`;
    els.updated.textContent = `Обновлено: ${new Date(meta.updated).toLocaleString("ru-RU")}`;
  }

  async function loadList(filterName) {
    if (filterName === "hysteria2") return hysteria2;
    const key = filterName === "caveat" ? "caveat" : "mobile";
    if (cache[key] === undefined) {
      const res = await fetch(`configs/${key}.txt`);
      if (!res.ok) throw new Error(`не удалось загрузить ${key}.txt`);
      cache[key] = extractLinks(await res.text());
    }
    let links = cache[key];
    if (filterName === "vless") links = links.filter((l) => l.startsWith("vless://"));
    if (filterName === "trojan") links = links.filter((l) => l.startsWith("trojan://"));
    return links;
  }

  async function applyFilter() {
    try {
      currentList = await loadList(filter);
      render();
    } catch (e) {
      toast("Ошибка: " + e.message, true);
    }
  }

  async function loadLocal() {
    try {
      const [metaRes, h2Res, pingRes] = await Promise.all([
        fetch("configs/sources.json"),
        fetch("configs/hysteria2.txt"),
        fetch("configs/ping.json"),
      ]);
      if (!metaRes.ok || !h2Res.ok) throw new Error("файлы конфигов не найдены");
      const meta = await metaRes.json();
      metaTotal = meta.total;
      metaMobile = meta.mobile || 0;
      metaCaveat = meta.caveat || 0;
      hysteria2 = extractLinks(await h2Res.text());
      if (pingRes.ok) pingMap = await pingRes.json();
      renderSources(meta);
      await applyFilter();
    } catch (e) {
      els.sourcesStatus.textContent = "Ошибка загрузки: " + e.message;
      els.updated.textContent = "";
      toast("Не удалось загрузить конфиги: " + e.message, true);
    }
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

  els.configs.addEventListener("input", () => {
    const links = extractLinks(els.configs.value);
    if (links.length) {
      currentList = links;
      metaTotal = 0;
      render();
    }
  });

  els.search.addEventListener("input", render);
  els.protoFilter.addEventListener("change", () => {
    filter = els.protoFilter.value;
    applyFilter();
  });
  els.sort.addEventListener("change", () => {
    sortMode = els.sort.value;
    render();
  });
  els.btnClear.addEventListener("click", () => {
    els.configs.value = "";
    els.search.value = "";
    els.subUrl.value = "";
    loadLocal();
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
      if (!links.length) throw new Error("нет конфигов");
      currentList = links;
      metaTotal = 0;
      render();
      const h2n = links.filter((l) => l.startsWith("hysteria2://")).length;
      toast(`Загружено: ${links.length} конфигов, ${h2n} hysteria2`);
    } catch (e) {
      toast("Ошибка загрузки подписки: " + e.message, true);
    } finally {
      els.btnFetch.disabled = false;
      els.btnFetch.textContent = "Загрузить";
    }
  });

  els.btnRefresh.addEventListener("click", loadLocal);

  els.btnCopyAll.addEventListener("click", () => {
    if (!currentList.length) {
      toast("Нет конфигов", true);
      return;
    }
    copyText(currentList.join("\n"), `Скопировано: ${currentList.length} конфигов`);
  });

  els.btnDownload.addEventListener("click", () => {
    if (!currentList.length) {
      toast("Нет конфигов", true);
      return;
    }
    const blob = new Blob([currentList.join("\n")], { type: "text/plain;charset=utf-8" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "configs.txt";
    a.click();
    URL.revokeObjectURL(a.href);
  });

  render();
  loadLocal();
})();
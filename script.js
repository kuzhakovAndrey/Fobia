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
    statH2: $("stat-h2"),
    statOther: $("stat-other"),
    statShown: $("stat-shown"),
    btnCopyAll: $("btn-copy-all"),
    btnDownload: $("btn-download"),
    sort: $("sort"),
    toast: $("toast"),
    sources: $("sources"),
    sourcesStatus: $("sources-status"),
    updated: $("updated"),
  };

  let allConfigs = [];
  let hysteria2 = [];
  let metaTotal = 0;
  let pingMap = {};
  let sortMode = "default";

  function extractLinks(text) {
    const links = [];
    for (const raw of text.split(/\r?\n/)) {
      const line = raw.trim();
      if (!line) continue;
      if (/^(hysteria2|hysteria|vless|vmess|ss|trojan|tuic|wireguard):\/\//.test(line)) links.push(line);
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
    let h2Items = hysteria2.map(parseHysteria2).map((c) => {
      const p = pingMap[`${c.host}:${c.port}`];
      c.moscow = p ? p.moscow : null;
      return c;
    });
    if (search) h2Items = h2Items.filter((c) => (c.name + " " + c.host + " " + c.port).toLowerCase().includes(search));
    if (sortMode === "ping") h2Items.sort((a, b) => (a.moscow ?? 1e9) - (b.moscow ?? 1e9));
    const filtered = h2Items;

    els.statTotal.textContent = metaTotal || allConfigs.length;
    els.statH2.textContent = hysteria2.length;
    els.statOther.textContent = (metaTotal || allConfigs.length) - hysteria2.length;
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
        const ping = document.createElement("span");
        ping.className = "ping-badge";
        if (c.moscow != null) {
          ping.textContent = `Мск: ${c.moscow} мс`;
          ping.classList.add(c.moscow < 100 ? "fast" : c.moscow < 300 ? "mid" : "slow");
        } else {
          ping.textContent = "Мск: недоступен";
          ping.classList.add("down");
        }
        item.append(proto, link, ping, copy);
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
      hysteria2 = extractLinks(await h2Res.text());
      if (pingRes.ok) pingMap = await pingRes.json();
      renderSources(meta);
      render();
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
      allConfigs = links;
      hysteria2 = links.filter((l) => l.startsWith("hysteria2://"));
      els.statTotal.textContent = allConfigs.length;
      render();
    }
  });

  els.search.addEventListener("input", render);
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
      allConfigs = links;
      hysteria2 = links.filter((l) => l.startsWith("hysteria2://"));
      render();
      toast(`Загружено: ${links.length} конфигов, ${hysteria2.length} hysteria2`);
    } catch (e) {
      toast("Ошибка загрузки подписки: " + e.message, true);
    } finally {
      els.btnFetch.disabled = false;
      els.btnFetch.textContent = "Загрузить";
    }
  });

  els.btnRefresh.addEventListener("click", loadLocal);

  els.btnCopyAll.addEventListener("click", () => {
    if (!hysteria2.length) {
      toast("Нет hysteria2 конфигов", true);
      return;
    }
    copyText(hysteria2.join("\n"), `Скопировано: ${hysteria2.length} конфигов`);
  });

  els.btnDownload.addEventListener("click", () => {
    if (!hysteria2.length) {
      toast("Нет hysteria2 конфигов", true);
      return;
    }
    const blob = new Blob([hysteria2.join("\n")], { type: "text/plain;charset=utf-8" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "hysteria2-configs.txt";
    a.click();
    URL.revokeObjectURL(a.href);
  });

  render();
  loadLocal();
})();
// vercel-doh — online DNS lookup tool (vanilla JS, no dependencies).
// Queries the same-origin dns-json endpoint (/dns-query-json) or, when a
// third-party DoH provider is selected, that provider's dns-json endpoint
// directly from the browser (CORS permitting).
//
// Borrowed from CF-Workers-DoH (cmliu) and adapted: multi-provider selection,
// parallel A/AAAA/NS lookup with tabbed results, click-to-copy, optional IP
// geo info, last-domain memory. All DNS answer rendering uses
// createElement/textContent — never innerHTML with answer data.

"use strict";

const form = document.getElementById("dns-form");
const domainInput = document.getElementById("domain");
const typeInput = document.getElementById("type");
const doCheckbox = document.getElementById("opt-do");
const cdCheckbox = document.getElementById("opt-cd");
const familySelect = document.getElementById("opt-family");
const ecsSelect = document.getElementById("opt-ecs");
const ecsIpInput = document.getElementById("opt-ecs-ip");
const submitButton = document.getElementById("submit-button");
const buttonText = document.getElementById("button-text");
const spinner = document.getElementById("spinner");
const results = document.getElementById("results");
const endpointCode = document.getElementById("endpoint-code");
const copyButton = document.getElementById("copy-endpoint");
const epFamily = document.getElementById("ep-family");
const epEcs = document.getElementById("ep-ecs");
const epEcsIp = document.getElementById("ep-ecs-ip");
const dohProvider = document.getElementById("doh-provider");
const customDoh = document.getElementById("custom-doh");
const getJsonBtn = document.getElementById("get-json-btn");
const copyResultBtn = document.getElementById("copy-result-btn");
/** Raw JSON of the latest result, for the 复制结果 button. */
let lastRawJson = "";

// ── DoH endpoint display (client-config builder) ────────────────────────
// The server injects the configured base path via window.DOH_ENDPOINT
// (path obfuscation); default to /dns-query when absent.
const dohPath = window.DOH_ENDPOINT || "/dns-query";

/** Loose client-side IP check (the server validates strictly). */
function looksLikeIp(value) {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(value) || /^[0-9a-fA-F:]{2,}$/.test(value);
}

/** Joins selected URL flags: "v4", "ecs", "ecs-8.8.8.8", "v4/ecs-8.8.8.8", … ("" when none). */
function flagPath(familySel, ecsSel, ecsIpSel) {
  const family = familySel.value;
  const ecs = ecsSel.value;
  const overrideIp = ecsIpSel && ecsIpSel.value ? ecsIpSel.value.trim() : "";
  // Filling the ECS IP override AUTO-ENABLES ECS (ecs-<ip> forces it on) —
  // unless ECS is explicitly set to 关闭, in which case the override is inert.
  let ecsFlag;
  if (ecs === "no-ecs") {
    ecsFlag = "no-ecs";
  } else if (overrideIp && looksLikeIp(overrideIp)) {
    ecsFlag = `ecs-${overrideIp}`;
  } else {
    ecsFlag = ecs;
  }
  return [family, ecsFlag].filter(Boolean).join("/");
}

// Selecting an address family auto-switches the record type to match:
// 仅IPv6 → AAAA, 仅IPv4 → A (when the type is an address type / ANY / empty).
if (familySelect) {
  familySelect.addEventListener("change", () => {
    const type = (typeInput.value || "").trim().toUpperCase();
    if (familySelect.value === "v6" && (type === "" || type === "A" || type === "ANY")) {
      typeInput.value = "AAAA";
    } else if (familySelect.value === "v4" && (type === "" || type === "AAAA" || type === "ANY")) {
      typeInput.value = "A";
    }
  });
}

function renderEndpoint() {
  const flags = flagPath(
    epFamily || { value: "" },
    epEcs || { value: "" },
    epEcsIp || { value: "" },
  );
  const endpoint = `${location.origin}${dohPath}${flags ? "/" + flags : ""}`;
  if (endpointCode) endpointCode.textContent = endpoint;
  return endpoint;
}

let currentEndpoint = renderEndpoint();
if (epFamily) epFamily.addEventListener("change", () => (currentEndpoint = renderEndpoint()));
if (epEcs) epEcs.addEventListener("change", () => (currentEndpoint = renderEndpoint()));
if (epEcsIp) epEcsIp.addEventListener("input", () => (currentEndpoint = renderEndpoint()));

if (copyButton) {
  copyButton.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(currentEndpoint);
      copyButton.textContent = "已复制 ✓";
      setTimeout(() => (copyButton.textContent = "复制"), 1500);
    } catch {
      copyButton.textContent = "复制失败";
    }
  });
}

// ── DNS record formatting ───────────────────────────────────────────────
const TYPE_NAMES = {
  1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT",
  28: "AAAA", 33: "SRV", 43: "DS", 46: "RRSIG", 48: "DNSKEY", 52: "TLSA",
  64: "SVCB", 65: "HTTPS", 257: "CAA",
};

const RCODE = {
  0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP",
  5: "REFUSED", 6: "YXDOMAIN", 7: "YXRRSET", 8: "NXRRSET", 9: "NOTAUTH",
  10: "NOTZONE", 16: "BADVERS", 17: "BADKEY", 18: "BADTIME",
};

/** Colored badge per record type (borrowed CF-Workers-DoH badge scheme). */
const BADGES = {
  1: { label: "A", cls: "b-A" },
  28: { label: "AAAA", cls: "b-AAAA" },
  5: { label: "CNAME", cls: "b-CNAME" },
  2: { label: "NS", cls: "b-NS" },
  6: { label: "SOA", cls: "b-SOA" },
};
function typeMeta(type) {
  return BADGES[type] || { label: TYPE_NAMES[type] || `TYPE${type}`, cls: "b-other" };
}

/** Returns an array of text fragments for a record, rendered as <span class="record-part">. */
function formatRecord(record) {
  const type = TYPE_NAMES[record.type] || `TYPE${record.type}`;
  const data = String(record.data || "");

  switch (type) {
    case "MX": {
      const [prio, host] = data.split(/\s+/);
      return [["优先级", prio], ["", host]];
    }
    case "SRV": {
      const [prio, weight, port, target] = data.split(/\s+/);
      return [["优先级", prio], ["权重", weight], ["端口", port], ["", target]];
    }
    case "CAA": {
      const [flags, tag, ...value] = data.split(/\s+/);
      return [["标记", flags], ["标签", tag], ["值", value.join(" ")]];
    }
    case "SOA": {
      const parts = data.split(/\s+/);
      if (parts.length >= 7) {
        return [
          ["主服务器", parts[0]], ["负责人", parts[1]],
          ["序列号", parts[2]], ["刷新", parts[3]],
          ["重试", parts[4]], ["过期", parts[5]], ["最小TTL", parts[6]],
        ];
      }
      return [["", data]];
    }
    case "TXT":
      // Google wraps TXT data in quotes; strip them for readability.
      return [["", data.replace(/^"|"$/g, "").replace(/""/g, '"')]];
    case "HTTPS":
    case "SVCB": {
      const [prio, target, ...params] = data.split(/\s+/);
      return [["优先级", prio], ["目标", target], ["参数", params.join(" ")]];
    }
    default:
      return [["", data]];
  }
}

function humanizeTtl(seconds) {
  const s = Number(seconds);
  if (!Number.isFinite(s) || s < 0) return "-";
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m${s % 60 ? " " + (s % 60) + "s" : ""}`;
  if (s < 86400) return `${Math.floor(s / 3600)}h`;
  return `${Math.floor(s / 86400)}d`;
}

// ── Safe DOM rendering (never innerHTML with external data) ─────────────
function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

/** Copies text to the clipboard with a brief ✓ feedback on the element. */
function copyText(text, targetEl) {
  if (!navigator.clipboard) return;
  navigator.clipboard.writeText(text).then(() => {
    if (!targetEl) return;
    targetEl.classList.add("copied");
    setTimeout(() => targetEl.classList.remove("copied"), 1500);
  }).catch(() => {
    /* clipboard blocked (http / permissions): ignore */
  });
}

/** Optional geo info for an IP (HTTPS + CORS, no key); fails silently. */
function loadGeo(ip, container) {
  fetch(`https://ipwho.is/${encodeURIComponent(ip)}`)
    .then((r) => (r.ok ? r.json() : null))
    .then((d) => {
      container.textContent = "";
      container.classList.remove("geo-loading");
      if (!d || d.success === false) return;
      if (d.country) container.append(el("span", "geo-country", d.country));
      if (d.connection && d.connection.asn) container.append(el("span", "geo-as", `AS${d.connection.asn}`));
    })
    .catch(() => {
      container.textContent = "";
      container.classList.remove("geo-loading");
    });
}

/** CF-style record card row: copyable value + colored badge + TTL + geo. */
function renderRecordRow(record) {
  const row = el("div", "record");

  const value = el("span", "ip", record.data === undefined ? "" : String(record.data));
  value.title = "点击复制";
  value.addEventListener("click", () => copyText(value.textContent.trim(), value));

  const meta = typeMeta(Number(record.type));
  const badge = el("span", `badge ${meta.cls}`, meta.label);

  const ttl = el("span", "ttl", `TTL: ${humanizeTtl(record.TTL)}`);
  row.append(value, badge, ttl);

  const data = String(record.data || "");
  if ((record.type === 1 || record.type === 28) && looksLikeIp(data)) {
    const geo = el("span", "geo-info geo-loading", "正在获取位置信息…");
    row.append(geo);
    loadGeo(data, geo);
  }
  return row;
}

function renderTable(title, records) {
  const frag = document.createDocumentFragment();
  frag.append(el("div", "section-title", title));
  const container = el("div", "records");
  for (const r of records) container.append(renderRecordRow(r));
  frag.append(container);
  return frag;
}

function setBanner(kind, message) {
  const banner = el("div", `banner ${kind}`, message);
  results.replaceChildren(banner);
  if (copyResultBtn) copyResultBtn.style.display = "none";
}

if (copyResultBtn) {
  copyResultBtn.addEventListener("click", async () => {
    if (!lastRawJson) return;
    try {
      await navigator.clipboard.writeText(lastRawJson);
      copyResultBtn.textContent = "已复制 ✓";
      setTimeout(() => (copyResultBtn.textContent = "复制结果"), 1500);
    } catch { /* clipboard blocked: ignore */ }
  });
}

// ── Provider selection ──────────────────────────────────────────────────
function toggleCustomDoh() {
  if (customDoh) customDoh.hidden = dohProvider.value !== "custom";
}

function selectedProvider() {
  const value = dohProvider.value;
  if (value === "current") return { base: "", isCurrent: true, label: "当前站点" };
  if (value === "custom") {
    const u = (customDoh.value || "").trim();
    return { base: u, isCurrent: false, label: u || "自定义" };
  }
  return { base: value, isCurrent: false, label: value };
}

/**
 * Builds the dns-json URL for the selected provider.
 * Current site: same-origin /dns-query-json with our URL flags
 * (v4/v6/ecs/no-ecs/ecs-<ip>); third-party: their endpoint + name/type/do/cd.
 */
function jsonQueryUrl(provider, params) {
  if (provider.isCurrent) {
    const flags = flagPath(familySelect || { value: "" }, ecsSelect || { value: "" }, ecsIpInput || { value: "" });
    return `/dns-query-json${flags ? "/" + flags : ""}?${params.toString()}`;
  }
  return `${provider.base}?${params.toString()}`;
}

/** Fetches one dns-json query from the selected provider. */
async function fetchJson(provider, name, type) {
  const params = new URLSearchParams({ name, type });
  if (doCheckbox.checked) params.set("do", "1");
  if (cdCheckbox.checked) params.set("cd", "1");
  const res = await fetch(jsonQueryUrl(provider, params), {
    headers: { Accept: "application/dns-json" },
  });
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(`HTTP ${res.status}${body ? `: ${body.slice(0, 200)}` : ""}`);
  }
  return res.json();
}

// ── Query flow ──────────────────────────────────────────────────────────
form.addEventListener("submit", async (event) => {
  event.preventDefault();

  const name = domainInput.value.trim();
  const type = (typeInput.value.trim() || "A").toUpperCase();
  if (!name) {
    setBanner("err", "请输入要查询的域名。");
    domainInput.focus();
    return;
  }

  const provider = selectedProvider();
  if (!provider.isCurrent && !/^https:\/\//i.test(provider.base)) {
    setBanner("err", "请选择有效的 DoH 服务，或在「自定义」中填写 https:// 开头的 dns-json 地址。");
    return;
  }

  results.replaceChildren(el("p", "placeholder", "查询中…"));
  submitButton.disabled = true;
  buttonText.style.display = "none";
  spinner.style.display = "inline-block";
  const startedAt = performance.now();

  try {
    if (type === "ALL") {
      const settled = await Promise.allSettled(
        ["A", "AAAA", "NS"].map((t) => fetchJson(provider, name, t)),
      );
      renderAllResult(settled, name, provider, Math.round(performance.now() - startedAt));
    } else {
      const data = await fetchJson(provider, name, type);
      renderResult(data, Math.round(performance.now() - startedAt), provider.label);
    }
  } catch (err) {
    setBanner("err", `查询失败: ${err.message}${provider.isCurrent ? "" : "（第三方服务需支持 CORS，失败时请改用「当前站点」）"}`);
  } finally {
    submitButton.disabled = false;
    buttonText.style.display = "inline-block";
    spinner.style.display = "none";
  }
});

function statusName(status) {
  return RCODE[Number(status)] || `RCODE${status}`;
}

function renderResult(data, elapsedMs, providerLabel) {
  const frag = document.createDocumentFragment();
  const status = Number(data.Status);
  const statusName_ = statusName(status);

  const bannerKind = status === 0 ? "ok" : status === 3 ? "warn" : "err";
  const bannerMsg =
    status === 0
      ? `查询成功 (${statusName_})`
      : status === 3
        ? `域名不存在 (${statusName_})`
        : `查询异常 (${statusName_})`;
  frag.append(el("div", `banner ${bannerKind}`, bannerMsg));

  const meta = el("div", "meta");
  meta.append(el("span", null, `耗时: ${elapsedMs} ms`));
  if (providerLabel) meta.append(el("span", null, `服务: ${providerLabel}`));
  meta.append(el("span", null, `RCODE: ${status} (${statusName_})`));
  if (data.Question && data.Question[0]) {
    meta.append(el("span", null, `${data.Question[0].name} ${TYPE_NAMES[data.Question[0].type] || data.Question[0].type}`));
  }
  frag.append(meta);

  if (data.Answer && data.Answer.length) frag.append(renderTable("应答 (Answer)", data.Answer));
  if (data.Authority && data.Authority.length) frag.append(renderTable("权威 (Authority)", data.Authority));
  if (data.Additional && data.Additional.length) frag.append(renderTable("附加 (Additional)", data.Additional));
  if (!data.Answer && !data.Authority && !data.Additional) {
    frag.append(el("p", "placeholder", "该查询没有返回任何记录。"));
  }

  frag.append(rawDetails(data));
  lastRawJson = JSON.stringify(data, null, 2);
  if (copyResultBtn) copyResultBtn.style.display = "inline-block";
  results.replaceChildren(frag);
}

function rawDetails(data) {
  const raw = document.createElement("details");
  raw.className = "raw";
  raw.append(el("summary", null, "查看原始 JSON"));
  raw.append(el("pre", "raw-json", JSON.stringify(data, null, 2)));
  return raw;
}

/** Renders a banner + meta line shared by the tabbed ALL-mode view. */
function allResultBanner(settled, name, providerLabel, elapsedMs) {
  const frag = document.createDocumentFragment();
  const failures = settled.filter((s) => s.status === "rejected").length;
  const bannerKind = failures === 3 ? "err" : failures > 0 ? "warn" : "ok";
  const bannerMsg = failures === 3
    ? "A / AAAA / NS 全部查询失败"
    : failures > 0
      ? `A / AAAA / NS 并行查询完成（${failures} 项失败，见各分页）`
      : "A / AAAA / NS 并行查询成功";
  frag.append(el("div", `banner ${bannerKind}`, bannerMsg));

  const meta = el("div", "meta");
  meta.append(el("span", null, `耗时: ${elapsedMs} ms`));
  meta.append(el("span", null, `服务: ${providerLabel}`));
  meta.append(el("span", null, `域名: ${name}`));
  frag.append(meta);
  return frag;
}

/** Tabbed results for the parallel A/AAAA/NS lookup (borrowed UX). */
function renderAllResult(settled, name, provider, elapsedMs) {
  const frag = document.createDocumentFragment();
  frag.append(allResultBanner(settled, name, provider.label, elapsedMs));

  const [aJson, aaaaJson, nsJson] = settled.map((s) => (s.status === "fulfilled" ? s.value : null));

  // Tab bar
  const tabs = el("div", "tabs");
  const tabDefs = [
    ["ipv4", "IPv4 地址"],
    ["ipv6", "IPv6 地址"],
    ["ns", "NS 记录"],
    ["raw", "原始数据"],
  ];
  const tabButtons = [];
  for (const [key, label] of tabDefs) {
    const b = el("button", "tab" + (key === "ipv4" ? " active" : ""), label);
    b.type = "button";
    b.dataset.pane = key;
    tabs.append(b);
    tabButtons.push(b);
  }
  frag.append(tabs);

  const panes = {
    ipv4: el("div", "pane"),
    ipv6: el("div", "pane hidden"),
    ns: el("div", "pane hidden"),
    raw: el("div", "pane hidden"),
  };
  tabs.addEventListener("click", (e) => {
    const btn = e.target.closest(".tab");
    if (!btn) return;
    for (const b of tabButtons) b.classList.toggle("active", b === btn);
    for (const key of Object.keys(panes)) panes[key].classList.toggle("hidden", key !== btn.dataset.pane);
  });

  // IPv4 / IPv6 panes: all records returned by the A / AAAA query
  // (may include CNAME chains), NS pane: NS + SOA records from the NS query.
  fillPane(panes.ipv4, aJson, "A", "未找到 A 记录（或查询失败）");
  fillPane(panes.ipv6, aaaaJson, "AAAA", "未找到 AAAA 记录（或查询失败）");
  fillPaneNs(panes.ns, nsJson);

  // Raw pane: merged Google-style payload.
  const merged = { Status: null, Question: [], Answer: [], Authority: [], Additional: [] };
  for (const j of [aJson, aaaaJson, nsJson]) {
    if (!j) continue;
    if (typeof j.Status === "number" && merged.Status === null) merged.Status = j.Status;
    for (const key of ["Question", "Answer", "Authority", "Additional"]) {
      if (Array.isArray(j[key])) merged[key].push(...j[key]);
    }
  }
  panes.raw.append(el("pre", "raw-json", JSON.stringify(merged, null, 2)));
  lastRawJson = JSON.stringify(merged, null, 2);
  if (copyResultBtn) copyResultBtn.style.display = "inline-block";

  for (const key of Object.keys(panes)) frag.append(panes[key]);
  results.replaceChildren(frag);
}

function fillPane(pane, json, title, emptyText) {
  pane.textContent = "";
  const answers = json && Array.isArray(json.Answer) ? json.Answer : [];
  const status = json && typeof json.Status === "number" ? Number(json.Status) : null;
  if (status !== null && status !== 0) {
    pane.append(el("div", `banner ${status === 3 ? "warn" : "err"}`, `${title} 查询失败 (${statusName(status)})`));
  } else if (answers.length === 0) {
    pane.append(el("p", "placeholder", emptyText));
  } else {
    pane.append(renderTable(`${title} 记录`, answers));
  }
}

function fillPaneNs(pane, json) {
  pane.textContent = "";
  const answers = [];
  if (json) {
    for (const key of ["Answer", "Authority"]) {
      if (Array.isArray(json[key])) answers.push(...json[key]);
    }
  }
  const nsSoa = answers.filter((r) => r.type === 2 || r.type === 6);
  const status = json && typeof json.Status === "number" ? Number(json.Status) : null;
  if (status !== null && status !== 0 && nsSoa.length === 0) {
    pane.append(el("div", `banner ${status === 3 ? "warn" : "err"}`, `NS 查询失败 (${statusName(status)})`));
  } else if (nsSoa.length === 0) {
    pane.append(el("p", "placeholder", "未找到 NS/SOA 记录（或查询失败）"));
  } else {
    pane.append(renderTable("NS / SOA 记录", nsSoa));
  }
}

// ── Get JSON: open the raw dns-json response in a new tab ───────────────
if (getJsonBtn) {
  getJsonBtn.addEventListener("click", () => {
    const name = domainInput.value.trim();
    if (!name) {
      alert("请输入要查询的域名。");
      domainInput.focus();
      return;
    }
    const provider = selectedProvider();
    if (!provider.isCurrent && !/^https:\/\//i.test(provider.base)) {
      alert("请选择有效的 DoH 服务，或在「自定义」中填写 https:// 开头的 dns-json 地址。");
      return;
    }
    const type = (typeInput.value.trim() || "A").toUpperCase();
    const params = new URLSearchParams({ name, type });
    if (doCheckbox.checked) params.set("do", "1");
    if (cdCheckbox.checked) params.set("cd", "1");
    window.open(jsonQueryUrl(provider, params), "_blank", "noopener");
  });
}

// ── Persistence: remember the last domain / provider / custom endpoint ──
function savePrefs() {
  try {
    localStorage.setItem("lastDomain", domainInput.value);
    localStorage.setItem("lastProvider", dohProvider.value);
    localStorage.setItem("lastCustomDoh", customDoh.value);
  } catch (e) { /* storage disabled */ }
}

try {
  const lastDomain = localStorage.getItem("lastDomain");
  if (lastDomain) domainInput.value = lastDomain;
  const lastProvider = localStorage.getItem("lastProvider");
  if (lastProvider && Array.from(dohProvider.options).some((o) => o.value === lastProvider)) {
    dohProvider.value = lastProvider;
  }
  const lastCustomDoh = localStorage.getItem("lastCustomDoh");
  if (lastCustomDoh) customDoh.value = lastCustomDoh;
} catch (e) { /* storage disabled */ }

toggleCustomDoh();
domainInput.addEventListener("input", savePrefs);
if (dohProvider) {
  dohProvider.addEventListener("change", () => {
    toggleCustomDoh();
    savePrefs();
  });
}
if (customDoh) customDoh.addEventListener("input", savePrefs);

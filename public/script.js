// vercel-doh — online DNS lookup tool (vanilla JS, Bootstrap tabs).
// Directly adapted from CF-Workers-DoH's inline script (cmliu, MIT):
// the query flow, tabs, copy and TTL formatting are borrowed; the data
// wiring is changed to vercel-doh's backend:
//   - "当前站点" queries our public /dns-query-json API (v4/v6/ECS/DO/CD
//     flags come from the advanced options);
//   - third-party providers are queried directly from the browser (CORS
//     permitting) — there is NO server-side arbitrary-URL proxy;
//   - all DNS answer rendering uses createElement/textContent (never
//     innerHTML with answer data);
//   - the original hardcoded blocked-IP lists and /ip-info proxy are
//     dropped; geo info comes from ipwho.is over HTTPS + CORS.

"use strict";

const currentHost = window.location.host;
const currentProtocol = window.location.protocol;
// 当前站点 = 本站公开的 dns-json 工具 API（固定路径，非私密 DoH 端点）。
const currentDohUrl = currentProtocol + "//" + currentHost + "/dns-query-json";
const privateDohPath = window.DOH_ENDPOINT || null;

const dohSelect = document.getElementById("dohSelect");
const customDohContainer = document.getElementById("customDohContainer");
const customDoh = document.getElementById("customDoh");
const domainInput = document.getElementById("domain");
const clearBtn = document.getElementById("clearBtn");
const copyBtn = document.getElementById("copyBtn");
const loading = document.getElementById("loading");
const resultContainer = document.getElementById("resultContainer");
const errorContainer = document.getElementById("errorContainer");
const errorMessage = document.getElementById("errorMessage");
const resultPre = document.getElementById("result");
const getJsonBtn = document.getElementById("getJsonBtn");
const dohUrlDisplay = document.getElementById("dohUrlDisplay");
const currentDomain = document.getElementById("currentDomain");
// 高级选项（仅「当前站点」生效的 vercel-doh 特色）
const optFamily = document.getElementById("opt-family");
const optEcs = document.getElementById("opt-ecs");
const optEcsIp = document.getElementById("opt-ecs-ip");
const optDo = document.getElementById("opt-do");
const optCd = document.getElementById("opt-cd");
// DoH 端点配置卡（SHOW_DOH_ENDPOINT=true 时存在）
const endpointCode = document.getElementById("endpoint-code");
const copyEndpoint = document.getElementById("copy-endpoint");
const epFamily = document.getElementById("ep-family");
const epEcs = document.getElementById("ep-ecs");
const epEcsIp = document.getElementById("ep-ecs-ip");

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
    ecsFlag = "ecs-" + overrideIp;
  } else {
    ecsFlag = ecs;
  }
  return [family, ecsFlag].filter(Boolean).join("/");
}

// ── DoH endpoint builder (client-config) ────────────────────────────────
function renderEndpoint() {
  const flags = flagPath(
    epFamily || { value: "" },
    epEcs || { value: "" },
    epEcsIp || { value: "" },
  );
  const endpoint = currentProtocol + "//" + currentHost + (privateDohPath || "/dns-query") + (flags ? "/" + flags : "");
  if (endpointCode) endpointCode.textContent = endpoint;
  return endpoint;
}

let currentEndpoint = renderEndpoint();
if (epFamily) epFamily.addEventListener("change", () => (currentEndpoint = renderEndpoint()));
if (epEcs) epEcs.addEventListener("change", () => (currentEndpoint = renderEndpoint()));
if (epEcsIp) epEcsIp.addEventListener("input", () => (currentEndpoint = renderEndpoint()));

if (copyEndpoint) {
  copyEndpoint.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(currentEndpoint);
      copyEndpoint.textContent = "已复制 ✓";
      setTimeout(() => (copyEndpoint.textContent = "复制"), 1500);
    } catch {
      copyEndpoint.textContent = "复制失败";
    }
  });
}

// ── 格式化 TTL（借用 CF） ────────────────────────────────────────────────
function formatTTL(seconds) {
  const s = Number(seconds);
  if (!Number.isFinite(s) || s < 0) return "-";
  if (s < 60) return s + "秒";
  if (s < 3600) return Math.floor(s / 60) + "分钟";
  if (s < 86400) return Math.floor(s / 3600) + "小时";
  return Math.floor(s / 86400) + "天";
}

// ── IP 地理位置（浏览器直连 ipwho.is，HTTPS+CORS 无 key，失败静默）──────
function loadGeo(ip, container) {
  fetch("https://ipwho.is/" + encodeURIComponent(ip))
    .then((r) => (r.ok ? r.json() : null))
    .then((d) => {
      container.textContent = "";
      container.classList.remove("geo-loading");
      if (!d || d.success === false) return;
      if (d.country) {
        const c = document.createElement("span");
        c.className = "geo-country";
        c.textContent = d.country;
        container.append(c);
      }
      if (d.connection && d.connection.asn) {
        const a = document.createElement("span");
        a.className = "geo-as";
        a.textContent = "AS" + d.connection.asn;
        container.append(a);
      }
    })
    .catch(() => {
      container.textContent = "";
      container.classList.remove("geo-loading");
    });
}

/** 点击复制（借用 CF 交互：元素后追加“✓ 已复制”反馈）。 */
function handleCopyClick(element, textToCopy) {
  if (!navigator.clipboard) return;
  navigator.clipboard.writeText(textToCopy).then(() => {
    element.classList.add("copied");
    setTimeout(() => element.classList.remove("copied"), 1800);
  }).catch(() => { /* clipboard blocked: ignore */ });
}

// ── 记录渲染（安全 DOM，绝不 innerHTML 拼接应答数据）────────────────────
function makeBadge(type) {
  const badge = document.createElement("span");
  if (type === 5) {
    badge.className = "badge bg-success";
    badge.textContent = "CNAME";
  } else if (type === 2) {
    badge.className = "badge bg-info";
    badge.textContent = "NS";
  } else if (type === 6) {
    badge.className = "badge bg-warning";
    badge.textContent = "SOA";
  } else {
    badge.className = "badge bg-secondary";
    badge.textContent = "类型: " + type;
  }
  return badge;
}

/** 普通记录行：可复制值 + 徽章(非 A/AAAA) + 地理位置(A/AAAA) + TTL。 */
function makeRecordRow(record) {
  const row = document.createElement("div");
  row.className = "d-flex justify-content-between align-items-center";

  const value = document.createElement("span");
  value.className = "ip-address";
  const data = String(record.data === undefined ? "" : record.data);
  value.textContent = data;
  value.title = "点击复制";
  value.addEventListener("click", function () { handleCopyClick(this, data); });
  row.append(value);

  if (record.type !== 1 && record.type !== 28) row.append(makeBadge(record.type));

  if (record.type === 1 || record.type === 28) {
    const geo = document.createElement("span");
    geo.className = "geo-info geo-loading";
    geo.textContent = "正在获取位置信息...";
    row.append(geo);
    if (looksLikeIp(data)) loadGeo(data, geo);
  }

  const ttl = document.createElement("span");
  ttl.className = "text-muted ttl-info";
  ttl.textContent = "TTL: " + formatTTL(record.TTL);
  row.append(ttl);
  return row;
}

/** SOA 详情行（借用 CF 的字段拆分：主 NS / 管理邮箱 / 序列号 / 刷新 / 重试 / 过期 / 最小TTL）。 */
function makeSoaRow(record) {
  const wrapper = document.createElement("div");
  wrapper.className = "ip-record";

  const top = document.createElement("div");
  top.className = "d-flex justify-content-between align-items-center mb-2";
  const name = document.createElement("span");
  name.className = "ip-address";
  name.textContent = String(record.name || "");
  name.addEventListener("click", function () { handleCopyClick(this, name.textContent); });
  top.append(name, makeBadge(6));
  const ttl = document.createElement("span");
  ttl.className = "text-muted ttl-info";
  ttl.textContent = "TTL: " + formatTTL(record.TTL);
  top.append(ttl);
  wrapper.append(top);

  const parts = String(record.data || "").split(/\s+/);
  if (parts.length >= 7) {
    let adminEmail = parts[1].replace(".", "@");
    if (adminEmail.endsWith(".")) adminEmail = adminEmail.slice(0, -1);
    const rows = [
      ["主 NS", parts[0]],
      ["管理邮箱", adminEmail],
      ["序列号", parts[2]],
      ["刷新间隔", formatTTL(parts[3])],
      ["重试间隔", formatTTL(parts[4])],
      ["过期时间", formatTTL(parts[5])],
      ["最小 TTL", formatTTL(parts[6])],
    ];
    const detail = document.createElement("div");
    detail.className = "ps-3 small";
    for (const [label, val] of rows) {
      const line = document.createElement("div");
      const strong = document.createElement("strong");
      strong.textContent = label + ": ";
      const span = document.createElement("span");
      span.className = "ip-address";
      span.textContent = val;
      span.addEventListener("click", function () { handleCopyClick(this, val); });
      line.append(strong, span);
      detail.append(line);
    }
    wrapper.append(detail);
  }
  return wrapper;
}

function renderPane(containerId, summaryId, records, emptyText) {
  const container = document.getElementById(containerId);
  const summary = document.getElementById(summaryId);
  container.textContent = "";
  if (!records || records.length === 0) {
    summary.textContent = emptyText;
    return;
  }
  summary.textContent = "找到 " + records.length + " 条记录";
  for (const r of records) {
    const wrap = document.createElement("div");
    wrap.className = "ip-record";
    wrap.append(r.type === 6 ? makeSoaRow(r) : makeRecordRow(r));
    container.append(wrap);
  }
}

/** 展示聚合结果（CF 结构：ipv4/ipv6/ns + 原始数据）。 */
function displayRecords(data) {
  resultContainer.style.display = "block";
  errorContainer.style.display = "none";
  resultPre.textContent = JSON.stringify(data, null, 2);

  renderPane("ipv4Records", "ipv4Summary", (data.ipv4 && data.ipv4.records) || [], "未找到 IPv4 记录");
  renderPane("ipv6Records", "ipv6Summary", (data.ipv6 && data.ipv6.records) || [], "未找到 IPv6 记录");
  renderPane("nsRecords", "nsSummary", (data.ns && data.ns.records) || [], "未找到 NS/SOA 记录");

  copyBtn.style.display = "block";
}

function displayError(message) {
  resultContainer.style.display = "none";
  errorContainer.style.display = "block";
  errorMessage.textContent = message;
  copyBtn.style.display = "none";
}

// ── 查询流程 ────────────────────────────────────────────────────────────
/** 并发查询 A/AAAA/NS，聚合为 CF 的 {ipv4, ipv6, ns} 结构。 */
async function resolveAll(doh, domain, isCurrent) {
  const settled = await Promise.allSettled(
    ["A", "AAAA", "NS"].map((t) => queryDns(doh, domain, t, isCurrent)),
  );
  const aJson = settled[0].status === "fulfilled" ? settled[0].value : null;
  const aaaaJson = settled[1].status === "fulfilled" ? settled[1].value : null;
  const nsJson = settled[2].status === "fulfilled" ? settled[2].value : null;

  const nsRecords = [];
  if (nsJson) {
    for (const key of ["Answer", "Authority"]) {
      if (Array.isArray(nsJson[key])) {
        for (const r of nsJson[key]) {
          if (r.type === 2 || r.type === 6) nsRecords.push(r);
        }
      }
    }
  }
  return {
    Status: (aJson && aJson.Status) || (aaaaJson && aaaaJson.Status) || (nsJson && nsJson.Status) || 0,
    Question: [],
    Answer: [
      ...((aJson && aJson.Answer) || []),
      ...((aaaaJson && aaaaJson.Answer) || []),
      ...nsRecords,
    ],
    ipv4: { records: (aJson && aJson.Answer) || [] },
    ipv6: { records: (aaaaJson && aaaaJson.Answer) || [] },
    ns: { records: nsRecords },
  };
}

/** 单次 dns-json 查询：当前站点走 /dns-query-json{flags}，第三方直连其端点。 */
async function queryDns(doh, domain, type, isCurrent) {
  const url = new URL(doh);
  url.searchParams.set("name", domain);
  url.searchParams.set("type", type);
  if (optDo && optDo.checked) url.searchParams.set("do", "1");
  if (optCd && optCd.checked) url.searchParams.set("cd", "1");
  if (isCurrent) {
    const flags = flagPath(optFamily || { value: "" }, optEcs || { value: "" }, optEcsIp || { value: "" });
    if (flags) url.pathname = url.pathname.replace(/\/?$/, "") + "/" + flags;
  }
  const res = await fetch(url.toString(), { headers: { Accept: "application/dns-json" } });
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error("HTTP " + res.status + (body ? ": " + body.slice(0, 200) : ""));
  }
  return res.json();
}

document.getElementById("dns-form").addEventListener("submit", async function (e) {
  e.preventDefault();

  const sel = dohSelect.value;
  let doh;
  let isCurrent = false;
  if (sel === "current") {
    doh = currentDohUrl;
    isCurrent = true;
  } else if (sel === "custom") {
    doh = customDoh.value.trim();
    if (!doh) { alert("请输入自定义 DoH 地址"); return; }
  } else {
    doh = sel;
  }
  if (!/^https:\/\//i.test(doh)) {
    alert("DoH 地址必须是 https:// 开头");
    return;
  }

  const domain = domainInput.value.trim();
  if (!domain) { alert("请输入需要解析的域名"); return; }
  if (!/^[a-zA-Z0-9._-]{1,253}$/.test(domain)) { alert("域名包含非法字符"); return; }

  loading.style.display = "block";
  resultContainer.style.display = "none";
  errorContainer.style.display = "none";
  copyBtn.style.display = "none";

  try {
    const data = await resolveAll(doh, domain, isCurrent);
    displayRecords(data);
  } catch (err) {
    displayError("查询失败: " + err.message + (isCurrent ? "" : "（第三方服务需支持 CORS，失败时请改用「自动 (当前站点)」）"));
  } finally {
    loading.style.display = "none";
  }
});

// ── Get Json：新标签打开所选服务的原始 dns-json ─────────────────────────
if (getJsonBtn) {
  getJsonBtn.addEventListener("click", function () {
    const domain = domainInput.value.trim();
    if (!domain) { alert("请输入需要解析的域名"); return; }
    const sel = dohSelect.value;
    let doh;
    let isCurrent = false;
    if (sel === "current") { doh = currentDohUrl; isCurrent = true; }
    else if (sel === "custom") {
      doh = customDoh.value.trim();
      if (!doh) { alert("请输入自定义 DoH 地址"); return; }
    } else doh = sel;
    if (!/^https:\/\//i.test(doh)) { alert("DoH 地址必须是 https:// 开头"); return; }
    const url = new URL(doh);
    url.searchParams.set("name", domain);
    if (isCurrent) {
      const flags = flagPath(optFamily || { value: "" }, optEcs || { value: "" }, optEcsIp || { value: "" });
      if (flags) url.pathname = url.pathname.replace(/\/?$/, "") + "/" + flags;
      if (optDo && optDo.checked) url.searchParams.set("do", "1");
      if (optCd && optCd.checked) url.searchParams.set("cd", "1");
    }
    window.open(url.toString(), "_blank", "noopener");
  });
}

// ── 页面初始化 ──────────────────────────────────────────────────────────
if (dohSelect) {
  dohSelect.addEventListener("change", function () {
    customDohContainer.style.display = this.value === "custom" ? "block" : "none";
  });
}
if (clearBtn) {
  clearBtn.addEventListener("click", function () {
    domainInput.value = "";
    domainInput.focus();
  });
}
if (copyBtn) {
  copyBtn.addEventListener("click", function () {
    handleCopyClick(copyBtn, resultPre.textContent);
  });
}

document.addEventListener("DOMContentLoaded", function () {
  try {
    const lastDomain = localStorage.getItem("lastDomain");
    if (lastDomain) domainInput.value = lastDomain;
  } catch (e) { /* storage disabled */ }
  if (domainInput) {
    domainInput.addEventListener("input", function () {
      try { localStorage.setItem("lastDomain", this.value); } catch (e) { /* ignore */ }
    });
  }

  if (currentDomain) currentDomain.textContent = currentHost;
  if (dohUrlDisplay) {
    dohUrlDisplay.addEventListener("click", function () {
      handleCopyClick(dohUrlDisplay, currentProtocol + "//" + currentHost + "/dns-query-json");
    });
  }
  const privatePath = document.getElementById("privateDohPath");
  if (privatePath && privateDohPath) {
    privatePath.textContent = currentProtocol + "//" + currentHost + privateDohPath;
    privatePath.addEventListener("click", function () {
      handleCopyClick(privatePath, privatePath.textContent);
    });
  }
});

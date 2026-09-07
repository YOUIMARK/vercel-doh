// vercel-doh — online DNS lookup tool (vanilla JS, no dependencies).
// Queries the same-origin dns-json endpoint (/dns-query-json).

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
  // ECS IP override only applies when ECS is explicitly ON (关闭/默认 → inert).
  const ecsFlag =
    ecs === "ecs" && ecsIpSel && ecsIpSel.value && looksLikeIp(ecsIpSel.value.trim())
      ? `ecs-${ecsIpSel.value.trim()}`
      : ecs;
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

function renderRecordRow(record) {
  const tr = document.createElement("tr");
  tr.append(el("td", "name", record.name));
  tr.append(el("td", "ttl", humanizeTtl(record.TTL)));
  const typeTd = el("td", "type");
  typeTd.append(el("span", "tag", TYPE_NAMES[record.type] || `TYPE${record.type}`));
  tr.append(typeTd);
  const dataTd = el("td", "data");
  for (const [label, value] of formatRecord(record)) {
    if (!value && value !== "0") continue;
    const span = el("span", "record-part");
    if (label) {
      const strong = document.createElement("strong");
      strong.textContent = `${label}: `;
      span.append(strong);
    }
    span.append(document.createTextNode(value));
    dataTd.append(span);
  }
  tr.append(dataTd);
  return tr;
}

function renderTable(title, records) {
  const frag = document.createDocumentFragment();
  frag.append(el("div", "section-title", title));
  const table = document.createElement("table");
  table.className = "records";
  const thead = document.createElement("thead");
  const headRow = document.createElement("tr");
  for (const h of ["名称", "TTL", "类型", "数据"]) headRow.append(el("th", null, h));
  thead.append(headRow);
  table.append(thead);
  const tbody = document.createElement("tbody");
  for (const r of records) tbody.append(renderRecordRow(r));
  table.append(tbody);
  frag.append(table);
  return frag;
}

function setBanner(kind, message) {
  const banner = el("div", `banner ${kind}`, message);
  results.replaceChildren(banner);
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

  const params = new URLSearchParams({ name, type });
  if (doCheckbox.checked) params.set("do", "1");
  if (cdCheckbox.checked) params.set("cd", "1");
  // Apply the selected URL flags to this query (v4/v6/ecs/no-ecs).
  const flags = flagPath(familySelect || { value: "" }, ecsSelect || { value: "" }, ecsIpInput || { value: "" });
  const jsonPath = `/dns-query-json${flags ? "/" + flags : ""}`;

  results.replaceChildren(el("p", "placeholder", "查询中…"));
  submitButton.disabled = true;
  buttonText.style.display = "none";
  spinner.style.display = "inline-block";
  const startedAt = performance.now();

  try {
    const res = await fetch(`${jsonPath}?${params}`, {
      headers: { Accept: "application/dns-json" },
    });
    if (!res.ok) {
      const body = await res.text().catch(() => "");
      throw new Error(`HTTP ${res.status}${body ? `: ${body.slice(0, 200)}` : ""}`);
    }
    const data = await res.json();
    renderResult(data, Math.round(performance.now() - startedAt));
  } catch (err) {
    setBanner("err", `查询失败: ${err.message}`);
  } finally {
    submitButton.disabled = false;
    buttonText.style.display = "inline-block";
    spinner.style.display = "none";
  }
});

function renderResult(data, elapsedMs) {
  const frag = document.createDocumentFragment();
  const status = Number(data.Status);
  const statusName = RCODE[status] || `RCODE${status}`;

  const bannerKind = status === 0 ? "ok" : status === 3 ? "warn" : "err";
  const bannerMsg =
    status === 0
      ? `查询成功 (${statusName})`
      : status === 3
        ? `域名不存在 (${statusName})`
        : `查询异常 (${statusName})`;
  frag.append(el("div", `banner ${bannerKind}`, bannerMsg));

  const meta = el("div", "meta");
  meta.append(el("span", null, `耗时: ${elapsedMs} ms`));
  meta.append(el("span", null, `RCODE: ${status} (${statusName})`));
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

  const raw = document.createElement("details");
  raw.className = "raw";
  raw.append(el("summary", null, "查看原始 JSON"));
  raw.append(el("pre", "raw-json", JSON.stringify(data, null, 2)));
  frag.append(raw);

  results.replaceChildren(frag);
}

// Landing page: the online DNS lookup tool (markup only — styles/scripts
// are served from public/ by the Vercel CDN, and by dev.ts locally).

import type { DoHConfig } from "../config.js";

export function health() {
  return (): Response =>
    new Response("ok", {
      status: 200,
      headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" },
    });
}

export function homePage(config: DoHConfig) {
  return (): Response => {
    const dohEndpoint = config.dohPath;
    const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>vercel-doh · DNS 查询</title>
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🔎</text></svg>">
<link rel="stylesheet" href="/style.css">
<script>window.DOH_ENDPOINT=${JSON.stringify(dohEndpoint)};</script>
</head>
<body>
<div class="wrap">
  <header>
    <div class="logo">🔎</div>
    <h1>vercel-doh</h1>
    <p>DNS over HTTPS 查询工具 · v${config.appVersion}</p>
  </header>

  <section class="card">
    <h2>🔍 查询 DNS 记录</h2>
    <form id="dns-form">
      <div class="query-grid">
        <input type="text" id="domain" name="domain" placeholder="例如: example.com" autocomplete="off" autocapitalize="none" spellcheck="false" required>
        <input type="text" id="type" name="type" list="type-list" value="A" placeholder="记录类型">
        <datalist id="type-list">
          <option value="A"><option value="AAAA"><option value="CNAME"><option value="MX">
          <option value="TXT"><option value="NS"><option value="SOA"><option value="PTR">
          <option value="SRV"><option value="CAA"><option value="HTTPS"><option value="SVCB">
          <option value="DS"><option value="DNSKEY"><option value="TLSA"><option value="ANY">
        </datalist>
      </div>
      <div class="options">
        <label>地址族
          <select id="opt-family">
            <option value="">自动</option>
            <option value="v4">仅 IPv4</option>
            <option value="v6">仅 IPv6</option>
          </select>
        </label>
        <label>ECS
          <select id="opt-ecs">
            <option value="">默认</option>
            <option value="ecs">开启</option>
            <option value="no-ecs">关闭</option>
          </select>
        </label>
        <label><input type="checkbox" id="opt-do"> DNSSEC OK (DO)</label>
        <label><input type="checkbox" id="opt-cd"> 禁用 DNSSEC 校验 (CD)</label>
      </div>
      <div style="margin-top:0.9rem">
        <button type="submit" id="submit-button">
          <span id="button-text">查询</span><span class="spinner" id="spinner"></span>
        </button>
      </div>
    </form>
  </section>

  <section class="card">
    <h2>🛡 DoH 端点(配置到客户端)</h2>
    <div class="endpoint-row">
      <code class="endpoint" id="endpoint-code">…</code>
      <button type="button" class="copy-btn" id="copy-endpoint">复制</button>
    </div>
    <div class="options" style="margin-top:0.7rem">
      <label>地址族
        <select id="ep-family">
          <option value="">自动</option>
          <option value="v4">仅 IPv4</option>
          <option value="v6">仅 IPv6</option>
        </select>
      </label>
      <label>ECS
        <select id="ep-ecs">
          <option value="">默认</option>
          <option value="ecs">开启</option>
          <option value="no-ecs">关闭</option>
        </select>
      </label>
    </div>
    <p class="hint">浏览器安全 DNS / AdGuard / dnscrypt-proxy / stubby / <code>dig +https</code> 均可使用。<br>
    端点路径: <code>${dohEndpoint}</code> · 上方下拉会拼出带 flag 的端点(如 <code>${dohEndpoint}/v4/ecs</code>),URL 优先于环境变量;上方查询表单的「地址族/ECS」下拉作用于本次查询。</p>
  </section>

  <section class="card">
    <h2>📋 查询结果</h2>
    <div id="results">
      <p class="placeholder">输入域名并点击「查询」。</p>
    </div>
  </section>

  <footer>vercel-doh v${config.appVersion} · 部署于 Vercel(Hono + Node.js + Fluid compute)</footer>
</div>
<script src="/script.js"></script>
</body>
</html>`;
    return new Response(html, {
      status: 200,
      headers: {
        "Content-Type": "text/html; charset=utf-8",
        "Cache-Control": "public, s-maxage=60",
      },
    });
  };
}

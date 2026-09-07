// Landing page: the online DNS lookup tool (markup only — styles/scripts
// are served from public/ by the Vercel CDN, and by dev.ts locally).

import type { DoHConfig } from "../config";

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
    <p class="hint">浏览器安全 DNS / AdGuard / dnscrypt-proxy / stubby / <code>dig +https</code> 均可使用。<br>
    端点路径: <code>${dohEndpoint}</code> · 查询仅转发给 1 个上游,默认不附加 ECS,保护隐私。</p>
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

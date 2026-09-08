// Landing page: the online DNS lookup tool (markup only — styles/scripts
// are served from public/ by the Vercel CDN, and by dev.ts locally).
//
// The page structure, classes and visual design are DIRECTLY BORROWED from
// CF-Workers-DoH (cmliu, MIT) — Bootstrap 5.3 + its original CSS — and only
// the data wiring is adapted to vercel-doh's backend:
//   - queries go to our own /dns-query-json (current site); third-party
//     providers go through the server-side /dns-query-proxy endpoint
//     (mirrors CF-Workers-DoH's ?doh= handler, no CORS wall, no client
//     headers forwarded);
//   - the original innerHTML-with-answer-data rendering is replaced by
//     createElement/textContent (see public/script.js);
//   - the original hardcoded "blocked IP" lists and /ip-info proxy are
//     dropped; geo info comes from ipwho.is in the browser.

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
    // The DoH path is an obfuscation secret — the frontend only shows it when
    // SHOW_DOH_ENDPOINT=true (default: hidden). The JSON tool API
    // (/dns-query-json) is public by design.
    const endpointScript = config.showDohEndpoint
      ? `<script>window.DOH_ENDPOINT=${JSON.stringify(dohEndpoint)};</script>`
      : "";
    const endpointCard = config.showDohEndpoint
      ? `<div class="card">
      <div class="card-header">🛡 DoH 端点(配置到客户端)</div>
      <div class="card-body">
        <div class="endpoint-row">
          <code class="endpoint" id="endpoint-code">…</code>
          <button type="button" class="btn btn-sm btn-outline-secondary" id="copy-endpoint">复制</button>
        </div>
        <div class="advanced-options">
          <label>地址族
            <select class="form-select form-select-sm" id="ep-family">
              <option value="">自动</option>
              <option value="v4">仅 IPv4</option>
              <option value="v6">仅 IPv6</option>
            </select>
          </label>
          <label>ECS
            <select class="form-select form-select-sm" id="ep-ecs">
              <option value="">默认</option>
              <option value="ecs">开启</option>
              <option value="no-ecs">关闭</option>
            </select>
          </label>
          <label>ECS IP 覆盖
            <input type="text" class="form-control form-control-sm" id="ep-ecs-ip" placeholder="如 8.8.8.8(填写即自动开启 ECS)" autocomplete="off" spellcheck="false" style="width:12rem">
          </label>
        </div>
        <p class="hint">浏览器安全 DNS / AdGuard / dnscrypt-proxy / stubby / <code>dig +https</code> 均可使用。
        端点路径: <code>${dohEndpoint}</code> · 上方下拉拼出带 flag 的端点(如 <code>${dohEndpoint}/v4/ecs-8.8.8.8</code>),URL 优先于环境变量。</p>
      </div>
    </div>`
      : "";
    const html = `<!DOCTYPE html>
<html lang="zh-CN">

<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="referrer" content="no-referrer">
  <title>DNS-over-HTTPS Resolver</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css"
    integrity="sha384-9ndCyUaIbzAi2FUVXJi0CjmCapSmO7SnpJef0486qhLnuZ2cdeRhO02iuK6FUUVM" crossorigin="anonymous">
  <link rel="icon"
    href="https://cf-assets.www.cloudflare.com/dzlvafdwdttg/6TaQ8Q7BDmdAFRoHpDCb82/8d9bc52a2ac5af100de3a9adcf99ffaa/security-shield-protection-2.svg"
    type="image/x-icon">
  <link rel="stylesheet" href="/style.css">
  ${endpointScript}
</head>

<body>
  <a href="https://github.com/YOUIMARK/vercel-doh" target="_blank" class="github-corner" aria-label="View source on Github">
    <svg viewBox="0 0 250 250" aria-hidden="true">
      <path d="M0,0 L115,115 L130,115 L142,142 L250,250 L250,0 Z"></path>
      <path
        d="M128.3,109.0 C113.8,99.7 119.0,89.6 119.0,89.6 C122.0,82.7 120.5,78.6 120.5,78.6 C119.2,72.0 123.4,76.3 123.4,76.3 C127.3,80.9 125.5,87.3 125.5,87.3 C122.9,97.6 130.6,101.9 134.4,103.2"
        fill="currentColor" style="transform-origin: 130px 106px;" class="octo-arm"></path>
      <path
        d="M115.0,115.0 C114.9,115.1 118.7,116.5 119.8,115.4 L133.7,101.6 C136.9,99.2 139.9,98.4 142.2,98.6 C133.8,88.0 127.5,74.4 143.8,58.0 C148.5,53.4 154.0,51.2 159.7,51.0 C160.3,49.4 163.2,43.6 171.4,40.1 C171.4,40.1 176.1,42.5 178.8,56.2 C183.1,58.6 187.2,61.8 190.9,65.4 C194.5,69.0 197.7,73.2 200.1,77.6 C213.8,80.2 216.3,84.9 216.3,84.9 C212.7,93.1 206.9,96.0 205.4,96.6 C205.1,102.4 203.0,107.8 198.3,112.5 C181.9,128.9 168.3,122.5 157.7,114.1 C157.9,116.9 156.7,120.9 152.7,124.9 L141.0,136.5 C139.8,137.7 141.6,141.9 141.8,141.8 Z"
        fill="currentColor" class="octo-body"></path>
    </svg>
  </a>
  <div class="container">
    <h1 class="text-center mb-4">DNS-over-HTTPS Resolver</h1>
    <div class="card">
      <div class="card-header">DNS 查询设置</div>
      <div class="card-body">
        <form id="dns-form">
          <div class="mb-3">
            <label for="dohSelect" class="form-label">选择 DoH 地址:</label>
            <select id="dohSelect" class="form-select">
              <option value="current" selected id="currentDohOption">自动 (当前站点)</option>
              <option value="https://dns.alidns.com/resolve">https://dns.alidns.com/resolve (阿里)</option>
              <option value="https://sm2.doh.pub/dns-query">https://sm2.doh.pub/dns-query (腾讯)</option>
              <option value="https://cloudflare-dns.com/dns-query">https://cloudflare-dns.com/dns-query (Cloudflare)</option>
              <option value="https://dns.google/resolve">https://dns.google/resolve (谷歌)</option>
              <option value="https://dns.adguard-dns.com/resolve">https://dns.adguard-dns.com/resolve (AdGuard)</option>
              <option value="https://dns.nextdns.io">https://dns.nextdns.io (NextDNS)</option>
              <option value="https://dns.opendns.com/dns-query">https://dns.opendns.com/dns-query (OpenDNS)</option>
              <option value="custom">自定义...</option>
            </select>
          </div>
          <div id="customDohContainer" class="mb-3" style="display:none;">
            <label for="customDoh" class="form-label">输入自定义 DoH 地址:</label>
            <input type="text" id="customDoh" class="form-control" placeholder="https://example.com/resolve（dns-json 端点）">
          </div>
          <div class="mb-3">
            <label for="domain" class="form-label">待解析域名:</label>
            <div class="input-group">
              <input type="text" id="domain" class="form-control" value="example.com"
                placeholder="输入域名，如 example.com" autocomplete="off" autocapitalize="none" spellcheck="false">
              <button type="button" class="btn btn-outline-secondary" id="clearBtn">清除</button>
            </div>
          </div>
          <div class="d-flex gap-2">
            <button type="submit" class="btn btn-primary flex-grow-1">解析</button>
            <button type="button" class="btn btn-outline-primary" id="getJsonBtn">Get Json</button>
          </div>
        </form>
      </div>
    </div>

    ${endpointCard}

    <div class="card">
      <div class="card-header d-flex justify-content-between align-items-center">
        <span>解析结果</span>
        <button class="btn btn-sm btn-outline-secondary" id="copyBtn" style="display: none;">复制结果</button>
      </div>
      <div class="card-body">
        <div id="loading" class="loading">
          <div class="loading-spinner"></div>
          <p>正在查询中，请稍候...</p>
        </div>

        <div id="resultContainer" style="display: none;">
          <ul class="nav nav-tabs result-tabs" id="resultTabs" role="tablist">
            <li class="nav-item" role="presentation">
              <button class="nav-link active" id="ipv4-tab" data-bs-toggle="tab" data-bs-target="#ipv4" type="button"
                role="tab">IPv4 地址</button>
            </li>
            <li class="nav-item" role="presentation">
              <button class="nav-link" id="ipv6-tab" data-bs-toggle="tab" data-bs-target="#ipv6" type="button"
                role="tab">IPv6 地址</button>
            </li>
            <li class="nav-item" role="presentation">
              <button class="nav-link" id="ns-tab" data-bs-toggle="tab" data-bs-target="#ns" type="button"
                role="tab">NS 记录</button>
            </li>
            <li class="nav-item" role="presentation">
              <button class="nav-link" id="raw-tab" data-bs-toggle="tab" data-bs-target="#raw" type="button"
                role="tab">原始数据</button>
            </li>
          </ul>
          <div class="tab-content" id="resultTabContent">
            <div class="tab-pane fade show active" id="ipv4" role="tabpanel" aria-labelledby="ipv4-tab">
              <div class="result-summary" id="ipv4Summary"></div>
              <div id="ipv4Records"></div>
            </div>
            <div class="tab-pane fade" id="ipv6" role="tabpanel" aria-labelledby="ipv6-tab">
              <div class="result-summary" id="ipv6Summary"></div>
              <div id="ipv6Records"></div>
            </div>
            <div class="tab-pane fade" id="ns" role="tabpanel" aria-labelledby="ns-tab">
              <div class="result-summary" id="nsSummary"></div>
              <div id="nsRecords"></div>
            </div>
            <div class="tab-pane fade" id="raw" role="tabpanel" aria-labelledby="raw-tab">
              <pre id="result">等待查询...</pre>
            </div>
          </div>
        </div>

        <div id="errorContainer" style="display: none;">
          <pre id="errorMessage" class="error-message"></pre>
        </div>
      </div>
    </div>

    <div class="beian-info">
      <p>基于 vercel-doh（Hono + Node.js + Fluid compute）的 DoH (DNS over HTTPS) 解析服务</p>
      <p class="footer-attrib">UI 直接借用 <a href="https://github.com/cmliu/CF-Workers-DoH" target="_blank"
          rel="noopener">CF-Workers-DoH</a> · 源码 <a href="https://github.com/YOUIMARK/vercel-doh" target="_blank"
          rel="noopener">YOUIMARK/vercel-doh</a></p>
    </div>
  </div>

  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"
    integrity="sha384-geWF76RCwLtnZ8qwWowPQNguL3RmwHVBC9FhGdlKrxdiJJigb/j/68SIy3Te4Bkz" crossorigin="anonymous"></script>
  <script src="/script.js"></script>
</body>

</html>`;
    return new Response(html, {
      status: 200,
      headers: {
        "Content-Type": "text/html; charset=utf-8",
        "Cache-Control": "public, s-maxage=60",
        // Defense-in-depth: pin scripts/styles to self + the SRI-checked CDN,
        // allow the browser geo lookup (ipwho.is), and lock framing.
        "Content-Security-Policy":
          "default-src 'self'; " +
          "script-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; " +
          "style-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; " +
          "img-src 'self' https: data:; " +
          "connect-src 'self' https://ipwho.is; " +
          "font-src 'self' https://cdn.jsdelivr.net data:; " +
          "object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'",
      },
    });
  };
}

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
    // The DoH path is an obfuscation secret — the frontend only shows it when
    // SHOW_DOH_ENDPOINT=true (default: hidden).
    const endpointScript = config.showDohEndpoint
      ? `<script>window.DOH_ENDPOINT=${JSON.stringify(dohEndpoint)};</script>`
      : "";
    const endpointCard = config.showDohEndpoint
      ? `<section class="card">
    <h2>🛡 DoH 端点(配置到客户端)</h2>
    <div class="card-body">
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
        <label>ECS IP 覆盖
          <input type="text" id="ep-ecs-ip" placeholder="可选,如 8.8.8.8(填写即自动开启 ECS)" autocomplete="off" autocapitalize="none" spellcheck="false">
        </label>
      </div>
      <p class="hint">浏览器安全 DNS / AdGuard / dnscrypt-proxy / stubby / <code>dig +https</code> 均可使用。<br>
      端点路径: <code>${dohEndpoint}</code> · 上方下拉会拼出带 flag 的端点(如 <code>${dohEndpoint}/v4/ecs-8.8.8.8</code>),URL 优先于环境变量;上方查询表单的「地址族/ECS/ECS IP」作用于本次查询。</p>
    </div>
  </section>`
      : `<section class="card">
    <h2>🛡 DoH 端点</h2>
    <div class="card-body">
      <p class="hint">端点为私有路径,已在前端隐藏。设置环境变量 <code>SHOW_DOH_ENDPOINT=true</code> 后可在此显示并生成客户端配置。</p>
    </div>
  </section>`;
    const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>DNS-over-HTTPS Resolver</title>
<link rel="icon" href="https://cf-assets.www.cloudflare.com/dzlvafdwdttg/6TaQ8Q7BDmdAFRoHpDCb82/8d9bc52a2ac5af100de3a9adcf99ffaa/security-shield-protection-2.svg" type="image/x-icon">
<link rel="stylesheet" href="/style.css">
${endpointScript}
</head>
<body>
  <a href="https://github.com/YOUIMARK/vercel-doh" target="_blank" rel="noopener" class="github-corner" aria-label="View source on Github">
    <svg viewBox="0 0 250 250" aria-hidden="true">
      <path d="M0,0 L115,115 L130,115 L142,142 L250,250 L250,0 Z"></path>
      <path d="M128.3,109.0 C113.8,99.7 119.0,89.6 119.0,89.6 C122.0,82.7 120.5,78.6 120.5,78.6 C119.2,72.0 123.4,76.3 123.4,76.3 C127.3,80.9 125.5,87.3 125.5,87.3 C122.9,97.6 130.6,101.9 134.4,103.2" fill="currentColor" style="transform-origin: 130px 106px;" class="octo-arm"></path>
      <path d="M115.0,115.0 C114.9,115.1 118.7,116.5 119.8,115.4 L133.7,101.6 C136.9,99.2 139.9,98.4 142.2,98.6 C133.8,88.0 127.5,74.4 143.8,58.0 C148.5,53.4 154.0,51.2 159.7,51.0 C160.3,49.4 163.2,43.6 171.4,40.1 C171.4,40.1 176.1,42.5 178.8,56.2 C183.1,58.6 187.2,61.8 190.9,65.4 C194.5,69.0 197.7,73.2 200.1,77.6 C213.8,80.2 216.3,84.9 216.3,84.9 C212.7,93.1 206.9,96.0 205.4,96.6 C205.1,102.4 203.0,107.8 198.3,112.5 C181.9,128.9 168.3,122.5 157.7,114.1 C157.9,116.9 156.7,120.9 152.7,124.9 L141.0,136.5 C139.8,137.7 141.6,141.9 141.8,141.8 Z" fill="currentColor" class="octo-body"></path>
    </svg>
  </a>
  <div class="wrap">
    <header>
      <h1>DNS-over-HTTPS Resolver</h1>
      <p>vercel-doh v${config.appVersion} · DNS over HTTPS 查询工具</p>
    </header>

    <section class="card">
      <h2>DNS 查询设置</h2>
      <div class="card-body">
        <form id="dns-form">
          <label for="doh-provider" class="field-label">DoH 服务</label>
          <select id="doh-provider">
            <option value="current" selected>自动 (当前站点,支持 v4/v6/ECS/DO/CD)</option>
            <option value="https://dns.alidns.com/resolve">阿里 DNS (alidns.com)</option>
            <option value="https://dns.google/resolve">Google (dns.google)</option>
            <option value="https://cloudflare-dns.com/resolve">Cloudflare</option>
            <option value="https://dns.adguard-dns.com/resolve">AdGuard</option>
            <option value="custom">自定义...</option>
          </select>
          <input type="text" id="custom-doh" placeholder="https://example.com/resolve（dns-json 端点）" autocomplete="off" autocapitalize="none" spellcheck="false" hidden>
          <div class="query-grid">
            <input type="text" id="domain" name="domain" placeholder="例如: example.com" autocomplete="off" autocapitalize="none" spellcheck="false" required>
            <input type="text" id="type" name="type" list="type-list" value="A" placeholder="记录类型">
            <datalist id="type-list">
              <option value="A"><option value="AAAA"><option value="CNAME"><option value="MX">
              <option value="TXT"><option value="NS"><option value="SOA"><option value="PTR">
              <option value="SRV"><option value="CAA"><option value="HTTPS"><option value="SVCB">
              <option value="DS"><option value="DNSKEY"><option value="TLSA"><option value="ANY">
              <option value="ALL"><!-- 并行查询 A + AAAA + NS，分页展示 -->
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
            <label>ECS IP 覆盖
              <input type="text" id="opt-ecs-ip" placeholder="可选,如 8.8.8.8(填写即自动开启 ECS)" autocomplete="off" autocapitalize="none" spellcheck="false">
            </label>
            <label><input type="checkbox" id="opt-do"> DNSSEC OK (DO)</label>
            <label><input type="checkbox" id="opt-cd"> 禁用 DNSSEC 校验 (CD)</label>
          </div>
          <div class="button-row">
            <button type="submit" id="submit-button">
              <span id="button-text">解析</span><span class="spinner" id="spinner"></span>
            </button>
            <button type="button" id="get-json-btn">Get JSON</button>
          </div>
          <p class="hint">「地址族 / ECS / ECS IP」为本服务特有选项,仅对「当前站点」生效;第三方服务只传 name/type/do/cd。<code>ALL</code> 并行查询 A/AAAA/NS 并分页展示。</p>
        </form>
      </div>
    </section>

    ${endpointCard}

    <section class="card">
      <h2>解析结果
        <span class="spacer"></span>
        <button type="button" class="copy-btn" id="copy-result-btn" style="display:none">复制结果</button>
      </h2>
      <div class="card-body">
        <div id="results">
          <p class="placeholder">输入域名并点击「解析」。</p>
        </div>
      </div>
    </section>

    <footer class="footer">
      <p>vercel-doh v${config.appVersion} · 部署于 Vercel (Hono + Node.js + Fluid compute)</p>
      <p class="dim">UI 直接借用 <a href="https://github.com/cmliu/CF-Workers-DoH" target="_blank" rel="noopener">CF-Workers-DoH</a> · 源码 <a href="https://github.com/YOUIMARK/vercel-doh" target="_blank" rel="noopener">YOUIMARK/vercel-doh</a></p>
    </footer>
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

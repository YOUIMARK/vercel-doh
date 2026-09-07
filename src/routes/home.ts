// Landing page + health check.

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
    const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>vercel-doh</title>
<style>
body{font-family:system-ui,-apple-system,sans-serif;max-width:50rem;margin:3rem auto;padding:0 1.2rem;line-height:1.7;color:#222}
h1{font-size:1.8rem}code{background:#f2f2f2;padding:.1rem .4rem;border-radius:4px;font-size:.92em}
table{border-collapse:collapse;margin:1rem 0}td,th{border:1px solid #ddd;padding:.4rem .8rem;text-align:left}
.endpoint{font-family:ui-monospace,monospace;background:#0d1117;color:#7ee787;padding:.7rem 1rem;border-radius:6px;overflow-x:auto}
</style></head>
<body>
<h1>🔎 vercel-doh</h1>
<p>v${config.appVersion} — DNS over HTTPS (DoH) 转发代理,部署于 Vercel(Hono + Node.js + Fluid compute)。</p>
<p>这是一个 <b>DoH 端点</b>,请用支持 DoH 的客户端(浏览器安全 DNS、AdGuard、dnscrypt-proxy、stubby、dig +https)访问:</p>
<div class="endpoint">https://&lt;your-project&gt;.vercel.app/dns-query</div>
<h2>端点</h2>
<table>
<tr><th>路径</th><th>说明</th></tr>
<tr><td><code>/dns-query</code></td><td>标准 DoH(GET/POST),默认不附加 ECS</td></tr>
<tr><td><code>/dns-query/auto_ecs</code></td><td>强制附加 EDNS Client Subnet</td></tr>
<tr><td><code>/dns-query/no_ecs</code></td><td>强制禁用 ECS</td></tr>
<tr><td><code>/dns-query-json</code></td><td>dns-json API(在线查询工具)</td></tr>
<tr><td><code>/health</code></td><td>健康检查</td></tr>
</table>
<h2>特性</h2>
<ul>
<li>RFC 8484 兼容(GET base64url + POST dns-message)</li>
<li>多上游顺序故障转移(默认不广播,保护隐私);可选竞速模式</li>
<li>TTL 感知缓存(按应答最小 TTL 设置 s-maxage);POST / 含 ECS 一律 no-store</li>
<li>ECS 注入(并入既有 OPT RR,绝不产生重复 OPT)</li>
</ul>
<p>上游: <code>${config.upstreamUrls.join(", ")}</code></p>
</body></html>`;
    return new Response(html, {
      status: 200,
      headers: {
        "Content-Type": "text/html; charset=utf-8",
        "Cache-Control": "public, s-maxage=60",
      },
    });
  };
}

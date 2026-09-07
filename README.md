# vercel-doh

DNS over HTTPS (DoH) 转发代理,零配置部署到 **Vercel**。
技术栈:**Hono + Node.js 运行时 + Fluid compute**(Vercel 当前官方推荐组合,
Edge Functions 已对新项目弃用)。

本项目融合了 8 个开源 Vercel/边缘 DoH 项目的优点,并规避了它们各自的硬伤:
多上游**顺序故障转移**(不广播,保护隐私)、TTL 感知缓存、正确的 EDNS Client
Subnet (ECS) 注入(绝不产生重复 OPT RR)、路径映射、隐私默认值。

## 特性

- **RFC 8484 兼容**: GET `?dns=<base64url>` 与 POST `application/dns-message`
  - 正确状态码: 400 / 405 / 406 / 413 / 415 / 502;成功响应 `Content-Type: application/dns-message`
- **隐私默认值**:
  - 默认只把查询发给 **1 个**上游(轮询),失败才顺序转移,**绝不并发广播**
  - 默认**不附加 ECS**、默认**不把客户端真实 IP 转发给上游**(转发前剥离 XFF 等头)
- **健壮**: 单上游 3s 超时,5xx/网络错误自动转移下一个(最多 3 次);全部失败返回
  合法的 SERVFAIL dns-message(200),标准客户端可正常解析
- **TTL 感知缓存**: GET + NOERROR 按应答最小 TTL 设置 `s-maxage`(上限可配);
  POST / 附加了 ECS / 负应答一律 `no-store`
- **ECS 支持(默认关)**: `/dns-query/auto_ecs` 强制附加、`/dns-query/no_ecs`
  强制禁用;客户端 IP 取可信头链(`x-vercel-forwarded-for` → `x-real-ip` →
  XFF 最右段),过滤私网/保留地址,**不信任可伪造的最左段**
- **路径映射(可选)**: `/dns-query/{provider}` 经 `DOMAIN_MAPPINGS` 路由到指定上游
- **dns-json API**: `/dns-query-json?name=...&type=A`(兼容 Google DoH JSON)
- **代理卫生**: HOP_BY_HOP 头过滤、请求体上限 64KB、上游 URL 仅 https 白名单

## 快速开始

```bash
git clone <your-repo> vercel-doh && cd vercel-doh
npm install
npm run dev            # 本地 http://localhost:3000
```

部署(零配置,Hono 框架预设自动识别并启用 Fluid compute):

```bash
npm i -g vercel
vercel deploy
```

## 使用

```bash
# GET(标准 DoH)
curl "https://<your-project>.vercel.app/dns-query?dns=AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB" \
  -H "Accept: application/dns-message" | xxd

# POST
curl -X POST --data-binary @query.bin \
  -H "Content-Type: application/dns-message" \
  -H "Accept: application/dns-message" \
  "https://<your-project>.vercel.app/dns-query"

# 标准客户端(dig +https / AdGuard / dnscrypt-proxy / 浏览器安全 DNS)
# 端点: https://<your-project>.vercel.app/dns-query

# 浏览器访问 https://<your-project>.vercel.app/ 查看说明页
```

## 环境变量

| 变量 | 默认值 | 说明 |
|---|---|---|
| `UPSTREAM_DOH_URLS` | `https://cloudflare-dns.com/dns-query` | 常规上游,逗号分隔(顺序转移) |
| `ECS_UPSTREAM_DOH_URLS` | `https://dns.google/dns-query` | 请求带 ECS 时使用的上游 |
| `JSON_UPSTREAM_DOH_URLS` | `https://dns.google/resolve` | dns-json 上游 |
| `AUTO_ADD_ECS` | `false` | 全局自动附加 ECS(默认关,隐私) |
| `IPV4_ECS_PREFIX_LENGTH` | `24` | ECS IPv4 前缀长度(0–32) |
| `IPV6_ECS_PREFIX_LENGTH` | `56` | ECS IPv6 前缀长度(0–128) |
| `CACHE_MAX_AGE` | `300` | GET 缓存 `s-maxage` 上限(秒) |
| `RACE_UPSTREAMS` | `false` | `true` 时并发竞速所有上游(最快者胜,牺牲隐私换延迟) |
| `UPSTREAM_TIMEOUT_MS` | `3000` | 单上游超时(500–30000) |
| `FORCE_RESPONSE_PADDING` | `false` | RFC 8467 响应填充(并入响应 OPT RR) |
| `DOMAIN_MAPPINGS` | `{}` | 路径映射 JSON,如 `{"google":{"targetDomain":"dns.google"}}` |
| `DEBUG_LOGGING` | `false` | 输出调试日志(注意: 不打印查询内容) |
| `APP_VERSION` | `1.0.0` | 信息页展示的版本号 |

## 测试

```bash
npm test          # vitest,71 个用例: wire/ecs/ttl/padding/cache-control/upstream/routes
npx tsc --noEmit  # 严格类型检查
```

关键回归用例:

- ECS 注入:**已有 OPT RR 时并入同一 OPT(ARCOUNT 不变、全报文仅 1 个 OPT)**,
  这是对常见"重复 OPT RR"bug 的显式防护
- 上游策略: 默认**不并发**、按序转移、全失败抛错;竞速模式取最快成功响应
- 缓存四象限: GET/POST/含 ECS/负应答
- 客户端 IP: XFF 最右段(防伪造)、私网过滤、IPv6 解析

## 架构

```
请求 → Hono 路由(/dns-query, /dns-query/auto_ecs, /dns-query/no_ecs,
                  /dns-query/{provider}, /dns-query-json, /health, /)
  → 校验(方法/Accept/Content-Type/体积) → [可选 ECS 注入]
  → 上游选择(轮询 → 顺序故障转移,或竞速) → fetch(3s 超时)
  → 解析应答 TTL → Cache-Control → application/dns-message 响应
```

```
src/
├── config.ts          # 唯一配置源(环境变量解析 + 校验)
├── upstream.ts        # 上游选择/故障转移/竞速 + 头过滤
├── cache-control.ts   # RFC 8484 + TTL 感知缓存策略
├── errors.ts          # SERVFAIL 报文 / 文本错误
├── log.ts             # 调试日志(默认关闭)
├── dns/
│   ├── wire.ts        # base64url、DNS 头/压缩指针/RR 遍历
│   ├── ecs.ts         # ECS 检测 + 注入(并入既有 OPT)
│   ├── ttl.ts         # 最小 TTL 提取
│   ├── padding.ts     # RFC 8467 填充
│   └── ip.ts          # IPv4/IPv6 解析 + 私网过滤
├── routes/            # dns-query / json / home 处理器
└── app.ts             # Hono 应用组装
```

## 生产化建议(如需公开服务)

- 在 Vercel Dashboard 开启 **WAF/Firewall** 或叠加 [Vercel Firewall](https://vercel.com/docs/firewall)
  限制来源,防滥用
- 如被爬虫探测,可把 DoH 路径改到非标准路径(修改 `vercel.json` rewrite)
- 需要鉴权时,可叠加 `x-doh-token` 头校验(本项目刻意保持无状态、零依赖)

## 为什么不用 Go / Edge / Next.js

- **Edge Functions**: 已被 Vercel 标记"对新项目弃用",且无 Fluid 优化
- **Go**: 每次调用 CPU 更低,但 DoH 转发是 I/O 密集,CPU 优势用不上;反而吃不到
  Fluid 的函数内并发/字节码缓存,还要承担 microVM 冷启动与闲置归档
- **Next.js**: 对单个 DoH 端点过重(构建 + 大 bundle)

> 详见本项目调研文档 `../vercel-doh-comparison.md` 与 `.trellis/tasks/09-07-doh-hono/`。

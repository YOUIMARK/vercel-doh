# vercel-doh

DNS over HTTPS (DoH) 转发代理,零配置部署到 **Vercel**。
技术栈:**Hono + Node.js 运行时 + Fluid compute**(Vercel 当前官方推荐组合,
Edge Functions 已对新项目弃用)。

本项目融合了 8 个开源 Vercel/边缘 DoH 项目的优点,并规避了它们各自的硬伤:
多上游**顺序故障转移**(不广播,保护隐私)、TTL 感知缓存、正确的 EDNS Client
Subnet (ECS) 注入(绝不产生重复 OPT RR)、路径映射、隐私默认值。

> 📖 完整部署步骤、验证命令与生产化防护(路径混淆 / Vercel Firewall 限流 / IP 白名单)
> 见 **[DEPLOYMENT.md](./DEPLOYMENT.md)**。

## 特性

- **RFC 8484 兼容**: GET `?dns=<base64url>` 与 POST `application/dns-message`
  - 正确状态码: 400 / 405 / 406 / 413 / 415 / 502;成功响应 `Content-Type: application/dns-message`
  - **协议门**: 查询先过校验(QDCOUNT=1 / QR=0 / OPCODE=0 / 结构完整 / 单 OPT / ECS 合法),不合格直接 400,不触上游
- **隐私默认值**:
  - 默认只把查询发给 **1 个**上游(轮询),失败才顺序转移,**绝不并发广播**
  - 默认**不附加 ECS**;上游出站头为 **allowlist**(Authorization/Cookie/XFF 等一律不外发)
  - ECS `/0`(客户端声明不披露地址)被尊重,绝不注入真实子网
- **健壮**: 单上游 3s 超时 + **总解析预算 `TOTAL_TIMEOUT_MS`(默认 10s,每次尝试取
  `min(单上游超时, 剩余)`,预算耗尽即放弃 → SERVFAIL)**;上游仅接受 **2xx + 精确
  `application/dns-message` + 结构合法 + 响应回显请求 ID/Question** 的应答,
  且响应体有 65535 字节上限(RFC 8484 最大报文长度),否则故障转移(非 2xx body 绝不当作 DNS 应答);`redirect: "error"` 防 SSRF;
  全部失败返回合法的 SERVFAIL dns-message(200)
- **TTL 感知缓存**: 正向按 Answer 最小 TTL;NXDOMAIN/NODATA 按 RFC 2308
  `min(SOA TTL, SOA.MINIMUM)`(**无 SOA 的负应答不缓存**);
  SERVFAIL/REFUSED/其它 RCODE(含 EDNS extended,如 BADVERS=16)一律 `no-store`;
  POST / 含 ECS(请求或响应)一律 `no-store`;
  **刻意不使用 `stale-while-revalidate`**: DNS 记录的 TTL 是硬过期语义(RFC 1035),
  CDN 一旦越过 s-maxage 就必须回源重取,绝不出 stale 兜底延长记录寿命;
  可选 `TTL_JITTER`(默认关)把 s-maxage **只降不升**地抖动,防 CDN 到期雪崩
- **ECS 支持(默认关)**: `/dns-query/auto_ecs` 强制附加、`/dns-query/no_ecs`
  强制禁用(**并剥离客户端已带的 ECS**,而非仅不注入);客户端 IP 取可信头链
  (`x-vercel-forwarded-for` → `x-real-ip` → XFF 最右段),过滤私网/保留地址,
  **不信任可伪造的最左段**;
  **RFC 7871 严格校验**: 请求 ECS 的 SCOPE PREFIX-LENGTH 必须为 0、地址超出源前缀的
  尾部位必须为 0(注入时自动掩码),非法即 400;
  上游响应的 EDNS/ECS 结构纳入信任边界,响应携带 ECS 时必须回显请求的 FAMILY/
  SOURCE PREFIX/地址,否则视为无效响应并故障转移
- **路径映射(可选)**: `/dns-query/{provider}` 经 `DOMAIN_MAPPINGS` 路由到指定上游
- **URL flags(按请求覆盖环境变量)**: 在端点路径后追加
  `/v4`(只返回 A 记录)/`/v6`(只返回 AAAA 记录)/`/ecs`(强制 ECS)/`/no-ecs`(强制禁 ECS,剥离已有 ECS)/
  `/ecs-<IP>`(强制 ECS 并用指定 IP 作为子网,如 `/ecs-8.8.8.8`,可用于测试地域解析),
  可组合且顺序任意,如 `/dns-query/v4/ecs-8.8.8.8`;URL 优先于环境变量
  (v4/v6 = **答案族**: 代理把查询类型重写为 A/AAAA,而非限制连接地址;
  ecs-<IP> 仅当 ECS 开启时生效,关闭(no-ecs)时该配置失效)
- **dns-json API 与 DoH 同路径**(一个端点两种协议): `{DOH_PATH}?name=...&type=A`
  即 JSON 查询(dns.google/resolve 风格,无需特定 Accept);flag 后缀同样生效,
  如 `/{DOH_PATH}/v4/ecs?name=...`
  (ecs = 代理用客户端 IP 掩码注入 `edns_client_subnet`;no-ecs 则剥离任何子网参数);
  上游应答**必须能解析为 dns-json schema**;输入先校验(name≤253 / type 白名单 /
  edns_client_subnet 合法 CIDR / cd、do 规范化布尔,非法 400);
  缓存按 Answer TTL 感知,负应答按 RFC 2308 从 SOA 的 MINIMUM 字段计算
  `min(SOA TTL, SOA.MINIMUM)`(无 TTL 信息不缓存)
- **隐私**: 前端**默认隐藏 DoH 端点路径**(路径混淆不泄露);设置
  `SHOW_DOH_ENDPOINT=true` 后前端才显示并可生成客户端端点 URL
- **代理卫生**: 请求体/上游响应上限 65535 字节、上游 URL 仅 https 白名单(含 DOMAIN_MAPPINGS)、
  Content-Type/Accept 按媒体类型精确协商(`;q=0` 即不接受,`application/dns-messageevil` 不匹配);
  GET `dns` 参数**严格按 RFC 8484 无 padding base64url** 解码(含 `=`/`+`/`/` 或
  `length%4==1` 一律 400,不再容忍 legacy padded 输入);
  POST 请求体按流**增量读取并设硬上限**(chunked 无 Content-Length 时不会整体读入内存);
  首页 Bootstrap 5.3 CDN 带 **SRI integrity + CSP 响应头**(脚本仅允许 self 与带 SRI 的 CDN,
  连接仅允许本站与 ipwho.is)

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
| `UPSTREAM_FAMILY` | `auto` | 答案族: `auto`(默认,不重写)/ `v4`(强制只查 A)/ `v6`(强制只查 AAAA);可用 URL flag 覆盖 |
| `DOH_PATH` | `/dns-query` | DoH 端点路径。改成随机路径(如 `/3f9a2b7c`)即路径混淆,标准路径自动 404;dns-json 工具查询(`?name=`)就在同一路径上,无额外端点 |
| `SHOW_DOH_ENDPOINT` | `false` | `true` 时前端显示 DoH 端点路径并生成客户端 URL(默认隐藏,防泄露混淆路径) |
| `ECS_UPSTREAM_DOH_URLS` | `https://dns.google/dns-query` | 请求带 ECS 时使用的上游 |
| `JSON_UPSTREAM_DOH_URLS` | `https://dns.google/resolve` | dns-json 上游 |
| `AUTO_ADD_ECS` | `false` | 全局自动附加 ECS(默认关,隐私) |
| `ECS_OVERRIDE_IP` | 空 | 固定 ECS 源 IP(如 `8.8.8.8`)。**仅当 ECS 开启时生效**;关闭(no-ecs)时失效;URL `ecs-<IP>` 优先于它 |
| `IPV4_ECS_PREFIX_LENGTH` | `24` | ECS IPv4 前缀长度(0–32) |
| `IPV6_ECS_PREFIX_LENGTH` | `56` | ECS IPv6 前缀长度(0–128) |
| `CACHE_MAX_AGE` | `300` | GET 缓存 `s-maxage` 上限(秒) |
| `RACE_UPSTREAMS` | `false` | `true` 时并发竞速所有上游(最快者胜,牺牲隐私换延迟) |
| `UPSTREAM_TIMEOUT_MS` | `3000` | 单上游超时(500–30000) |
| `TOTAL_TIMEOUT_MS` | `10000` | **总墙钟预算**(100–60000): 约束整个解析(所有 failover 尝试 / JSON 上游循环),每次尝试取 `min(单上游超时, 剩余)`;预算耗尽即放弃 → SERVFAIL。`/dns-query-proxy` 除外(保持 CF-Workers-DoH 原版 fetch 语义,无人工超时) |
| `TTL_JITTER` | `0` | 缓存 TTL 抖动(0–1 小数,默认 0 = 关): 把 `s-maxage` **只降不升**(`max(1, floor(权威TTL × (1−rand×jitter)))`),防 CDN 到期雪崩;绝不把新鲜度抬过权威 TTL |
| `FORCE_RESPONSE_PADDING` | `false` | RFC 8467 响应填充(**Random-Block-Length**: 每次随机选 128/256/512 字节块对齐,防流量分析;响应无 OPT RR 时自动追加) |
| `DOMAIN_MAPPINGS` | `{}` | 路径映射 JSON,如 `{"google":{"targetDomain":"dns.google"}}` |
| `PROXY_DOH_ALLOWLIST` | 前端下拉的 7 个提供商 | `/dns-query-proxy` 允许的 `doh=` 上游白名单(逗号分隔 https URL)。**fetch 目标永远是配置数据而非请求数据**(SSRF 防护): 不在白名单内的 `doh=` 一律 400;需自定义提供商时在此扩展 |
| `DEBUG_LOGGING` | `false` | 调试模式: 输出调试日志(不打印查询内容)+ dns-message 路径附 `X-DOH-upstream`/`X-DOH-rcode`/`X-DOH-cache`、dns-json 路径附 `X-DOH-upstream`/`X-DOH-cache` 诊断响应头 |
| `APP_VERSION` | `1.0.0` | 信息页展示的版本号 |

## 测试

```bash
npm test          # vitest 全量(293 个用例)
npx tsc --noEmit  # 严格类型检查
npm run typecheck:node  # NodeNext 模式校验部署产物 ESM 导入(无扩展名会报 TS2835)
```

> 测试目录按仓库策略**仅在本地维护**(`test/` 已 gitignore,不随 GitHub 分发);
> fresh clone 后需自行补齐测试文件才能跑 `npm test`。

关键回归用例:

- ECS 注入:**已有 OPT RR 时并入同一 OPT(ARCOUNT 不变、全报文仅 1 个 OPT)**,
  这是对常见"重复 OPT RR"bug 的显式防护;`/no-ecs` **剥离已有 ECS**(仅 ECS 时整 OPT
  移除、ARCOUNT-1;混其它 option 时保留并重建 RDLENGTH)
- 上游策略: 默认**不并发**、按序转移、全失败抛错;竞速模式取最快成功响应;
  响应必须**回显请求 ID/Question**(v4/v6 改写后按改写报文比较),超限/坏类型/坏 body 全部转移
- 缓存四象限: GET/POST/含 ECS/负应答,外加无 SOA 负应答与 extended RCODE(BADVERS=16)不缓存
- 客户端 IP: XFF 最右段(防伪造)、私网过滤、IPv6 解析

## 架构

```
请求 → Hono 路由(/dns-query, /dns-query/auto_ecs, /dns-query/no_ecs,
                  /dns-query/{provider}, /dns-query?name=…(JSON), /dns-query-proxy,
                  /health, /)
  → 校验(方法/Accept/Content-Type/体积(增量流上限)/QR/OPCODE/QDCOUNT/ECS 严格校验)
  → [ECS 剥离|注入] → 上游选择(轮询 → 顺序故障转移,或竞速)
  → fetch(min(单上游超时, 剩余预算) + 响应校验(结构/回显/EDNS-ECS 信任边界)/上限)
  → 解析应答 TTL + extended RCODE → Cache-Control(无 serve-stale) → 响应
```

```
src/
├── config.ts          # 唯一配置源(环境变量解析 + 校验)
├── media.ts           # 媒体类型精确解析 + Accept q-value 协商
├── upstream.ts        # 上游选择/故障转移/竞速 + 响应校验 + 头过滤
├── cache-control.ts   # RFC 8484 + TTL 感知缓存策略
├── errors.ts          # SERVFAIL 报文 / 文本错误
├── log.ts             # 调试日志(默认关闭)
├── dns/
│   ├── wire.ts        # base64url、DNS 头/压缩指针/RR 遍历/extended RCODE
│   ├── ecs.ts         # ECS 检测 + 注入(并入既有 OPT)+ 剥离(no-ecs)
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

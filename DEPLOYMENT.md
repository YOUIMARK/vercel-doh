# 部署与生产化防护

> 配套文档: [README.md](./README.md)。本文件包含完整部署步骤、验证命令、
> 以及公开服务前的防护建议(路径混淆 + Vercel Firewall 限流/白名单)。

---

## 一、部署步骤

### 1. 前置条件

- 已就绪的 GitHub 仓库(本项目即 `YOUIMARK/vercel-doh`)
- Vercel 账号(免费 Hobby 即可;函数时长上限 300s、内存 2GB、请求体 4.5MB,均远超 DoH 需求)

### 2. 导入部署(零配置)

**方式 A — Dashboard(推荐)**
1. 打开 https://vercel.com → **Add New → Project**
2. Import 选择 `YOUIMARK/vercel-doh`
3. Framework Preset 自动识别为 **Hono**(无需改任何构建配置)→ **Deploy**

**方式 B — Vercel CLI**
```bash
npm i -g vercel
vercel login
cd vercel-doh
vercel link          # 关联已有项目或新建
vercel deploy --prod
```

### 3. 环境变量(可选,全部有默认值)

项目 **Settings → Environment Variables** 添加(部署后再改需重新 Deploy):

| 变量 | 默认值 | 建议 |
|---|---|---|
| `UPSTREAM_DOH_URLS` | `https://cloudflare-dns.com/dns-query` | 想多上游容错就逗号分隔,如 `https://cloudflare-dns.com/dns-query,https://dns.google/dns-query` |
| `UPSTREAM_FAMILY` | `auto` | 答案族: `auto`(不重写)/ `v4`(强制只查 A)/ `v6`(强制只查 AAAA);被 URL flag 覆盖 |
| `DOH_PATH` | `/dns-query` | **路径混淆**: 改成随机路径段后,DoH 端点挂到新路径,标准 `/dns-query` 自动 404;dns-json 工具查询(`?name=`)就在同一路径上,无额外端点 |
| `SHOW_DOH_ENDPOINT` | `false` | `true` 时前端显示并生成 DoH 端点 URL(默认隐藏,防泄露混淆路径) |
| `ECS_UPSTREAM_DOH_URLS` | `https://dns.google/dns-query` | 带 ECS 的请求走这里 |
| `JSON_UPSTREAM_DOH_URLS` | `https://dns.google/resolve` | 网页工具的 dns-json 上游 |
| `AUTO_ADD_ECS` | `false` | 需要地域解析再开,会向上游泄露客户端子网 |
| `ECS_OVERRIDE_IP` | 空 | 固定 ECS 源 IP(如 `8.8.8.8`)。**仅当 ECS 开启时生效**,no-ecs 时失效;URL `ecs-<IP>` 优先 |
| `CACHE_MAX_AGE` | `300` | GET 缓存 s-maxage 上限(秒) |
| `FORCE_RESPONSE_PADDING` | `false` | RFC 8467 随机块长填充(128/256/512 随机选块对齐,防流量分析;响应无 OPT 时自动追加) |
| `RACE_UPSTREAMS` | `false` | `true` = 并发竞速(最快者胜,牺牲隐私) |
| `UPSTREAM_TIMEOUT_MS` | `3000` | 单上游超时 |
| `TOTAL_TIMEOUT_MS` | `10000` | 总墙钟预算(100–60000): 约束整个解析(所有 failover 尝试 / JSON 上游循环),每次尝试取 `min(单上游超时, 剩余)`;预算耗尽即放弃 → SERVFAIL |
| `TTL_JITTER` | `0` | 缓存 TTL 抖动(0–1 小数,默认 0 = 关): `s-maxage` **只降不升**(min 1s),防 CDN 到期雪崩;绝不抬过权威 TTL |
| `DOMAIN_MAPPINGS` | `{}` | 路径映射,如 `{"google":{"targetDomain":"dns.google"}}` |
| `DEBUG_LOGGING` | `false` | 排障时开: 调试日志(不打印查询内容)+ `X-DOH-upstream`/`X-DOH-rcode`/`X-DOH-cache` 诊断响应头 |

### 4. 部署后验证

```bash
# ① 网页工具(浏览器打开即是)
curl -sS https://<你的项目>.vercel.app/ | head -20

# ② GET DoH —— 应返回合法 DNS 报文(65 字节左右)
curl -sS "https://<你的项目>.vercel.app/dns-query?dns=AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB" \
  -H "Accept: application/dns-message" | xxd

# ③ POST DoH
curl -sS -X POST --data-binary @query.bin \
  -H "Content-Type: application/dns-message" -H "Accept: application/dns-message" \
  "https://<你的项目>.vercel.app/dns-query" | xxd

# ④ 标准客户端
dig +https @<你的项目>.vercel.app example.com A

# ⑤ 健康检查
curl -sS https://<你的项目>.vercel.app/health   # → ok
```

> 若返回的是 33 字节 SERVFAIL 报文(rcode=2),先看函数日志(`vercel logs` 或
> Dashboard → Logs):通常是上游网络问题或环境变量拼写错误,与代码无关。

### 5. 自定义域名与区域

- **域名**: Settings → Domains 添加(证书自动签发);个人自用也可直接用 `*.vercel.app`
- **区域**: Settings → Functions → Region。默认 `iad1`(美国);离你近的亚洲区域可显著
  降低延迟,如 `sin1`(新加坡)/ `hkg1`(香港)。Pro 可配最多 3 个区域 + 故障转移
- **Fluid Compute**: 2025-04-23 起新项目**默认开启**;若你的项目创建较早,
  到 Settings → Functions 确认 **Fluid Compute** 已开启(冷启动优化 + 函数内并发)

---

## 二、生产化防护

> 目标场景: 把自用 DoH 端点公开到公网,既要能用,又别被扫描器/滥用者打爆。

### 1. 路径混淆(环境变量驱动,推荐)

设置环境变量 **`DOH_PATH`** 为随机路径段,DoH 端点即挂到该路径,
**标准 `/dns-query` 自动失效(返回 404)**,混淆真正生效。

```bash
# 生成随机路径段
openssl rand -hex 8        # 例如 3f9a2b7c8d1e4f5a
```

Dashboard → Settings → Environment Variables 添加:
```text
DOH_PATH = /3f9a2b7c8d1e4f5a
```

部署后客户端配置为:
```text
https://<你的项目>.vercel.app/3f9a2b7c8d1e4f5a            # GET ?dns=…
https://<你的项目>.vercel.app/3f9a2b7c8d1e4f5a/auto_ecs   # 强制 ECS
```

**URL flags(按请求覆盖环境变量,URL 优先)**: 在端点路径后追加一个或多个 flag,
顺序任意、可组合:
```text
/v4        只返回 A 记录(代理把查询类型重写为 A;覆盖 UPSTREAM_FAMILY)
/v6        只返回 AAAA 记录(重写为 AAAA)
/ecs       强制附加 ECS(= /auto_ecs)
/ecs-<IP>  强制附加 ECS 并用指定 IP 作为子网(如 /ecs-8.8.8.8,可测地域解析;
           仅当 ECS 开启时生效,no-ecs 时失效)
/no-ecs    强制禁用 ECS(= /no_ecs)

例: https://<你的项目>.vercel.app/3f9a2b7c8d1e4f5a/v4/ecs-8.8.8.8
    https://<你的项目>.vercel.app/3f9a2b7c8d1e4f5a/v6/google   (v6 + provider)
```

> ⚠️ 用**路径后缀**而非 query 参数: DoH GET 客户端会自己拼接 `?dns=...`,
> query 里的 flag 会被拼坏(如 `?v4&ecs?dns=…`)。路径后缀与 RFC 8484 完全兼容。
> ⚠️ v4/v6 = **答案族**(返回 A/AAAA),不是连接地址族——避免歧义。

网页工具的 JSON API 就在 **`{DOH_PATH}` 本身**(一个端点两种协议): GET `/{DOH_PATH}?name=...`
即 JSON 查询(dns.google/resolve 风格,无需特定 Accept 头),基路径上的 flag 同样生效
(如 `/{DOH_PATH}/v6?name=...`);不存在任何额外的 `-json` 端点。

行为细节:
- `DOH_PATH` 必须是**单个路径段**(`/xxx` 格式,字母/数字/`-`/`_`),非法值会在启动时报错
- 设置后标准 `/dns-query`、`/dns-query/auto_ecs` 等**不再注册**,返回 404,也不存在任何固定 JSON 端点;
  dns-json 工具查询(`?name=`)就在 `{DOH_PATH}` 上(前端由服务端注入实际路径,工具照常可用;
  注意:自定义路径时工具页会暴露该路径)
- **前端默认隐藏端点路径**(路径混淆不泄露): 需设置 `SHOW_DOH_ENDPOINT=true`
  后,网页工具才会显示并生成带 flag 的客户端端点 URL;
  `/health`、`/` 保持固定路径
- 未设置时行为不变(默认 `/dns-query`)

> ⚠️ 混淆≠安全,只是把端点从「公开约定路径」变成「不易被发现」。
> 真正的滥用防护要靠下面的限流/白名单。

### 2. Vercel Firewall / WAF(免费 Hobby 可用)

Vercel Firewall 对所有套餐开放,**限流功能 Hobby 免费额度为每月前 100 万次
允许的限流请求**。Dashboard → 项目 → **Firewall** 配置:

**2.1 限流(强烈建议,防滥用/防被打爆)**
- WAF → **Rate Limiting** → 新建规则
- 匹配: Path = `/dns-query*`
- 限制: 每个 IP `120 次/分钟`(个人用量远低于此)
- 动作: **Block(返回 429)**
- ⚠️ 关键: **不要用 "Managed Challenge" / 验证码类动作** —— DoH 客户端是程序,
  无法完成 JS/HTML 质询,会被全部误杀。API/DoH 端点只适合 Block。

**2.2 IP 白名单(个人自用最稳)**
- WAF → **IP Blocking** → 把你的家庭/公司出口 IP 加进 allow 列表,其余全拒。
- 代价: 换网络(手机流量/出差)会被挡,需临时改规则。适合「固定出口 IP + 只给自己用」。

**2.3 关闭多余暴露(可选)**
- 不需要网页工具时,可在 `vercel.json` 加 redirect 把 `/` 指走,或接受现状
  (信息页只暴露端点说明,无敏感信息)。

### 3. 应用内既有防护(无需额外配置)

| 防护 | 位置 |
|---|---|
| 请求体 65535 字节上限(413,chunked 增量读取) | `src/routes/dns-query.ts` |
| 方法白名单 GET/POST(405)、Accept(406)、Content-Type(415) | 同上 |
| 上游 URL 仅 https 白名单(防 SSRF) | `src/config.ts` |
| hop-by-hop 头剥离、不转发客户端 IP | `src/upstream.ts` |
| 上游失败返回 SERVFAIL 报文,不泄露内部细节 | `src/errors.ts` |
| 日志默认不记录查询内容 | `src/log.ts` |

### 4. 监控与成本

- **用量**: Dashboard → Usage 关注 Functions 的 Active CPU 与调用量;被刷会立刻反映
- **Spend Management**(可选): 设预算上限,防失控账单
- 正常个人使用远低于免费额度: 一次查询 ≈ 几十 ms CPU、几 KB 流量

### 5. 可选进阶: 请求头 Token(代码未内置,按需自行加)

如果只给**支持自定义请求头的客户端**用(dnscrypt-proxy、AdGuard Home 等),
可以在 `src/routes/dns-query.ts` 入口加一个校验: 读环境变量 `DOH_TOKEN`,
设置后要求请求带 `x-doh-token: <token>`,否则 401。

⚠️ 权衡: **浏览器安全 DNS 无法发送自定义头**,开启 Token 后浏览器用户全部失效;
且混淆路径 + 限流通常已足够,Token 仅适合「白名单场景的加强」。

---

## 三、常见问题排查

| 现象 | 原因 | 处理 |
|---|---|---|
| 返回 33 字节 SERVFAIL | 上游不可达/超时 | `vercel logs` 看日志;`curl` 直连上游验证 |
| 返回 400/415/406 | 客户端请求不规范 | 检查 Accept / Content-Type / dns 参数 |
| 冷启动首包慢(数百 ms) | 函数闲置归档 | 属正常;确认 Fluid Compute 开启可缓解 |
| 网页工具打不开 | /style.css 404 | 确认文件在 `public/`;本地 `npm run dev` 可复现 |
| 换网络后被 429 | 限流/白名单规则 | 调高限额或把新 IP 加入白名单 |

# DoH Proxy - Cloudflare Snippets & Workers Edition (dohx)

这是一个专为 **Cloudflare Snippets** (Rules -> Snippets) 及 **Cloudflare Workers** 设计的极简、高性能 DNS over HTTPS (DoH) 与 DNS over QUIC (HTTP/3) 边缘加速代理。

依托 Cloudflare 全球 Anycast 边缘网络与原生 HTTP/3 (QUIC) 协议支持，实现 0-RTT 握手、抗弱网丢包与连接无缝迁移，同时通过边缘缓存技术将常见域名解析延迟降低至 1~3ms。

## 特性

- **DNS over QUIC (HTTP/3) 极速传输**：借助 Cloudflare 边缘的 HTTP/3 (QUIC) 支持与 `Alt-Svc` 协商通告，客户端可通过 QUIC 协议直接进行 DNS 解析，彻底避免 TCP 三次握手与队头阻塞。
- **协议支持边界明确**：
  - **客户端入站**：支持 **HTTP/3 (QUIC)** 与 **HTTP/2** 极速通道，实现真正的 0-RTT 连接与抗弱网迁移。
  - **上游服务转发**：**仅支持 DoH (HTTPS 443 端口)**。受 Cloudflare 沙箱底层机制限制，不支持原生的 DoQ（DNS over QUIC，UDP 853 端口）上游。若路径中传入 `quic://` 前缀，系统会自动清洗并适配至对应的官方 DoH 端点。
- **双查询规范兼容**：
  - **RFC 8484 (Wireformat)**：支持标准 GET (`?dns=...`) 与二进制 POST (`application/dns-message`) 请求。
  - **DNS-over-HTTPS JSON API**：支持 Google / Cloudflare 规范的 JSON 格式解析 (`?name=domain&type=A`)。
- **多上游智能路由**：内置主流高速上游别名（Cloudflare, Google, Quad9, 阿里 DNS, 腾讯 DNSPod, 360, AdGuard 广告拦截等），支持按路径即插即用切换。
- **边缘智能缓存 (Edge Caching)**：自动优化 DNS 响应的 Cache-Control 头，热门解析在边缘节点毫秒级直接命中。
- **隐蔽防探测 (Stealth Mode)**：精准识别非规范的扫描请求，静默返回空 `404 Not Found`，不暴露代理特征与服务指纹。
- **高纯度隐私防护**：严格剥离客户端真实 IP 及 Cloudflare 专属透传头（`Host`, `X-Forwarded-For`, `X-Real-IP`, `CF-Connecting-IP`, `Referer` 等），防止源站追踪。
- **安全域名白名单**：内置公共 DNS 域名白名单，杜绝被利用作为通用网络代理。
- **极致轻量无依赖**：纯原生 JavaScript 单文件编写，CPU 执行耗时小于 2ms，完全满足 Snippets 严苛的 5ms 限制，无需 npm 依赖与复杂编译。

## 预置上游对照表

| 路由别名路径 | 对应上游服务 | 说明 |
| :--- | :--- | :--- |
| `/` 或 `/dns-query` | Cloudflare DNS (`1.1.1.1`) | 默认全球极速公共 DNS |
| `/cloudflare` 或 `/cf` | Cloudflare DNS (`cloudflare-dns.com`) | Cloudflare 主干解析 |
| `/cf-security` | Cloudflare Security (`1.1.1.2`) | 自动拦截恶意软件 |
| `/cf-family` | Cloudflare Family (`1.1.1.3`) | 拦截恶意软件与成人内容 |
| `/google` | Google Public DNS (`8.8.8.8`) | 谷歌全球公共 DNS |
| `/quad9` | Quad9 DNS (`9.9.9.9`) | 瑞士隐私保护与威胁阻断 |
| `/alidns` 或 `/ali` | 阿里公共 DNS (`dns.alidns.com`) | 国内主流优化线路 |
| `/dnspod` 或 `/tencent`| 腾讯 DNSPod (`doh.pub`) | 腾讯公共 DNS |
| `/360` | 360 安全 DNS (`doh.360.cn`) | 360 安全解析 |
| `/adguard` | AdGuard DNS (`dns.adguard-dns.com`)| 拦截常见广告与跟踪器 |
| `/opendns` | Cisco OpenDNS (`doh.opendns.com`) | 思科公共 DNS |

### 灵活路径与多协议格式全面兼容说明

除了基础别名路由外，系统内置自适应 URL 重写与协议头清洗引擎，全面兼容以下八大类灵活写法：

#### 1. 默认极速路径 (Default)
- 根路径：`https://dns.你的域名.com`
- 标准 DoH 路径：`https://dns.你的域名.com/dns-query`
- 别名解析路径：`https://dns.你的域名.com/resolve`

#### 2. 预设服务商别名短路径 (Alias Routing)
- 谷歌公共 DNS：`https://dns.你的域名.com/google` 或 `/google/dns-query`
- 阿里公共 DNS：`https://dns.你的域名.com/alidns` 或 `/ali`
- 腾讯公共 DNS：`https://dns.你的域名.com/dnspod` 或 `/tencent`
- 瑞士 Quad9：`https://dns.你的域名.com/quad9`
- 广告与威胁拦截：`https://dns.你的域名.com/adguard`、`/cf-security`、`/cf-family`
- 思科 OpenDNS 与 360：`https://dns.你的域名.com/opendns`、`/360`

#### 3. 纯公共 IP 极速路径 (Direct IP Routing)
直接使用公共 DNS 的经典 IP 作为路径，系统自动识别并映射至其官方优化 DoH 端点：
- 阿里 DNS：`https://dns.你的域名.com/223.5.5.5` 或 `/223.6.6.6`
- 谷歌 DNS：`https://dns.你的域名.com/8.8.8.8` 或 `/8.8.4.4`
- Cloudflare：`https://dns.你的域名.com/1.1.1.1` 或 `/1.0.0.1`（安全版 `/1.1.1.2`、家庭版 `/1.1.1.3`）
- Quad9：`https://dns.你的域名.com/9.9.9.9` 或 `/149.112.112.112`
- 腾讯 DNSPod：`https://dns.你的域名.com/119.29.29.29`
- AdGuard：`https://dns.你的域名.com/94.140.14.14` 或 `/94.140.15.15`
- 支持追加子路径，例如：`https://dns.你的域名.com/223.5.5.5/dns-query`

#### 4. 完整 URL 代理模式 (Full URL Proxy)
原生支持将上游完整的 HTTP/HTTPS 地址拼接在代理域名之后：
- `https://dns.你的域名.com/https://dns.google/dns-query`
- `https://dns.你的域名.com/https://dns.alidns.com/dns-query`
- `https://dns.你的域名.com/http://doh.pub/dns-query`

#### 5. 省略协议头的完整域名模式 (Hostname Omitted Scheme)
支持省略 `https://` 协议前缀，直接输入白名单域名及路径：
- `https://dns.你的域名.com/dns.google/dns-query`
- `https://dns.你的域名.com/dns.alidns.com/dns-query`
- `https://dns.你的域名.com/doh.pub/dns-query`
- 省略子路径自适应：`https://dns.你的域名.com/dns.google`（自动补全 `/dns-query`）

#### 6. 异构协议头自动清洗兼容 (Protocol Normalization)
针对客户端误配或协议转换工具传入的 QUIC/DoQ 协议头，自动清洗并平滑适配为对应的高速 DoH 上游：
- `quic://` 协议清洗：`https://dns.你的域名.com/quic://223.5.5.5`
- `quic://` 域名清洗：`https://dns.你的域名.com/quic://dns.google/dns-query`
- `doq://` 协议清洗：`https://dns.你的域名.com/doq://223.5.5.5`

#### 7. 连续斜杠压缩与单斜杠折叠容错 (Slash Normalization)
兼容部分反向代理软件或网关自动压缩双斜杠为单斜杠的极端边界场景：
- `/https:/dns.google/dns-query`（自动还原为 `https://`）
- `/quic:/223.5.5.5`（自动剔除协议前缀）
- 多重斜杠容错：`///dns-query`、`//google//`

#### 8. 双标准查询协议规范
- **RFC 8484 (Wireformat 二进制)**：GET `?dns=<base64url>` 或 POST 二进制流（`application/dns-message`）
- **DNS JSON API**：GET `?name=<domain>&type=<A|AAAA|CNAME|TXT...>`
## 部署指南

### 方案一：Cloudflare Snippets (推荐)

Snippets 完全免费，无需配置 Worker 路由，直接挂载在现有域名规则下。

1. 登录 [Cloudflare 控制台](https://dash.cloudflare.com/)，进入你的域名管理面板。
2. 确保在 **DNS** 列表中已为加速子域名（如 `dns.你的域名.com`）添加解析记录（例如 A 记录指向 `192.0.2.1`），并开启**橙色云朵 (Proxied)**。
3. 进入 **Speed (速度)** -> **Optimization (优化)** -> **Protocol (协议)**，确保开启 **HTTP/3 (with QUIC)** 及 **0-RTT Connection Resumption**。
4. 进入左侧菜单 **Rules (规则)** -> **Snippets (代码片段)**。
5. 点击 **Create Snippet**，名称填写 `dohx`。
6. 将本项目中的 `index.js` 代码全部复制并粘贴到代码编辑器中。
7. 在 **Filter (过滤器)** 中配置触发规则：
   - 字段选择 `Hostname`
   - 运算符选择 `equals`
   - 值填写 `dns.你的域名.com`
8. 点击 **Save and Deploy (保存并部署)** 即可立即生效。

### 方案二：Cloudflare Workers

1. 进入 Cloudflare 控制台 -> **Workers & Pages** -> **Create application** -> **Create Worker**。
2. 将 `index.js` 代码粘贴并部署。
3. 在 Worker 的 **Settings (设置)** -> **Domains & Routes (域与路由)** 中添加你的自定义域名（例如 `dns.你的域名.com`）。

## 客户端配置示例

### 1. Clash / Mihomo (Clash Meta) / Clash Verge Rev

在配置文件的 `dns` 字段中配置（支持 HTTP/2 及 HTTP/3 QUIC）：

```yaml
dns:
  enable: true
  listen: 0.0.0.0:1053
  ipv6: false
  enhanced-mode: redir-host
  nameserver:
    # 默认上游 (Cloudflare)
    - https://dns.你的域名.com/dns-query
    # 或指定上游 (例如 Google / 阿里)
    - https://dns.你的域名.com/google/dns-query
    - https://dns.你的域名.com/alidns/dns-query
  # Mihomo / Clash Meta 支持指定 h3 协议 (QUIC)
  # - https://dns.你的域名.com/dns-query#h3=true
```

### 2. Surge (iOS / macOS)

在 Surge 配置文件的 `[General]` 段落中添加：

```ini
[General]
doh-server = https://dns.你的域名.com/dns-query
doh-format = wireformat
# 支持启用 HTTP/3
doh-follow-cname = true
```

### 3. Sing-box

在 `dns.servers` 中增加远程 DoH 节点：

```json
{
  "dns": {
    "servers": [
      {
        "tag": "remote_doh",
        "address": "https://dns.你的域名.com/dns-query",
        "address_resolver": "local_dns",
        "strategy": "prefer_ipv4"
      }
    ]
  }
}
```

### 4. Shadowrocket (小火箭)

1. 打开 Shadowrocket，进入 **设置** -> **DNS**。
2. 在 **HTTPS DNS** 中填入：
   `https://dns.你的域名.com/dns-query`
3. 选择返回并保存。

### 5. 浏览器配置 (Chrome / Edge / Firefox)

- **Chrome / Edge**：进入 `设置` -> `隐私和安全` -> `安全` -> `使用安全 DNS` -> 选择 `自定义`，输入 `https://dns.你的域名.com/dns-query`。
- **Firefox**：进入 `设置` -> `常规` -> `网络设置` -> 勾选 `启用基于 HTTPS 的 DNS` -> 选择 `最大保护` 或 `增强保护` -> 自定义填入 `https://dns.你的域名.com/dns-query`。

### 6. macOS / iOS 系统原生加密 DNS (移动配置文件)

可生成包含 DoH 的 `.mobileconfig` 描述文件导入系统，指定 `ServerURL` 为 `https://dns.你的域名.com/dns-query`。

### 7. 命令行验证测试

#### RFC 8484 (Wireformat) 查询测试 (doggo / kdig)
```bash
# 使用 doggo 工具
doggo example.com @https://dns.你的域名.com/dns-query

# 使用 kdig 工具
kdig @https://dns.你的域名.com/dns-query +https example.com
```

#### JSON API 格式快速测试 (curl)
```bash
curl -s -H "Accept: application/dns-json" \
  "https://dns.你的域名.com/dns-query?name=github.com&type=A"
```

指定阿里 DNS 上游查询：
```bash
curl -s -H "Accept: application/dns-json" \
  "https://dns.你的域名.com/alidns?name=taobao.com&type=A"
```

## 常见问题排查

### 1. 访问域名返回 404？
本项目启用了**隐蔽防探测 (Stealth Mode)**。直接通过普通浏览器访问根路径而未带 DNS 协议参数（如 `?dns=` 或 `?name=`）属于非规范请求，系统将直接返回空 404，属于正常安全机制。

### 2. 如何确认是否走通了 HTTP/3 (QUIC)？
客户端首次连接通常通过 HTTP/2 握手，响应头中包含 `Alt-Svc: h3=":443"; ma=86400`。支持 HTTP/3 的客户端在后续请求中会自动切换为 QUIC。亦可使用支持 HTTP/3 的 curl 测试：
```bash
curl --http3 -H "Accept: application/dns-json" \
  "https://dns.你的域名.com/dns-query?name=cloudflare.com&type=A" -v
```

## 授权协议

本项目基于 [MIT License](LICENSE) 开源。

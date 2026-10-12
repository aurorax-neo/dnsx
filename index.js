/**
 * dnsx - Cloudflare Snippets & Workers DNS over HTTPS (DoH) / QUIC 加速代理
 * 专为 5ms CPU 限制与高并发边缘网络优化，支持 RFC 8484 与 DNS-JSON 规范
 */

// 预置主流高速上游 DNS 基础地址映射表
const UPSTREAM_SERVERS = {
  // 默认上游 (Cloudflare 极速公共 DNS)
  default: "https://1.1.1.1",

  // Cloudflare 系列
  cloudflare: "https://cloudflare-dns.com",
  cf: "https://cloudflare-dns.com",
  "cf-security": "https://security.cloudflare-dns.com", // 阻止恶意软件 (1.1.1.2)
  "cf-family": "https://family.cloudflare-dns.com",     // 阻止恶意软件与成人内容 (1.1.1.3)

  // Google Public DNS (8.8.8.8 / 8.8.4.4)
  google: "https://dns.google",

  // Quad9 (9.9.9.9 瑞士隐私保护与威胁阻断)
  quad9: "https://dns.quad9.net",

  // 国内主流公共 DNS
  alidns: "https://dns.alidns.com",
  ali: "https://dns.alidns.com",
  dnspod: "https://doh.pub",
  tencent: "https://doh.pub",
  "360": "https://doh.360.cn",

  // AdGuard DNS (广告与跟踪拦截)
  adguard: "https://dns.adguard-dns.com",

  // Cisco OpenDNS
  opendns: "https://doh.opendns.com",
};

// 动态自定义上游安全白名单 (防止被用作通用代理)
const ALLOWED_UPSTREAM_HOSTS = new Set([
  "1.1.1.1",
  "1.0.0.1",
  "cloudflare-dns.com",
  "security.cloudflare-dns.com",
  "family.cloudflare-dns.com",
  "dns.google",
  "dns.quad9.net",
  "dns.alidns.com",
  "doh.pub",
  "doh.360.cn",
  "dns.adguard-dns.com",
  "doh.opendns.com",
]);

// CORS 跨域响应头及 HTTP/3 (QUIC) 协商通告
const RESPONSE_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS, HEAD",
  "Access-Control-Allow-Headers": "Content-Type, Accept, Cache-Control",
  "Access-Control-Max-Age": "86400",
  // 指示客户端支持 HTTP/3 (QUIC) 极速连接
  "Alt-Svc": 'h3=":443"; ma=86400, h3-29=":443"; ma=86400',
};

export default {
  async fetch(request) {
    const method = request.method;

    // 1. 处理 OPTIONS 跨域预检请求
    if (method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: RESPONSE_HEADERS,
      });
    }

    const url = new URL(request.url);
    const path = url.pathname;
    const searchParams = url.searchParams;

    // 2. DNS 请求规范校验 (Stealth Mode: 隐蔽防探测)
    // RFC 8484 GET: 携带 dns 参数
    // DNS-JSON GET: 携带 name 参数
    // RFC 8484 POST: Content-Type 包含 application/dns-message 或二进制流
    const isDnsWireGet = method === "GET" && searchParams.has("dns");
    const isDnsJsonGet = method === "GET" && searchParams.has("name");
    const contentType = request.headers.get("content-type") || "";
    const isDnsWirePost = method === "POST" && (
      contentType.includes("application/dns-message") ||
      contentType.includes("application/octet-stream") ||
      contentType === ""
    );

    // 拦截非 DNS 规范的探测请求 (防恶意扫描、防探针，不暴露代理特征)
    if (!isDnsWireGet && !isDnsJsonGet && !isDnsWirePost && method !== "HEAD") {
      return new Response(null, { status: 404 });
    }

    // 3. 路由与上游 DNS 地址解析
    let upstreamBase = "";
    const cleanPath = path.replace(/^\/+|\/+$/g, ""); // 去除首尾斜杠

    if (cleanPath === "" || cleanPath === "dns-query" || cleanPath === "resolve") {
      // 默认上游：Cloudflare DNS
      const subPath = cleanPath === "resolve" ? "/resolve" : "/dns-query";
      upstreamBase = `${UPSTREAM_SERVERS.default}${subPath}`;
    } else {
      const slashIndex = cleanPath.indexOf("/");
      const firstSegment = (slashIndex === -1 ? cleanPath : cleanPath.slice(0, slashIndex)).toLowerCase();
      const restPath = slashIndex === -1 ? "" : cleanPath.slice(slashIndex + 1);

      if (firstSegment in UPSTREAM_SERVERS) {
        // 匹配到预设别名
        const serverOrigin = UPSTREAM_SERVERS[firstSegment];
        const subPath = restPath ? `/${restPath}` : "/dns-query";
        upstreamBase = `${serverOrigin}${subPath}`;
      } else {
        // 动态自定义上游解析 (例如 /dns.google/dns-query 或 /https://dns.google/dns-query)
        let customTarget = cleanPath;
        if (customTarget.startsWith("https:/") && !customTarget.startsWith("https://")) {
          customTarget = customTarget.replace("https:/", "https://");
        } else if (!customTarget.startsWith("https://") && !customTarget.startsWith("http://")) {
          customTarget = "https://" + customTarget;
        }

        try {
          const parsedCustom = new URL(customTarget);
          if (ALLOWED_UPSTREAM_HOSTS.has(parsedCustom.hostname)) {
            const targetPath = parsedCustom.pathname && parsedCustom.pathname !== "/"
              ? parsedCustom.pathname
              : "/dns-query";
            upstreamBase = `${parsedCustom.protocol}//${parsedCustom.hostname}${targetPath}`;
          } else {
            // 未在安全白名单内的上游域名拒绝代理
            return new Response(null, { status: 403 });
          }
        } catch (_) {
          return new Response(null, { status: 404 });
        }
      }
    }

    // 4. 构造向上游发起的完整目标 URL
    const targetUrl = new URL(upstreamBase);
    for (const [key, val] of searchParams.entries()) {
      targetUrl.searchParams.set(key, val);
    }

    // 5. 构造透传请求 (剔除敏感客户端 Header，保护隐私与 ECS 安全)
    const initHeaders = new Headers(request.headers);
    initHeaders.delete("Host");
    initHeaders.delete("X-Forwarded-For");
    initHeaders.delete("X-Real-IP");
    initHeaders.delete("CF-Connecting-IP");
    initHeaders.delete("CF-Ray");
    initHeaders.delete("CF-IPCountry");
    initHeaders.delete("CF-Visitor");
    initHeaders.delete("Referer");
    initHeaders.delete("Origin");

    // 补齐规范的 Accept 头
    if (isDnsJsonGet && !initHeaders.has("Accept")) {
      initHeaders.set("Accept", "application/dns-json");
    } else if (isDnsWireGet && !initHeaders.has("Accept")) {
      initHeaders.set("Accept", "application/dns-message");
    }

    const init = {
      method: method,
      headers: initHeaders,
      redirect: "follow",
    };

    if (method !== "GET" && method !== "HEAD") {
      init.body = request.body;
      init.duplex = "half";
    }

    // 6. 发起上游 DNS 请求并优化响应
    try {
      const response = await fetch(targetUrl.toString(), init);
      const resHeaders = new Headers(response.headers);

      // 注入 CORS 与 HTTP/3 通告头
      for (const [key, val] of Object.entries(RESPONSE_HEADERS)) {
        resHeaders.set(key, val);
      }

      // 边缘缓存优化：如果上游返回成功且缺少 Cache-Control，设置默认缓存以充分利用 Anycast 边缘节点加速
      if (response.status === 200 && !resHeaders.has("Cache-Control")) {
        resHeaders.set("Cache-Control", "public, max-age=60, stale-while-revalidate=120");
      }

      return new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers: resHeaders,
      });
    } catch (_) {
      return new Response(null, { status: 502 });
    }
  },
};

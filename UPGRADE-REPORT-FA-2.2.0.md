# گزارش ارتقای Gozargah 2.2.0

## هدف

افزایش دامنهٔ پروتکل‌ها و transportها بدون تولید کانفیگ‌های ظاهراً معتبر ولی غیرقابل‌اجرا روی Cloudflare Worker.

## قابلیت‌های اضافه‌شده

### پروتکل‌ها
- VLESS
- VMess
- Shadowsocks
- HTTP
- Trojan
- WireGuard
- Hysteria2

### Transport / ALPN
- TCP
- mKCP/KCP
- WebSocket
- HTTPUpgrade
- XHTTP
- gRPC
- h2
- http/1.1
- h3
- ALPN presets:
  - h3
  - h2
  - http/1.1
  - h2 + http/1.1
  - h3 + h2
  - h3 + h2 + http/1.1

## معماری

پشتیبانی به دو سطح تقسیم شده است:

1. **native-edge**: پروفایل‌هایی که همین Worker در data-plane فعلی واقعاً می‌تواند مدیریت کند؛ در 2.2.0 شامل VLESS/WebSocket و Trojan/WebSocket است.
2. **origin-engine**: پروفایل‌هایی که برای termination واقعی به Xray/sing-box روی origin نیاز دارند. این حالت با `ORIGIN_ENGINE_HOST` و `ORIGIN_ENGINE_PORT` فعال می‌شود.

پروتکل‌های UDP-native مانند WireGuard و Hysteria2 عمداً به‌عنوان Worker-native علامت نمی‌خورند؛ برای آن‌ها یک engine با UDP واقعی لازم است.

## APIهای جدید

- `GET /<panel>/api/network/capabilities`
- `GET /<sub>/<token>/profiles`
- `GET /<sub>/<token>/capabilities`

## Adaptive Selection

ترتیب اولیهٔ انتخاب به‌صورت bounded و deterministic است و native WebSocket قبل از origin profiles قرار می‌گیرد. در لایهٔ بالاتر می‌توان health telemetry موجود در D1 را برای تغییر اولویت profileها استفاده کرد.

## اعتبارسنجی

- TypeScript source-only typecheck با shim محیط Cloudflare: **PASS**
- TypeScript transpile syntax check: **39 فایل / PASS**
- protocol catalog executable smoke test: **PASS**
- package.json / package-lock.json: **2.2.0**
- آرشیو نهایی بدون `node_modules` ایجاد شد.

## محدودیت‌های آگاهانه

Cloudflare Workers در حال حاضر HTTP/HTTPS و WebSocket را ورودی می‌پذیرد و inbound raw TCP برای Worker به‌صورت عمومی در دسترس نیست؛ در مقابل outbound TCP socket از `connect()` موجود است. بنابراین Worker به‌تنهایی نباید WireGuard/Hysteria2 یا listenerهای TCP خام را native اعلام کند.

این طراحی دربارهٔ «عبور تضمینی از قطع کامل اینترنت بین‌الملل» ادعایی ندارد؛ فقط بین مسیرهای واقعاً موجود و engineهای متصل failover تطبیقی انجام می‌دهد.

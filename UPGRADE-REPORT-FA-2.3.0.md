# گزارش ارتقای Gozargah 2.3.0

## هدف

نسخه 2.3.0 هسته را از «فهرست پروتکل‌ها» به «Adaptive Protocol Orchestrator» ارتقا می‌دهد.
یعنی Worker دیگر صرفاً اعلام نمی‌کند که یک پروتکل وجود دارد؛ بلکه compatibility، نوع اجرا، security،
ALPN و تنوع transport را در یک policy واحد رتبه‌بندی می‌کند.

## قابلیت‌های جدید

### 1. Adaptive Protocol Policy

فایل جدید:
`src/protocols/policy.ts`

برای هر capability معتبر، پروفایل‌های security سازگار ساخته می‌شود و خروجی شامل این موارد است:

- protocol
- transport
- security
- ALPN
- native-edge / origin-engine
- UDP requirement
- readiness
- bounded score
- rationale

در پیکربندی فعلی، وقتی origin engine تنظیم شده باشد، 52 پروفایل آماده برای policy قابل شناسایی است.

### 2. Origin Engine Orchestration

پارامترهای جدید:

- `ORIGIN_ENGINE_HOST`
- `ORIGIN_ENGINE_PORT`
- `ORIGIN_ENGINE_SNI`
- `ORIGIN_ENGINE_PATH`
- `ORIGIN_ENGINE_GRPC_SERVICE`
- `ORIGIN_ENGINE_TRANSPORTS`

به‌طور پیش‌فرض این transportها برای Xray خروجی داده می‌شوند:

- XHTTP
- gRPC
- HTTPUpgrade
- WebSocket

Xray configuration اکنون خانواده‌ای از outboundهای origin مانند VLESS/XHTTP، VLESS/gRPC،
VLESS/HTTPUpgrade، VMess/WS و Trojan/WS/XHTTP را به‌صورت adaptive تولید می‌کند و observatory +
leastPing را حفظ می‌کند.

### 3. Adaptive Manifest

`/sub/<token>/profiles` اکنون علاوه بر capability matrix شامل `adaptive_policy` است.
کلاینت/engine می‌تواند این manifest را به‌عنوان لیست اولویت استفاده کند.

### 4. API جدید

`GET /<panelPath>/api/network/policy`

این endpoint policy، محدودیت‌ها و آماده‌بودن origin engine را نشان می‌دهد.

## Worker-native در برابر origin-engine

Cloudflare Workers ورودی HTTP/HTTPS، WebSocket و HTTP/3 دارد، اما ورودی direct TCP هنوز عمومی نشده است؛
در مقابل، Workers برای outbound TCP از `connect()` پشتیبانی می‌کند. بنابراین WireGuard/Hysteria2 و
سایر UDP/raw-TCP profiles در Worker به‌عنوان native termination ادعا نمی‌شوند و فقط در origin-engine
family قرار می‌گیرند.

## AI / intelligence

هسته local learner، resilience engine، quarantine، circuit breaker، health quorum و dynamic Workers AI
discovery از 2.2.0 حفظ شده‌اند. در 2.3.0 لایه policy بالای آن‌ها اضافه شده است.

AI همچنان نباید مستقیماً byte-level networking را بازنویسی کند؛ مدل برای تحلیل و انتخاب محدود استفاده
می‌شود و policy deterministic جلوی تغییرات غیرقابل‌کنترل را می‌گیرد.

## تست‌ها

- production TypeScript typecheck با Cloudflare shim: PASS
- runtime compile برای production source: PASS
- protocol catalog test: PASS
- adaptive subscription/Xray smoke test: PASS
- 52 ready adaptive profiles با origin engine پیکربندی‌شده: PASS
- 2 native-edge capabilities: PASS
- origin Xray outbounds برای XHTTP/gRPC/HTTPUpgrade/WS: PASS

تست کامل `npm test` در محیط فعلی فقط به وجود dependencyهای نصب‌شده نیاز دارد؛ registry/cache کامل
در محیط اجرای مدل موجود نبود، بنابراین ادعای اجرای کامل integration suite داده نمی‌شود.

## محدودیت فنی

هیچ AI یا Worker نمی‌تواند در صورت نبودن upstream واقعی، یک مسیر فیزیکی جدید به اینترنت جهانی ایجاد کند.
این نسخه روی resilience، failover، profile diversification، health-aware selection و recovery کار می‌کند؛
«عبور تضمینی از قطع کامل بین‌الملل» ادعای فنی معتبری نیست.

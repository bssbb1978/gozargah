# گزارش ارتقای Gozargah 2.1.0

## هستهٔ جدید

- حلقهٔ health زمان‌بندی‌شده برای مسیرهای ازپیش‌تعریف‌شده در D1
- طبقه‌بندی چندسیگنالهٔ وضعیت شبکه با quorum
- ذخیرهٔ `network_state` در D1
- endpoint احراز‌شدهٔ `GET /api/network/state`
- حفظ موتور Edge Learner و Circuit Breaker نسخهٔ 2.0
- حفظ failover پویا و quarantine

## رفتار حلقهٔ health

Worker هر ۵ دقیقه فقط endpointهایی را که در `proxyIPs` ذخیره شده‌اند، روی یکی از پورت‌های مجاز Cloudflare HTTPS probe می‌کند. هیچ اسکن رنج یا discovery عمومی انجام نمی‌شود.

پورت‌های پیش‌فرض: `443,2053,2083,2087,8443`

در صورت نیاز می‌توان با `HEALTH_PROBE_PORTS` فهرست را محدود کرد.

## Network State

وضعیت‌ها:

- `healthy`
- `degraded`
- `recovery`
- `no_healthy_path`

این طبقه‌بندی صرفاً سلامت مسیرهای تنظیم‌شده را توصیف می‌کند و به‌تنهایی اثبات‌کنندهٔ DPI یا قطع اینترنت بین‌الملل نیست.

## AI

Edge Learner داخلی بدون مدل اجرا می‌شود. Workers AI همچنان لایهٔ اختیاری برای diagnostics است و خرابی مدل نباید data-plane را متوقف کند.

## اعتبارسنجی

- parse همهٔ فایل‌های TypeScript
- typecheck در محیط Cloudflare با `@cloudflare/workers-types`
- unit tests برای network-state classifier و engine

## محدودیت

قطع کامل upstream بین‌المللی چیزی نیست که Cloudflare Worker بتواند از داخل خودش ایجاد کند. این نسخه فقط بین مسیرهای واقعاً موجود و endpointهای ازپیش‌تعریف‌شده adaptive failover و recovery انجام می‌دهد.

# گزارش ارتقای Gozargah 2.8.0 — Consensus Resilience Mesh

## هدف

نسخهٔ 2.8.0 لایهٔ تصمیم‌گیری را از «پیش‌بینی + Guard» به یک **Consensus Resilience Mesh** ارتقا می‌دهد. تصمیم تغییر policy فقط با یک سیگنال انجام نمی‌شود؛ چند سیگنال مستقلِ aggregate باید هم‌جهت باشند.

## قابلیت‌های جدید

### 1) Multi-Signal Policy Fusion
سیگنال‌های زیر ترکیب می‌شوند:

- سلامت اندازه‌گیری‌شدهٔ profile
- forecast موفقیت
- احتمال مدل محلی Edge Learner
- confidence وضعیت شبکه
- freshness داده
- failure-rate
- volatility
- تعداد نمونه
- quarantine state

خروجی bounded شامل:

- `consensus`
- `agreement`
- `uncertainty`
- `switchRisk`
- `fusionMode`

حالت‌ها:

- `stable`
- `cautious`
- `recovery`
- `insufficient_evidence`

این لایه payload را بررسی نمی‌کند و از روی telemetry نمی‌گوید DPI یا قطعی بین‌المللی «اثبات شده» است.

### 2) Adaptive Guard v3 gate
Guard اکنون برای promotion دو کنترل اضافه دارد:

- حداقل consensus: `0.58`
- حداکثر switch-risk: `0.58`

بنابراین یک candidate می‌تواند از نظر یک metric بهتر باشد ولی اگر سیگنال‌ها با هم اختلاف داشته باشند، به‌جای promotion در حالت staged/recovery می‌ماند.

### 3) D1 persistence
جدول جدید:

`policy_signal_state`

و ستون‌های جدید در `protocol_policy_state`:

- `consensus`
- `signal_agreement`
- `switch_risk`
- `fusion_mode`

Schema version:

`14`

Migrationها guarded هستند و روی پایگاه‌های قدیمی با `ALTER TABLE` فقط در صورت نبود ستون اجرا می‌شوند.

### 4) Network Fusion API
endpoint جدید:

`GET /{panelPath}/api/network/fusion`

برای observability فقط. این endpoint صراحتاً نشان می‌دهد که خروجی observational است و برای اثبات یک مکانیزم فیلترینگ استفاده نمی‌شود.

### 5) Live Adaptive Manifest v7
manifest adaptive اکنون علاوه بر plan/guard اطلاعات consensus را نیز منتقل می‌کند:

- consensus
- signalAgreement
- switchRisk
- fusionMode

### 6) Scheduler integration
health scheduler در همان چرخهٔ Cron:

`health → forecast → protocol plan → guard → fusion state → D1 persistence`

را انجام می‌دهد.

## مدل هوش داخلی

Edge Learner محلی همچنان فعال است و بدون LLM می‌تواند تصمیم بگیرد. Workers AI یک لایهٔ اختیاری برای diagnostics است و سیستم اصلی برای کارکرد شبکه به آن وابسته نیست.

Cloudflare در مستندات فعلی کاتالوگ Workers AI را با 65 مدل نشان می‌دهد و امکان جست‌وجوی مدل‌های جدید را فراهم کرده است؛ بنابراین discovery زنده به‌جای فهرست ثابت همچنان معماری اصلی باقی مانده است. مدل‌های جدیدی مانند GLM-5.2 و Kimi K2.7 Code نیز در changelog فعلی Cloudflare ثبت شده‌اند. 

## اعتبارسنجی

- Production TypeScript typecheck با shim APIهای Cloudflare: **PASS**
- Transpile/syntax check برای 47 فایل TypeScript: **PASS / 0 errors**
- Syntax check تمام `.mjs`: **PASS**
- Version metadata: **2.8.0 / 2.8.0**
- Focused Fusion smoke test: **PASS**
- Controller smoke test: **PASS**
- Guard promotion/recovery smoke test: **PASS**

تست کامل `npm test` در این محیط اجرا نشد چون `esbuild` در `node_modules` وجود ندارد؛ این موضوع به‌عنوان تست سبز ادعا نشده است.

## محدودیت فنی

این نسخه برای resilience، failover، recovery، تنوع protocol/transport، پیش‌بینی و جلوگیری از policy flapping قوی‌تر شده است. با این حال:

- Worker نمی‌تواند از هیچ، یک upstream جدید برای اینترنت ایجاد کند.
- telemetry به‌تنهایی اثبات نمی‌کند که DPI، قطعی بین‌الملل یا یک مکانیزم خاص فیلترینگ فعال است.
- protocolهای UDP مانند WireGuard/Hysteria2 همچنان برای data-plane واقعی به origin engine مناسب نیاز دارند؛ Worker صرفاً قابلیت را مدیریت/اعلام می‌کند.

## منابع فنی فعلی

- Cloudflare Workers protocols: HTTP/HTTPS، WebSocket، HTTP/3 و outbound TCP sockets مستند شده‌اند؛ inbound raw TCP عمومی نشده است.
- Cron Triggers و `scheduled()` برای health loop رسمی هستند.
- Workers AI Model Catalog برای discovery پویا استفاده می‌شود.

منابع: https://developers.cloudflare.com/workers/reference/protocols/ ; https://developers.cloudflare.com/workers/configuration/cron-triggers/ ; https://developers.cloudflare.com/workers-ai/models/ ; https://developers.cloudflare.com/changelog/post/2026-05-08-planned-model-deprecations/

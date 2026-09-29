# گزارش ارتقای Gozargah 2.5.0 — Self-Healing Adaptive Guard

## هدف

این نسخه یک لایهٔ جدید بالای Adaptive Protocol Controller نسخهٔ 2.4 اضافه می‌کند تا تغییر policyها کنترل‌شده، قابل‌ردگیری و ضد نوسان شود.

## قابلیت‌های جدید

### 1) Adaptive Guard / Canary

- policy جدید ابتدا می‌تواند `staged` شود.
- پنجرهٔ نگه‌داری bounded برابر 10 دقیقه دارد.
- اگر confidence به‌طور معنی‌دار بهتر شود، promotion انجام می‌شود.
- اگر profile فعال خراب شود، policy جدید می‌تواند فوراً promotion شود.
- تعداد rollbackها در D1 ثبت می‌شود.

### 2) D1 State

جدول جدید:

`adaptive_guard_state`

شامل:
- active plan
- previous plan
- staged plan
- status
- holdUntil
- rollbackCount
- updatedAt

### 3) Network Signal Fusion

وضعیت شبکه علاوه بر `healthy/degraded/recovery/no_healthy_path` اکنون یک signal class و anomaly score دارد:

- `normal`
- `broad_degradation`
- `selective_degradation`
- `insufficient_evidence`

این فقط یک طبقه‌بندی مشاهده‌ای روی telemetry مسیرهای پیکربندی‌شده است و تشخیص قطعی DPI، سانسور یا قطع اینترنت محسوب نمی‌شود.

### 4) Audit Trail

promotion/staging/rollback موتور policy در `events` ثبت می‌شود تا اپراتور بتواند تغییرات خودکار را بررسی کند.

### 5) API جدید

`GET /{panelPath}/api/network/guard`

اطلاعات guard فعلی، staged fingerprint، rollback count و semantics تصمیم‌گیری را ارائه می‌دهد.

## منطق AI داخلی

Edge Learner محلی همچنان در Worker باقی مانده و Guard تصمیم نهایی را bounded می‌کند. Workers AI اختیاری است و برای diagnostics/model assistance به کار می‌رود؛ هیچ LLM مستقیماً packet bytes را rewrite نمی‌کند.

## محدودیت‌های واقعی

Cloudflare Workers طبق مستندات فعلی ورودی HTTP/HTTPS، WebSocket و HTTP/3 و خروجی TCP با `connect()` دارد؛ inbound raw TCP عمومی نیست. در نتیجه WireGuard/Hysteria2 و سایر UDP-native capabilities همچنان به origin engine نیاز دارند. همچنین اگر upstream بین‌المللی واقعاً کاملاً قطع باشد، Worker نمی‌تواند یک مسیر فیزیکی جدید به اینترنت ایجاد کند.

## اعتبارسنجی

- Production TypeScript typecheck با shim APIهای Worker: **PASS**
- Pure engine compile: **PASS**
- Adaptive Guard smoke test: **PASS**
- Signal-fusion smoke test: **PASS**
- `npm run test:engine`: **NOT RUNNABLE IN THIS ENVIRONMENT** چون `esbuild` داخل `node_modules` موجود نیست.

## نسخه

`2.5.0`

SHA-256 در فایل جداگانهٔ release ارائه می‌شود.

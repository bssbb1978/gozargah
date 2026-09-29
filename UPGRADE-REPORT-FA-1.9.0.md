# Gozargah 1.9.0 — گزارش ارتقای ذره‌بینی

## هستهٔ جدید

نسخهٔ 1.9.0 روی نسخهٔ 1.8.0 ساخته شده و معماری را از «سلامت ProxyIP» به سه لایهٔ مستقل ارتقا می‌دهد:

1. **Path Intelligence**: سلامت مسیر/ProxyIP، latency، EWMA، failure-rate، trend، freshness و quarantine.
2. **Profile Intelligence**: سلامت پروفایل اتصال، مستقل از مسیر؛ چهار پروفایل محدود و deterministic:
   - `standard`
   - `fragmented`
   - `alt-port`
   - `fragmented-alt`
3. **Local Policy Brain**: موتور تصمیم‌گیری محلی که حتی بدون Workers AI کار می‌کند و فقط بین گزینه‌های از پیش تعریف‌شده انتخاب می‌کند.

## اتصال به data-plane

پارامتر `gz_profile` به WebSocket profile path اضافه شده است. Worker این مقدار را فقط از چهار مقدار مجاز قبول می‌کند و telemetry اتصال واقعی را به D1 می‌فرستد.

بنابراین health فقط داشبورد نیست؛ اتصال واقعی روی امتیاز مسیر اثر می‌گذارد و انتخاب Xray نیز با observatory/leastPing بین پروفایل‌های تولیدشده انجام می‌شود.

## D1

جدول جدید:

`profile_health`

فیلدها:

- `profile_id`
- `latency_ms`
- `ok`
- `failures`
- `successes`
- `quarantine_until`
- `checked_at`
- `consecutive_failures`
- `consecutive_successes`

Schema version از 5 به 6 تغییر کرد.

## Workers AI

رتبه‌بندی discovery مدل‌ها دیگر فقط بر اساس جدیدترین تاریخ نیست. مدل‌ها با یک heuristic محدود بر اساس metadata موجود در catalog امتیاز می‌گیرند:

- reasoning / thinking
- function calling / tool calling
- vision / multimodal
- long context / large context
- نشانه‌های سرعت مثل fast/flash/turbo
- تازگی مدل
- اندازهٔ context وقتی در metadata موجود باشد

Cloudflare در کاتالوگ جاری مدل‌های متعددی دارد و Model Search رسمی بر اساس نام/شرح و metadata قابل استفاده است. این نسخه مدل را «هوشمندانه‌تر» انتخاب می‌کند اما این score هرگز benchmark مستقل یا اثبات «بهترین مدل دنیا» نیست.

## Xray adaptive ensemble

Xray اکنون در حالت خنثی حداقل دو profile دارد و در presetهای اپراتوری می‌تواند ensemble کامل چهارحالته بسازد. `leastPing` روی outbounds کاربردی اجرا می‌شود و transportهای داخلی `gzx-*` وارد balancer نمی‌شوند.

پروفایل‌ها از preset صریح کاربر ساخته می‌شوند و موتور مقادیر تصادفی یا خارج از محدوده تولید نمی‌کند.

## پنل

endpoint جدید:

`GET /{panelPath}/api/network/profiles`

خروجی شامل:

- profile decision
- score
- state
- confidence
- trend
- quarantine
- persistence mode

است.

## محدودیت واقعی

این نسخه **تضمین نمی‌کند که هر DPI یا هر نوع قطع اینترنت را دور بزند**. Worker نمی‌تواند در صورت قطع کامل upstream یک مسیر فیزیکی جدید به اینترنت ایجاد کند. معماری فقط بین مسیرها و پروفایل‌هایی که واقعاً قابل دسترسی هستند adaptive failover و recovery انجام می‌دهد.

همچنین Local Policy Brain یک مدل زبانی/LLM محلی نیست؛ یک policy engine deterministic و مقاوم در برابر خرابی AI است. Workers AI در صورت فعال‌بودن نقش تحلیل‌گر اختیاری را دارد.

## کنترل کیفیت

- تعداد فایل‌های TypeScript که با TypeScript transpiler بررسی شدند: **34**
- syntax diagnostics: **0**
- ساخت Xray با یک harness مستقل و mock import بررسی شد:
  - JSON معتبر
  - profile path شامل `gz_profile`
  - observatory فعال
  - balancer فعال
  - profileهای fragment داخل transport جدا
  - transport داخلی وارد selector نشده است
- تست کامل `npm test` در محیط فعلی قابل اجرای کامل نبود چون dependencyهای npm موجود نیستند و نصب registry timeout/در حالت offline با `ENOTCACHED` متوقف شد.

## فایل‌های اصلی تغییرکرده

- `src/ai/edge-brain.ts`
- `src/ai/diagnostics.ts`
- `src/ai/resilience.ts`
- `src/config.ts`
- `src/db/store.ts`
- `src/handlers/websocket.ts`
- `src/panel/api.ts`
- `src/sub/operators.ts`
- `src/subscription.ts`
- `src/test/engine.ts`
- `src/test/worker.integration.test.ts`
- `package.json`
- `package-lock.json`
- `README.md`

نسخهٔ پروژه: **1.9.0**

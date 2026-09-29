# گزارش ارتقای Gozargah 2.1.0

## خلاصه

این نسخه روی پایهٔ 1.9.0 ساخته شده و «هوشمندی داخلی» را از heuristic صرف به یک موتور کوچک یادگیرندهٔ آنلاین تبدیل می‌کند. موتور دادهٔ خام ترافیک یا payload را ذخیره نمی‌کند و فقط از نتیجهٔ اتصال، latency، failure/success، freshness و trend استفاده می‌کند.

## تغییرات اصلی

### 1. Edge Learner داخلی
- `src/ai/edge-learner.ts`
- مدل logistic کوچک داخل Worker
- یادگیری آنلاین با SGD محدود
- وزن‌ها و bias در محدودهٔ ثابت نگه داشته می‌شوند
- UCB-style exploration برای جلوگیری از قفل‌شدن روی یک مسیر
- بدون نیاز به Workers AI

### 2. Adaptive Resilience v2
- ترکیب health score + local learner probability + exploration
- half-open recovery برای حداکثر دو مسیر وقتی همهٔ مسیرها نامناسب‌اند
- حفظ quarantine و circuit breaker
- preferred path برای هر کاربر
- confidence و learner confidence در تصمیم

### 3. حافظهٔ per-user در D1
جدول `user_adaptive_state`:
- مسیر ترجیحی
- پروفایل ترجیحی
- تعداد موفقیت/شکست
- آخرین وضعیت
- timestamp

در صورت موفقیت یک مسیر، ترجیح همان کاربر به آن مسیر تقویت می‌شود؛ در شکست، ترجیح همان مسیر/پروفایل می‌تواند کنار گذاشته شود.

### 4. سلامت مدل AI
جدول `ai_model_health`:
- موفقیت و شکست هر مدل
- quarantine موقت مدل خراب
- رتبه‌بندی مدل‌ها بر اساس نتیجهٔ واقعی
- fallback خودکار به مدل بعدی

### 5. Model Discovery پویا
کشف مدل‌ها از Model Search رسمی Cloudflare انجام می‌شود و مدل‌های deprecated/experimental از جست‌وجوی عادی حذف می‌شوند. شناسه‌های مدل‌هایی که در Cloudflare فعلاً Paid-only اعلام شده‌اند به‌صورت hard deny در fallback عمومی وارد نمی‌شوند؛ مدل‌های صریحاً تنظیم‌شده توسط اپراتور همچنان قابل انتخاب هستند.

### 6. Cloudflare Pages Advanced Mode
اضافه شد:
- `wrangler.pages.toml`
- `scripts/build-pages-worker.mjs`
- `npm run build:pages`

هدف: build همان Worker برای Pages Advanced Mode با D1 + Workers AI.

## APIهای جدید/به‌روزشده

- `GET /{panelPath}/api/network/resilience`
- `GET /{panelPath}/api/network/profiles`
- `GET /{panelPath}/api/network/brain`
- `POST /{panelPath}/api/network/probe`

`/network/brain` فقط telemetry تجمیعی مدل محلی را برمی‌گرداند و credential یا payload شبکه را نمایش نمی‌دهد.

## محدودیت مهم

این معماری «تضمین عبور از DPI» یا «ایجاد اینترنت بین‌الملل در زمان قطع کامل upstream» نیست. Worker فقط می‌تواند بین مسیرها/پروفایل‌های واقعاً پیکربندی‌شده و قابل‌دسترسی failover کند. موتور AI نیز مجاز به تولید تنظیمات دلخواه و دستکاری خودسرانهٔ protocol bytes نیست.

## اعتبارسنجی

- 35 فایل TypeScript: `PARSE_ERRORS=0`
- TypeScript با shim حداقلی محیط Cloudflare: `tsc EXIT=0`
- JSONهای package/lock/tsconfig: معتبر
- اسکریپت‌های `.mjs`: `node --check` موفق
- `npm ci --offline`: به دلیل نبود `youch-core` در cache npm اجرا نشد؛ بنابراین تست اجرایی کامل `npm test` را سبز اعلام نمی‌کنیم.

## نسخه

`2.1.0`

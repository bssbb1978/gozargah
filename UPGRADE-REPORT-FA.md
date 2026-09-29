# گزارش ارتقای Gozargah 2.10.0 — هوشمندی شبکه با دامنهٔ شواهد مشخص

## خلاصهٔ انتشار

نسخهٔ ۲.۱۰ یک طبقه‌بند محافظه‌کار برای وضعیت مسیرهای پیکربندی‌شده اضافه می‌کند و منبع نمونه‌های سلامت را از هم جدا می‌سازد. این تغییر ادعای «AI ضد DPI» نیست: یادگیری محلی و policy قطعی ۲.۹ حفظ شده‌اند؛ Workers AI همچنان فقط مشاور اختیاریِ خواندنی است.

## تغییرات واقعی

### ۱) طبقه‌بندی failure domain و condition

ماژول جدید `src/ai/network-intelligence.ts` خطا را فقط وقتی به DNS/TCP/TLS/HTTP/WebSocket و دسته‌های دیگر نسبت می‌دهد که پیام خطا یا برچسب مرحله شواهد قابل‌تشخیصی داشته باشد. timeout مبهم و خطای نامشخص `UNKNOWN` می‌ماند.

وضعیت‌های خروجی:

- `HEALTHY`
- `DEGRADED`
- `SEVERELY_DEGRADED`
- `PARTIALLY_UNREACHABLE`
- `UPSTREAM_UNAVAILABLE`
- `UNKNOWN`

`UPSTREAM_UNAVAILABLE` فقط یعنی حداقل سه endpoint پیکربندی‌شده، با مشاهدهٔ تازه از egress Worker همگی شکست خورده‌اند. این وضعیت اثبات قطعی اینترنت بین‌الملل یا DPI نیست. پاسخ همیشه `physicalUpstreamDisconnectionProven=false` و `dpiProven=false` دارد.

### ۲) نمونه‌های telemetry با منبع مشخص

از ستون `kind` موجود در جدول `health_samples` برای `path_tcp`، `path_dial` و `path_https` استفاده می‌شود. retention حداکثر ۲۴ نمونه برای هر منبع/موضوع است و خواندن آخرین نمونه‌ها با یک query محدود تا ۳۲ endpoint انجام می‌شود. `loadHealthSamples(..., 'path', ...)` تاریخچهٔ قدیمی را نگه می‌دارد و نمونه‌های tagged را هم برای پیش‌بینی ادغام می‌کند.

**Migration لازم نشد**؛ D1 schema همچنان ۱۴ است.

### ۳) API و رخداد

endpoint جدیدی اضافه نشده است. پاسخ موجود `GET /{panelPath}/api/network/state` حالا `condition` شامل state/confidence/evidence/recommendation/source/scope و آخرین مسیر سالم را نیز می‌دهد. scheduler کد condition را در `network_state.reason_codes` ذخیره و هنگام تغییر وضعیت، رخداد audit محدود ثبت می‌کند.

### ۴) ماتریس capability کامل‌تر

ماتریس نسخهٔ ۲.۹ حفظ و با `status`های `WORKER_NATIVE`، `ORIGIN_ENGINE_REQUIRED`، `UNSUPPORTED` و `DISABLED` تکمیل شده؛ `EXPERIMENTAL` رزرو است و در حال حاضر هیچ profile آزمایشی اعلام نمی‌شود. descriptor شامل layer، وجود generator، امکان live verification، نیاز پشتیبانی client، requirements/incompatibilities و risk class است. generatorهای origin از capabilityهای آماده و allowlist عبور می‌کنند.

## تغییرات AI

- هوش اصلی همچنان deterministic/local است: learner کوچک logistic، Bayesian reliability، forecast و signal fusion.
- Workers AI تغییری نکرده؛ برای تصمیم policy استفاده نمی‌شود و فقط diagnostics تجمیعی می‌سازد.
- کشف مدل زنده در صورت تنظیم token/account همچنان اختیاری است؛ فهرست fallback ثابت قبلی نیز باقی مانده و availability مدل‌ها تضمین نمی‌شود.
- AI اجازهٔ ساخت پروتکل، transport یا profile جدید ندارد.

## APIهای جدید

**هیچ‌کدام.** فقط پاسخ `network/state` و رخدادهای scheduler توسعه یافتند؛ مسیرهای قبلی و secrets تغییر نام ندادند.

## D1 و migration

- Schema: **۱۴**
- Migration: **ندارد**
- رده‌بندی source از ستون متنی `health_samples.kind` استفاده می‌کند؛ جدول و index موجودند.

## پروتکل‌ها

- `WORKER_NATIVE`: VLESS/WebSocket، Trojan/WebSocket.
- `ORIGIN_ENGINE_REQUIRED`: VLESS/XHTTP، gRPC، HTTPUpgrade؛ Trojan/XHTTP؛ VMess/WebSocket، با محدودیت پیکربندی و allowlist.
- `UNSUPPORTED`: WireGuard/UDP، Hysteria2/UDP، Shadowsocks، HTTP عمومی و pairهای بدون generator.
- Origin آمادهٔ تولید به معنی origin زندهٔ تأییدشده نیست.

## نتایج آزمون

- **PASS** `npm run typecheck`
- **PASS** `npm test`: ۳۶ تست engine، چهار suite pure logic به‌علاوهٔ suite جدید network intelligence، و ۱۲ تست Worker/D1
- **PASS** `npm run build`: Wrangler dry-run؛ استقرار انجام نشد
- **PASS** `npm audit`: صفر آسیب‌پذیری گزارش‌شده
- **PASS** `git diff --check`
- **NOT RUN** ESLint/formatter: script/config در repo وجود ندارد
- **NOT RUN** استقرار Cloudflare و آزمون live
- **REQUIRES LIVE ORIGIN** آزمون سازگاری Xray/sing-box
- **REQUIRES CLIENT** آزمون ISP، POP/region و رفتار واقعی کاربر

## محدودیت‌های فنی

1. probe زمان‌بندی‌شده فقط TCP open/close از egress کلودفلر است؛ TLS، WebSocket و application handshake جداگانه probe نمی‌شوند.
2. HTTPS HEAD دستی، HTTP status و خطای DNS/TLS را فقط تا حدی طبقه‌بندی می‌کند که runtime آن را آشکار کند.
3. هیچ client telemetry، POP/region correlation، origin adapter، domain ownership graph یا dynamic fragmentation tuner در این انتشار اضافه نشد.
4. condition با مشاهدهٔ panel/state قابل محاسبه است؛ scheduler رخداد تغییر و کد state را ذخیره می‌کند، اما این classifier جایگزین controller قبلی نشده است.
5. قطع فیزیکی همهٔ upstreamها با AI یا Worker قابل بازسازی نیست؛ سیستم فقط last-known-good و recovery probe محدود را گزارش/ادامه می‌دهد.
6. این انتشار در production مستقر یا از شبکهٔ ایران آزمایش نشده است؛ بنابراین موفقیت دورزدن فیلترینگ/DPI ادعا نمی‌شود.

## فایل‌های انتشار

- `release.tar.gz`
- `release.sha256`
- `UPGRADE-REPORT-FA.md`

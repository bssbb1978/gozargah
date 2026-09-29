# گزارش ارتقای Gozargah 2.7.0

## عنوان
Predictive Resilience Mesh

## هدف
این نسخه یک لایهٔ پیش‌بین محلی و سبک بالای Adaptive Guard اضافه می‌کند. تصمیم‌ها همچنان bounded و قابل rollback هستند و Worker ادعا نمی‌کند که می‌تواند هویت سانسورگر/DPI را با قطعیت تشخیص دهد یا هنگام قطع کامل upstream اینترنت جدید بسازد.

## قابلیت‌های جدید

### 1) Predictive Mesh داخلی
ماژول `src/ai/predictive-mesh.ts` از حداکثر 24 نمونهٔ اخیر هر path/profile استفاده می‌کند و این سیگنال‌ها را محاسبه می‌کند:
- reliability
- EWMA latency
- latency volatility
- success slope
- latency slope
- drift: improving / stable / degrading
- forecastSuccess
- confidence

این مدل deterministic و کوچک است و برای اجرای داخل Worker طراحی شده است.

### 2) D1 Health History
دو جدول جدید اضافه شده‌اند:
- `health_samples`
- `predictive_state`

تاریخچه به‌صورت bounded نگه‌داری می‌شود و برای هر path/profile حداکثر 24 نمونهٔ اخیر حفظ می‌شود.

### 3) Forecast-aware Protocol Selection
`protocol-controller` علاوه بر score، health و Bayesian/UCB از forecast استفاده می‌کند.
- روند رو به بهبود امتیاز می‌گیرد.
- روند رو به افت جریمه می‌شود.
- volatility بالا باعث احتیاط می‌شود.
- نتیجه در policy fingerprint لحاظ می‌شود.

### 4) Adaptive Guard v2.1
Promotion فقط با confidence gain انجام نمی‌شود. یکی از این دو شرط لازم است:
- confidence gain معنادار
- forecast gain حداقل 0.06

همچنین اگر volatility کاندید بالا باشد promotion مسدود می‌شود، مگر اینکه active واقعاً unhealthy باشد.

### 5) Live Subscription v4
Manifest تطبیقی اطلاعات پیش‌بین را نیز مصرف می‌کند و fallback ladder روی forecast فعلی ساخته می‌شود.

### 6) Endpoint جدید
`GET /{panelPath}/api/network/forecast`

خروجی شامل forecast موفقیت، drift، volatility، تعداد نمونه و زمان آخرین مشاهده است.

## سازگاری
State قدیمی Adaptive Guard در D1 به plan جدید normalize می‌شود و برای فیلدهای جدید default امن اعمال می‌گردد.

## اعتبارسنجی
- Production TypeScript typecheck با shim APIهای Cloudflare: PASS
- predictive-mesh runtime smoke test: PASS
- protocol-controller runtime smoke test: PASS
- تمام فایل‌های `.mjs` با `node --check`: PASS
- JSON metadata (`package.json`, `package-lock.json`): PASS

تست کامل `npm test` وابسته به نصب `node_modules` است؛ این محیط dependencyهای npm پروژه را همراه archive ندارد، بنابراین اجرای end-to-end واقعی را ادعا نمی‌کنیم.

## مرزهای فنی
این ارتقا برای resilience، prediction، fallback، recovery، anti-flapping و انتخاب تطبیقی طراحی شده است. هیچ بخشی ادعای تشخیص قطعی DPI، تشخیص هویت اپراتور، یا ایجاد یک upstream بین‌المللی جدید در زمان قطع کامل اینترنت ندارد.

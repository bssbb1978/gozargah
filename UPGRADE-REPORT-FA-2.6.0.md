# گزارش ارتقای Gozargah 2.6.0

## عنوان
Resilience Mesh Controller + Self-Healing Adaptive Guard v2

## قابلیت‌های اصلی

### 1) Ensemble داخلی روی Edge
سیستم حالا برای امتیازدهی مسیر/پروفایل از سه سیگنال محلی استفاده می‌کند:
- Logistic online learner موجود در 2.x
- Bayesian reliability با posterior محافظه‌کارانه و credible band
- UCB-style bounded exploration

این لایه هیچ LLM یا runtime سنگینی برای تصمیم‌های اصلی لازم ندارد.

### 2) Failure-domain isolation
خانوادهٔ `protocol:transport` به‌عنوان failure domain محاسبه می‌شود. اگر یک خانواده نرخ شکست بالا و نمونهٔ کافی داشته باشد، در plan جدید penalty می‌گیرد تا همهٔ fallbackها در یک failure domain متمرکز نشوند.

### 3) سه حالت خودکار
- `stable`: وضعیت عادی و تعویض محافظه‌کارانه
- `diversify`: وقتی افت انتخابی/recovery دیده شود، تنوع transport بیشتر می‌شود
- `safe`: هنگام broad degradation یا نبود مسیر سالم، مسیرهای اندازه‌گیری‌شده و کم‌خطا ترجیح داده می‌شوند و exploration کاهش می‌یابد.

### 4) Adaptive Guard v2
Guard حالا علاوه بر canary/hold/rollback، بودجهٔ تغییر دارد:
- حداکثر 3 promotion در هر 30 دقیقه
- hold بعد از promotion برابر 15 دقیقه
- اگر active plan واقعاً خراب باشد، emergency promotion مجاز است.

### 5) D1 migration
state قدیمی Guard نسخهٔ 1 هنگام خواندن به نسخهٔ 2 تبدیل می‌شود و مقادیر جدید به‌صورت امن مقداردهی می‌شوند.

### 6) Manifest و policy
نسخهٔ live manifest به v6 ارتقا یافت و plan جدید این اطلاعات را نیز برمی‌گرداند:
- strategy
- failureDomains
- confidence
- fallback ladder
- guard state
- path selection

## تست
- Production TypeScript source typecheck با shim APIهای Cloudflare: PASS
- Engine smoke test: PASS
  - Bayesian reliability
  - risk-adjusted score
  - network signal classification
  - safe/diversify strategy
  - failure-domain penalty
  - change-budget guard
  - emergency recovery
- package/lock version consistency: PASS
- npm integration test کامل در این محیط قابل اجرا نیست چون dependencyهای `node_modules` نصب‌شده در runner موجود نیستند.

## مرزهای فنی
این نسخه از telemetry مسیرهای از قبل پیکربندی‌شده استفاده می‌کند و از آن برای تشخیص قطعی DPI یا نسبت‌دادن افت به یک سانسورگر خاص استفاده نمی‌کند. همچنین در صورت قطع کامل upstream بین‌الملل، Worker نمی‌تواند از هیچ یک مسیر فیزیکی جدید به اینترنت ایجاد کند؛ سیستم فقط بین مسیرها/profileهای واقعاً موجود adaptive failover و recovery انجام می‌دهد.

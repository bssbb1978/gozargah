# گزارش ارتقای Gozargah 2.4.0

## هستهٔ جدید

- Live Adaptive Protocol Controller
- Live Adaptive Manifest v4 با مسیر fallback پویا
- policy fingerprint برای audit/rollback
- تنوع اجباری protocol/transport/security در fallback ladder
- bias بازیابی در وضعیت degraded/recovery
- sticky per-user preference به‌عنوان ترجیح نرم
- bounded exploration برای پروفایل‌های بدون دادهٔ کافی
- ذخیرهٔ آخرین policy در D1 (`protocol_policy_state`)
- API: `/network/autoplan`
- API: `/network/policy-state`
- subscription: `/adaptive` یا `/autoadaptive`

## مدل هوش مصنوعی

- Edge learner داخلی و deterministic همچنان مرجع اصلی تصمیم است.
- Workers AI فقط لایهٔ اختیاری برای تحلیل/diagnostics است.
- هیچ مدل AI مجاز به تولید transport ناشناخته یا تغییر خودسرانهٔ bytes شبکه نیست.

## محدودیت فنی

Cloudflare Worker هنوز inbound raw TCP/UDP را به‌صورت عمومی ارائه نمی‌کند؛ بنابراین WireGuard/Hysteria2 و سایر UDP-native transports همچنان origin-engine capability هستند و Live Manifest این موضوع را صریح نگه می‌دارد.

## اعتبارسنجی

- protocol catalog smoke test
- protocol controller smoke test
- TypeScript typecheck با Cloudflare types/shim
- JSON generation tests

## به‌روزرسانی تکمیلی 2026-09-29

- scheduler اکنون علاوه بر health مسیر، `protocol_policy_state` را نیز هر چرخه تازه‌سازی می‌کند.
- manifest زنده با `/adaptive` بر اساس state موجود در D1 تولید می‌شود.
- لینک `subAdaptive` به API لینک‌های هر کاربر اضافه شد.
- فهرست fallback مدل‌های ثابت Workers AI با مدل‌های جدیدتر موجود در کاتالوگ فعلی همگام شد؛ discovery زنده همچنان اولویت دارد.

## نتیجهٔ تست نهایی

- Production TypeScript typecheck با Cloudflare shim: **PASS**
- Live protocol controller smoke test: **PASS**
- حالت recovery + preference quarantine test: **PASS**
- transport/protocol diversity test: **PASS**
- policy fingerprint test: **PASS**
- `scripts/test.mjs`: در این محیط به دلیل نبود `esbuild` در `node_modules` اجرا نشد (**dependency environment**, نه خطای کد)

## نکتهٔ صحت

پشتیبانی native Worker با capability واقعی Cloudflare محدود است؛ Worker ورودی WebSocket/HTTP(S)/HTTP3 دارد و outbound TCP با `connect()`، اما inbound raw TCP هنوز در مستندات رسمی «coming soon» است. بنابراین UDP-native مانند WireGuard/Hysteria2 در نسخهٔ فعلی فقط به‌عنوان origin-engine capability مدل می‌شوند.

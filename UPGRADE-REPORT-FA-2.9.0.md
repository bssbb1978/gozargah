# گزارش ارتقای Gozargah 2.9.0 — مرزبندی واقعی قابلیت‌ها

## خلاصه

این انتشار به‌جای افزودن ادعای «هوش مصنوعی ضد DPI»، capability catalog را با generatorهای واقعاً موجود هم‌راستا می‌کند. در نتیجه پنل دیگر transportهایی را که صرفاً نام یا قالب metadata داشتند به‌عنوان پروفایل آماده معرفی نمی‌کند. انتخاب‌گر محلی، پیش‌بینی، fusion، Guard و recovery موجود حفظ شده‌اند.

## تغییرات معماری واقعی

### ۱) ماتریس صریح protocol / transport / security

هر ترکیب اکنون این موارد را دارد:

- `boundary`: یکی از `WORKER_NATIVE`، `ORIGIN_ENGINE_REQUIRED` یا `UNSUPPORTED`
- `ready`: فقط وقتی generator این repository همان ترکیب را واقعاً تولید می‌کند و transport در تنظیم اپراتور مجاز است
- `security` و `alpn`: فقط مقادیر سازگار با profile ثبت‌شده
- `deploymentValidation`: تفکیک قابلیت Worker-native از origin اعلام‌شده ولی بررسی‌نشده
- `reason`: علت غیرقابل‌استفاده بودن یا نیاز به origin engine

`ORIGIN_ENGINE_HOST` فقط اعلام پیکربندی است؛ سلامت، نسخه یا سازگاری Xray/sing-box را اثبات نمی‌کند. پورت origin به عدد صحیح بازهٔ ۱ تا ۶۵۵۳۵ محدود است و پورت نامعتبر generation را fail-closed می‌کند. allowlist متغیر `ORIGIN_ENGINE_TRANSPORTS` روی ماتریس policy و templateهای adaptive اعمال می‌شود و transport ناشناخته حذف می‌شود.

### ۲) حذف پروفایل‌های metadata-only از اشتراک

قالب‌های WireGuard روی `h3`، Hysteria2 روی `h3`، Shadowsocks و HTTP عمومی که generator واقعی و data-plane لازم نداشتند، دیگر به‌عنوان template قابل استفاده صادر نمی‌شوند. WireGuard و Hysteria2 در ماتریس کامل با مرز `UNSUPPORTED` باقی می‌مانند؛ آن‌ها به UDP واقعی نیاز دارند و Worker این پروژه UDP ورودی terminate نمی‌کند.

### ۳) تست‌پذیری

Runner موتور اکنون چهار مجموعهٔ pure logic را اجرا می‌کند: engine، predictive mesh، protocol catalog و protocol controller. تست‌های جدید allowlist، boundary، status بررسی‌نشدهٔ origin، نبودن templateهای جعلی UDP، و خروجی adaptive را پوشش می‌دهند.

## نسخه

- برنامه: **Gozargah 2.9.0**
- D1 schema: **14** (بدون تغییر)
- Migration جدید: **ندارد**؛ این انتشار فقط منطق capability و serialization اشتراک را تغییر می‌دهد.

## APIها

endpoint تازه‌ای اضافه نشده است. قرارداد پاسخ این endpointهای موجود دقیق‌تر شده است:

- `GET /{panelPath}/api/network/capabilities` — ماتریس کامل و مرزهای capability
- `GET /{panelPath}/api/network/policy` — policy فقط از profileهای تولیدپذیر
- `GET /{subPath}/{token}/adaptive` — ماتریس، ترتیب adaptive و templateهای محدود به allowlist

## ماتریس قابلیت این نسخه

| پروتکل / انتقال | مرز | وضعیت |
|---|---|---|
| VLESS / WebSocket + TLS | `WORKER_NATIVE` | آماده؛ مسیر WebSocket خود Worker |
| Trojan / WebSocket + TLS | `WORKER_NATIVE` | آماده؛ مسیر WebSocket خود Worker |
| VLESS / XHTTP، gRPC، HTTPUpgrade | `ORIGIN_ENGINE_REQUIRED` | template فقط با host و transport مجاز؛ origin بررسی سلامت نشده |
| Trojan / XHTTP | `ORIGIN_ENGINE_REQUIRED` | template فقط با host و transport مجاز؛ origin بررسی سلامت نشده |
| VMess / WebSocket | `ORIGIN_ENGINE_REQUIRED` | template فقط با host و transport مجاز؛ origin بررسی سلامت نشده |
| WireGuard / UDP و Hysteria2 / UDP | `UNSUPPORTED` | generator و UDP data-plane در این Worker وجود ندارد |
| Shadowsocks، HTTP proxy عمومی و سایر زوج‌های اعلام‌نشده | `UNSUPPORTED` | هیچ template اجرایی در این repository وجود ندارد |

ALPNهای ثبت‌شدهٔ عمومی معتبرند، اما این انتشار برای هر ALPN صرفاً به‌خاطر وجود نام آن profile تولید نمی‌کند. مثلاً HTTP/3 در generator فعلی profile آماده ندارد.

## هوش مصنوعی و تصمیم‌گیری

- **هوش محلی:** Edge Learner، Bayesian reliability، predictive mesh، signal fusion، failure-family scoring و guard نسخهٔ قبل حفظ شده‌اند؛ این‌ها الگوریتم‌های آماری/قطعی‌اند، نه LLM.
- **Workers AI:** اختیاری و صرفاً برای diagnostics تجمیعی/خواندنی است. در این انتشار مدل جدیدی اضافه نشد و AI مجاز نیست config شبکه تولید یا فعال کند.
- **Discovery / fallback / health:** کشف کاتالوگ، اولویت مدل و cooldown/quarantine موجود بدون تغییر حفظ شده است.
- **مرز ایمنی:** هیچ مدلی نمی‌تواند transport ناسازگار یا پشتیبانی‌نشده را به capability آماده تبدیل کند.

## اعتبارسنجی

| مورد | وضعیت | نتیجه |
|---|---|---|
| TypeScript typecheck | **PASS** | `npm run typecheck` |
| Pure logic tests | **PASS** | engine: 36 check؛ predictive mesh، protocol catalog و controller نیز اجرا شدند |
| Worker + D1 integration | **PASS** | Vitest: 11/11 |
| Worker build / Cloudflare dry-run | **PASS** | `npm run build`؛ خروجی bundle حدود 394 KiB / gzip حدود 105 KiB |
| `npm audit` | **PASS** | صفر آسیب‌پذیری پس از pin امن patchهای transitive `undici` و `sharp` |
| D1 migration validation | **PASS** | migration جدیدی وجود ندارد؛ schema version 14 حفظ شد |
| ESLint / formatter | **NOT RUN** | این repository اسکریپت/config مربوطه ندارد |
| استقرار واقعی Cloudflare / آزمون live origin | **NOT RUN** | به‌هیچ‌وجه production-ready یا live-verified ادعا نمی‌شود |

## محدودیت‌ها

- این تغییر تضمین عبور از فیلترینگ، DPI، محدودیت اپراتور یا قطعی اینترنت بین‌الملل نیست و هیچ مکانیزم فیلترینگ را تشخیص قطعی نمی‌دهد.
- اگر upstream بین‌المللی کاملاً قطع باشد، Worker نمی‌تواند اینترنت یا مسیر فیزیکی جدید بسازد.
- health probeهای زمان‌بندی‌شده از egress کلودفلر اجرا می‌شوند؛ آن‌ها کیفیت مسیر کلاینت در ایران یا وضعیت منطقه‌ای ISP را مستقیماً اندازه نمی‌گیرند.
- هیچ origin engine از این محیط در دسترس نبود؛ templateهای origin فقط اعلام شده‌اند و با Xray/sing-box زنده تست نشدند.
- Worker این پروژه inbound خام TCP/UDP ندارد. UDP-native protocols تا زمان اضافه‌شدن و تست یک adapter واقعی `UNSUPPORTED` هستند.
- adaptation فقط بین مسیرها و پروفایل‌های واقعاً پیکربندی‌شده و قابل تولید تصمیم می‌گیرد؛ AI دسترسی شبکه خلق نمی‌کند.

## فایل‌های انتشار

- `release.tar.gz`
- `release.sha256`
- `UPGRADE-REPORT-FA.md`

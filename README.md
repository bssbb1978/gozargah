
# Gozargah 2.10.0 — Evidence-Scoped Network Intelligence

## 2.10.0 — Evidence-Scoped Network Intelligence
### 2.10.0 highlights
- `/api/network/state` now adds a conservative condition classification (`HEALTHY`, `DEGRADED`, `SEVERELY_DEGRADED`, `PARTIALLY_UNREACHABLE`, `UPSTREAM_UNAVAILABLE`, `UNKNOWN`) scoped to configured Worker-egress paths.
- TCP socket, live dial, and manual HTTPS HEAD observations are kept as distinct bounded D1 sample kinds in the existing health-sample table; no schema migration is needed.
- Error causes are classified only from recognizable stage evidence. Opaque timeouts stay `UNKNOWN`; all-path failure never proves a physical international outage or DPI.
- Local deterministic selection remains primary; Workers AI remains optional and cannot override capability checks.
- The full capability descriptor assigns each protocol/transport pair one of `WORKER_NATIVE`, `ORIGIN_ENGINE_REQUIRED`, `UNSUPPORTED`, `DISABLED`, or `EXPERIMENTAL` (no experimental profiles are currently generated).
- Profiles without a real generator are never advertised as ready; UDP-only WireGuard/Hysteria2 are explicitly unsupported by this Worker data plane.
- Origin profiles are emitted only for the configured transport allowlist and are labeled declared-but-not-tested; setting a hostname is not treated as an engine health check.
- Security and ALPN metadata are tied to the actual profile templates; unsupported combinations are excluded from adaptive policy.
- Multi-signal policy gating combines measured health, forecast, local learner, and network confidence before promotion.
- D1 persists consensus/agreement/switch-risk state; `/{panelPath}/api/network/fusion` exposes it for observability.
- Adaptive Guard blocks low-consensus/high-switch-risk promotions and falls back to staged/recovery behavior.

- Bayesian reliability + UCB exploration in the local edge ensemble.
- Failure-domain isolation by protocol/transport family.
- `stable / diversify / safe` strategy modes driven by observed network state.
- Emergency safe mode prefers measured, low-failure profiles during broad degradation.
- 3 changes per 30-minute window with 15-minute promotion hold to prevent policy flapping.
- Existing D1 telemetry, per-user preference, canary staging and rollback are preserved.


- canary/staged policy promotion with a bounded 10-minute hold window
- automatic promotion when the candidate is materially better or the active profile is unhealthy
- rollback history in D1 via `adaptive_guard_state`
- observational network anomaly score and signal class (`normal`, `broad_degradation`, `selective_degradation`, `insufficient_evidence`)
- new authenticated endpoint: `/{panelPath}/api/network/guard`
- audit events for adaptive policy promotions/staging/rollback
- local deterministic learner remains the final policy guard; Workers AI remains optional

### 2.10.0 engineering documents

- [Capability Matrix](CAPABILITY-MATRIX.md)
- [Adaptive Engine](ADAPTIVE-ENGINE.md)
- [AI Engine and limits](AI-ENGINE.md)
- [Failure Domains](FAILURE-DOMAINS.md)
- [Recovery Model](RECOVERY-MODEL.md)
- [2.10.0 Test Report](TEST-REPORT-2.10.0.md)
- [Persian Upgrade Report](UPGRADE-REPORT-FA-2.10.0.md)

2.5 continues the live protocol controller from 2.4 and adds a guard layer that
stages small policy changes before promotion, rolls back on active-profile failure,
and keeps a persistent previous/staged plan in D1.

New endpoints:
- `GET /{panelPath}/api/network/autoplan`
- `GET /{panelPath}/api/network/policy-state`
- `GET /{panelPath}/api/network/guard`
- `GET /{subPath}/{token}/adaptive` (live adaptive manifest v5)

The scheduled health loop refreshes health and policy every five minutes, so the
D1 state remains warm even without an active subscriber. Raw TCP/UDP inbound is
not available in this Worker data plane. This release advertises only profile
pairs with a real generator; UDP-native protocols remain `UNSUPPORTED` until a
real UDP-capable adapter is implemented and validated.

This release adds deterministic multi-signal path scoring, circuit-breaker recovery, connection-outcome telemetry, stable per-user ordering, and AI-model cooldown/failover. It does not claim to defeat a complete upstream international outage and does not fingerprint or rewrite protocol bytes.

<div align="center">

<picture>
  <source media="(prefers-color-scheme: light)" srcset="docs/hero-light.svg">
  <img src="docs/hero.svg" alt="گذرگاه — Gozargah · دروازهٔ امن عبور روی Cloudflare Workers" width="100%">
</picture>

# گذرگاه · Gozargah

**دروازهٔ امن عبور — پنل پروکسی چندکاربره روی Cloudflare Workers**

<sub>بدون سرور · بدون هزینه · بدون وابستگی — کل پنل در یک فایل</sub>

[![Release](https://img.shields.io/github/v/release/panelgozargah/gozargah?style=flat-square&labelColor=0B1020&color=00D9FF)](https://github.com/panelgozargah/gozargah/releases/latest)
[![License: MIT](https://img.shields.io/badge/license-MIT-2563EB?style=flat-square&labelColor=0B1020)](LICENSE)
[![Tests](https://img.shields.io/github/actions/workflow/status/panelgozargah/gozargah/test.yml?branch=main&style=flat-square&labelColor=0B1020&label=tests)](https://github.com/panelgozargah/gozargah/actions/workflows/test.yml)
[![Deploy](https://img.shields.io/github/actions/workflow/status/panelgozargah/gozargah/deploy.yml?branch=main&style=flat-square&labelColor=0B1020&label=deploy)](https://github.com/panelgozargah/gozargah/actions/workflows/deploy.yml)
[![Website](https://img.shields.io/website?url=https%3A%2F%2Fgozargah.dpdns.org%2F&style=flat-square&labelColor=0B1020&up_color=7C3AED)](https://gozargah.dpdns.org/)
[![Platform](https://img.shields.io/badge/☁️_Cloudflare_Workers-native-7C3AED?style=flat-square&labelColor=0B1020)](#-چرا-گذرگاه)
[![Storage](https://img.shields.io/badge/storage-D1_Relational-D946EF?style=flat-square&labelColor=0B1020)](#-سفر-یک-درخواست)
[![Protocols](https://img.shields.io/badge/protocols-VLESS_·_Trojan-00D9FF?style=flat-square&labelColor=0B1020)](#-چرا-گذرگاه)
[![Operators](https://img.shields.io/badge/operators-MCI_·_Irancell_·_Rightel_·_Shatel_·_TCI-22C55E?style=flat-square&labelColor=0B1020)](#-تیون-عمیق-اپراتور)
[![Xray](https://img.shields.io/badge/Xray-auto--best_leastPing-00D9FF?style=flat-square&labelColor=0B1020)](#-فرمت-xray--اتصال-خودکار-بهترین-مسیر)
[![UI](https://img.shields.io/badge/UI-Gozargah_Nexus-7C3AED?style=flat-square&labelColor=0B1020)](#-رابط-کاربری--gozargah-nexus-ui)
[![Runtime Deps](https://img.shields.io/badge/runtime_deps-zero-22C55E?style=flat-square&labelColor=0B1020)](#-چرا-گذرگاه)
[![i18n](https://img.shields.io/badge/i18n-FA_·_EN_RTL-2563EB?style=flat-square&labelColor=0B1020)](#-رابط-کاربری--gozargah-nexus-ui)

<picture>
  <source media="(prefers-color-scheme: light)" srcset="docs/stats-light.svg">
  <img src="docs/stats-dark.svg" alt="یک فایل · صفر وابستگی · چهار فرمت · پنج اپراتور · صد درصد رایگان" width="100%">
</picture>

<img src="docs/divider.svg" width="60%">

</div>

**گذرگاه** یک پنل پروکسی چندکاربرهٔ کامل است که به‌صورت بومی روی Cloudflare Workers زندگی می‌کند: یک فایل جاوااسکریپت که همه‌چیز داخلش تعبیه شده — پنل مدیریت، موتور پروکسی، اشتراک‌ساز، صفحهٔ وضعیت کاربر و تمام دارایی‌های رابط کاربری. نه سرور می‌خواهد، نه نصب، نه هزینه؛ یک اکانت رایگان کلودفلر و پنج دقیقه وقت کافی است تا یک پنل کامل با دیتابیس اختصاصی، داشبورد فارسی/انگلیسی و لینک اشتراک برای هر کاربر داشته باشید.

طراحی گذرگاه از روز اول با سه قاعده پیش رفته: **امنیت واقعی به‌جای نمایشی**، **حسابداری دقیق به‌جای تخمین**، و **مستقل بودن مطلق در زمان اجرا**. نسخهٔ ۱.۲ این قواعد را یک قدم جلوتر می‌برد: کانفیگ‌هایی که خودشان بهترین مسیر را پیدا می‌کنند، پریست‌های اختصاصی برای اپراتورهای ایران، و صفحه‌ای که کاربر شما با یک نگاه می‌فهمد «وصل هستم یا نه». نتیجه پنلی است که نه به سرویس ثالثی وابسته است، نه اطلاعات شما را از اکانت کلودفلر بیرون می‌برد و نه برای کارکردن به هیچ چیز دیگری نیاز دارد.

## ✨ چرا گذرگاه؟

<div align="center">

<picture>
  <source media="(prefers-color-scheme: light)" srcset="docs/features-light.svg">
  <img src="docs/features-dark.svg" alt="دوازده ویژگی کلیدی گذرگاه — از یک‌فایلی بودن تا تیون اپراتور و اتصال خودکار بهترین مسیر" width="100%">
</picture>

</div>

ایدهٔ پشت این دوازده کارت ساده است: هر چیزی که می‌تواند یک وابستگی، یک سرور یا یک نقطهٔ شکست باشد، حذف شده؛ و هر چیزی که تجربهٔ کاربر ایرانی را بهتر می‌کند، با دروازهٔ صداقت اضافه شده. پنل به هیچ CDNای برای دارایی‌هایش درخواست نمی‌زند، مصرف را تخمین نمی‌زند و امنیت را به ظاهر رابط کاربری گره نمی‌زند. حتی QR و فونت و آیکون‌ها داخل همان یک فایل زندگی می‌کنند.

## 🧠 موتور داخلی 2.0 — Edge Learner

نسخهٔ 2.0 علاوه بر policy deterministic، یک مدل کوچک online داخل Worker دارد که از latency، reliability، freshness، trend و continuity یاد می‌گیرد. نتیجه در D1 نگه‌داری می‌شود و برای انتخاب مسیر و پروفایل استفاده می‌شود؛ بدون نیاز اجباری به Workers AI.

وقتی همهٔ مسیرها unhealthy باشند، موتور recovery حداکثر دو مسیر را half-open دوباره امتحان می‌کند.

### حافظهٔ per-user
وضعیت ترجیح مسیر/پروفایل هر کاربر در D1 جداگانه ذخیره می‌شود تا یک کاربر مسیر خراب را روی سایر کاربران تحمیل نکند.

### سلامت مدل‌های Workers AI
نتیجهٔ واقعی inference برای هر model ID ذخیره می‌شود؛ مدل خراب موقتاً quarantine می‌شود و fallback بعدی انتخاب می‌شود.

### Cloudflare Pages
ساخت Pages Advanced Mode با `npm run build:pages` و `wrangler.pages.toml` اضافه شده است.

## 📱 صفحهٔ وضعیت کاربر — یک نگاه برای «وصل شم؟»

هر کاربر یک لینک شخصی دارد؛ وقتی در مرورگر بازش کنید، به‌جای خروجی خام اشتراک، یک صفحهٔ زنده و شیشه‌ای می‌بینید: حلقهٔ مصرف با اعداد واقعی، وضعیت اتصال، انقضا، و هاب ایمپورت با دکمه‌های یک‌کلیکی برای v2rayNG، Hiddify، Clash-Meta و Sing-box. کلاینت‌های پروکسی همچنان همان خروجی خام را می‌گیرند — تشخیص خودکار از روی User-Agent.

## 🧠 موتور تطبیقی 2.0 — Local Policy Brain + Profile Ensemble

نسخهٔ 2.0 علاوه بر سلامت ProxyIP، سلامت **پروفایل اتصال** را نیز با telemetry واقعی ثبت می‌کند. چهار حالت محدود و صریح وجود دارد: `standard`، `fragmented`، `alt-port` و `fragmented-alt`؛ این‌ها از preset انتخاب‌شده ساخته می‌شوند و موتور مقادیر تصادفی یا خارج از محدوده تولید نمی‌کند. Xray با observatory و `leastPing` این مجموعه را به‌صورت دوره‌ای مقایسه می‌کند و پنل، نتیجهٔ آن را در D1 نگه می‌دارد.

لایهٔ `Local Policy Brain` حتی بدون Workers AI کار می‌کند: با latency، نرخ خطا، تازگی داده، روند موفقیت/شکست و quarantine تصمیم می‌گیرد. این موتور جای مدل زبانی را نمی‌گیرد و «AI واقعی» نیست؛ مزیتش این است که با قطع سرویس مدل، لایهٔ تصمیم‌گیری شبکه از کار نمی‌افتد. endpoint مدیریت‌شدهٔ `network/profiles` نیز وضعیت پروفایل‌ها و انتخاب فعلی را نشان می‌دهد.

این معماری **adaptive** است، نه تضمین‌کنندهٔ عبور از هر نوع فیلترینگ. اگر upstream بین‌المللی واقعاً قطع باشد، Worker نمی‌تواند مسیر فیزیکی جدید ایجاد کند؛ فقط می‌تواند از مسیرها و پروفایل‌هایی استفاده کند که از شبکهٔ کاربر واقعاً قابل دسترسی‌اند.

## 🧠 مشاور عملیات Workers AI (اختیاری و فقط‌خواندنی)

داشبورد یک تحلیل‌گر اختیاری دارد که با binding بومی `AI` روی Workers AI اجرا می‌شود. ورودی مدل فقط شمارنده‌های تجمیعی پنل است (تعداد کاربران فعال/غیرفعال، فعالیت ۲۴ساعته، شمار کاربران دارای سهمیه و تعداد مسیرهای پشتیبان). **هیچ IP، نام کاربر، UUID، رمز، لینک اشتراک یا محتوای ترافیک ارسال نمی‌شود.** خروجی صرفاً توصیهٔ تشخیصی است؛ مدل هیچ تنظیمی را تغییر نمی‌دهد و نمی‌تواند تضمین کند فیلتر یا DPI دور زده می‌شود.

در `wrangler.toml`، binding `[ai]` با نام `AI` آماده است. برای کشف فهرست جاری مدل‌های متنی Cloudflare، شناسهٔ اکانت را به‌صورت متغیر `AI_CATALOG_ACCOUNT_ID` و یک Secret با نام `AI_CATALOG_API_TOKEN` (حداقل مجوز **Workers AI Read**) تنظیم کنید. فهرست از API رسمی Cloudflare گرفته، مدل‌های متنی نامعتبر/آزمایشی/منسوخ فیلتر و حداکثر هشت مورد نگه‌داری می‌شوند؛ وقتی تاریخ انتشار/به‌روزرسانی موجود باشد، جدیدترها زودتر امتحان می‌شوند. نتیجه در isolate حداکثر ۶ ساعت cache می‌شود. این یک **ترتیب ترجیح عملیاتی** است، نه بنچمارک یا اثبات «هوشمندترین مدل»؛ دسترسی، هزینه و کیفیت مدل باید در حساب خودتان بررسی شود، و ممکن است فراخوانی مدل پولی هزینه داشته باشد. با `AI_MODELS` می‌توانید شناسه‌های دلخواه را به‌ترتیب اولویت مشخص کنید؛ این مقدار بر کشف خودکار مقدم است. اگر توکن کاتالوگ تنظیم نشود یا API در دسترس نباشد، فهرست fallback داخلی به‌کار می‌رود. اگر خود inference در دسترس نباشد، یک عیب‌یاب قاعده‌محورِ سبک روی Worker جایگزین می‌شود؛ این مدل زبانی یا ضد DPI نیست. برای جلوگیری از مصرف ناخواسته، سقف درخواست با D1 و به‌ازای IP به ۵ درخواست در هر ۱۰ دقیقه محدود شده است. حذف binding قابلیت را خاموش می‌کند.

```bash
npx wrangler secret put AI_CATALOG_API_TOKEN
# در wrangler.toml یا تنظیمات Worker: AI_CATALOG_ACCOUNT_ID = "<Cloudflare account ID>"
```

<div align="center">

<img src="docs/preview-status.png" alt="صفحهٔ وضعیت کاربر گذرگاه — تم تاریک شیشه‌ای با حلقهٔ مصرف و هاب ایمپورت" width="86%">

</div>

- **هاب ایمپورت:** لینک عمیق مخصوص هر کلاینت + کپی + QR تعبیه‌شده (بدون هیچ CDN)
- **سوییچ قالب:** خودکار / Base64 / Clash-Meta / Sing-box / Xray — همه با حفظ تیون اپراتور
- **چیپ‌های اپراتور:** با یک کلیک، کل صفحه و همهٔ لینک‌ها با پریست اپراتور بازسازی می‌شوند
- **درگاه‌های جایگزین:** اگر ۴۴۳ مسدود بود، لینک آمادهٔ ۲۰۵۳ / ۲۰۸۳ / ۲۰۸۷ / ۸۴۴۳
- تم روشن/تاریک، فارسی/انگلیسی، و احترام کامل به `prefers-reduced-motion`

## 🎚 تیون عمیق اپراتور

<picture>
  <source media="(prefers-color-scheme: light)" srcset="docs/operators-light.svg">
  <img src="docs/operators-dark.svg" alt="پریست اختصاصی پنج اپراتور ایران — فینگرپرینت، فرگمنت و چرخ پورت" width="100%">
</picture>

هر اپراتور ایرانی رفتار DPI متفاوتی دارد؛ یک کانفیگ ثابت نمی‌تواند برای همه بهینه باشد. گذرگاه برای **همراه اول، ایرانسل، رایتل، شاتل و مخابرات** یک پریست اختصاصی ساخته: فینگرپرینت uTLS مناسب همان شبکه، پریست فرگمنت TLS داخل کپ‌های مستند Xray، و چرخ پورت‌های HTTPS کلادفلر. کافی است به لینک اشتراک `?op=mci` (یا هر اپراتور دیگر) اضافه شود.

قاعدهٔ **صداقت** سرنوشت‌ساز است: پریست فقط با انتخاب صریح کاربر اعمال می‌شود. بدون `?op=`، خروجی کاملاً خنثی و بی‌برند است — هیچ حدس ASN، هیچ برچسب غیرواقعی. و طبق درس میدانی، **ECH همیشه opt-in است** (`?ech=1`) چون DPI ایران با هندشیک‌های ECH مشکل دارد؛ پیش‌فرض در همهٔ فرمت‌ها خاموش است.

## 🧭 سفر یک درخواست

<div align="center">

<picture>
  <source media="(prefers-color-scheme: light)" srcset="docs/pipeline-light.svg">
  <img src="docs/pipeline-dark.svg" alt="سفر یک درخواست در گذرگاه — کلاینت، لبهٔ کلودفلر، دروازه، D1 و مقصد" width="100%">
</picture>

</div>

هر اتصال با یک هندشیک سبک در ورکر احراز می‌شود، مسیر کاربر از روی هاست تشخیص داده می‌شود و سپس ترافیک یا مستقیم به مقصد می‌رود یا در صورت نیاز از رلهٔ ProxyIP عبور می‌کند. همهٔ داده‌های پایدار (کاربران، مصرف، سشن‌ها، تنظیمات) در دیتابیس D1 خودتان می‌مانند و ورکر هیچ تله‌متری‌ای به بیرون نمی‌فرستد.

## ⚡ فرمت Xray — اتصال خودکارِ بهترین مسیر

فایل `xray` خروجی گذرگاه فقط لینک نیست؛ یک موتور انتخاب مسیر است. پروفایل شامل **observatory** است که هر ۳ دقیقه همهٔ مسیرها را probe می‌کند و بالانسر **leastPing** با تگ `auto-best` مسیر پیش‌فرض را به زنده‌ترین و سریع‌ترین outbound می‌برد — اگر یک مسیر throttle یا فیلتر شود، بدون هیچ دخالتی کنار می‌رود. با `?op=` یک کلون فرگمنت‌دار هم به خانواده اضافه می‌شود تا observatory آن را هم بسنجد.

## 🚀 استقرار در ۵ دقیقه

<div align="center">

<picture>
  <source media="(prefers-color-scheme: light)" srcset="docs/terminal-light.svg">
  <img src="docs/terminal-dark.svg" alt="استقرار گذرگاه در سه دستور — wrangler d1 create و npm run deploy" width="92%">
</picture>

</div>

فقط یک اکانت Cloudflare لازم است. (روش توسعه و استقرار با Wrangler به Node.js 22.12+ نیاز دارد؛ روش Paste به Node نیاز ندارد.)

### روش ۱ — Paste در داشبورد (بدون هیچ ابزاری)

1. فایل آمادهٔ `dist/gozargah-worker.js` را از [Releases](../../releases/latest) بردارید (یا خودتان با `npm run build` بسازید).
2. در داشبورد Cloudflare: **Workers & Pages → Create → Worker** — نام دلخواه (مثلاً `gozargah`) و Create.
3. دکمهٔ **Edit code** → محتوای فایل را جایگزین کنید → **Deploy**.
4. **ساخت دیتابیس:** **Storage & Databases → D1 → Create** — نام: `gozargah`.
5. در Worker: **Settings → Bindings → Add → D1 Database** — Variable name: دقیقاً `GZ_DB` — دیتابیس `gozargah` → Deploy.
6. صفحهٔ `https://<worker>.workers.dev/gozargah` را باز کنید — تمام! (ورود با `admin`)

> تا قبل از اتصال D1، پنل «راهنمای اتصال دیتابیس» را نشان می‌دهد و Worker در حالت بی‌دیتابیس هم پروکسی می‌کند (UUID قطعی از روی هاست).

### روش ۲ — wrangler (برای توسعه)

```bash
git clone https://github.com/panelgozargah/gozargah.git
cd gozargah
npm install
npx wrangler d1 create gozargah     # database_id را در wrangler.toml جای‌گذاری کنید
npm run deploy
```

> 🔄 **به‌روزرسانی خودکار:** در فورک خودتان دو Secret تعریف کنید — `CLOUDFLARE_API_TOKEN` و `CLOUDFLARE_ACCOUNT_ID` — از این به بعد هر push به `main` خودکار دیپلوی می‌شود.

## 🔑 ورود اولیه

| مورد | مقدار پیش‌فرض |
|------|----------------|
| آدرس پنل | `https://<worker>.workers.dev/gozargah` |
| رمز عبور | `admin` |

> ⚠️ پنل تا تغییر رمز پیش‌فرض، نوار هشدار زرد نشان می‌دهد. اولین کار بعد از ورود: **تنظیمات → رمز جدید**.
> مسیر پنل و مسیر اشتراک هم از همان‌جا قابل تغییر است.

## 👥 کاربران و اشتراک

- هر کاربر: **UUID اختصاصی + رمز Trojan + سهمیه (GB) + تاریخ انقضا + فعال/غیرفعال**؛ دکمهٔ قطع دسترسی در کارت کاربر، نشست جدید را فوراً رد می‌کند و نشست موجود حداکثر طی ۲ دقیقه با بازبینی D1 بسته می‌شود.
- **دو حالت انقضا:** تاریخ ثابت، یا «از اولین اتصال» — ساعت فقط وقتی شروع می‌شود که کاربر واقعاً وصل شود
- **ریست دوره‌ای مصرف:** روزانه / هفتگی / ۳۰ روزه — پنجرهٔ چرخشی بدون نیاز به Cron Worker
- مصرف واقعی up/down هر کاربر زنده در کارت او نمایش داده می‌شود (نوار گرادیانی)؛ نشست‌های فعال حداکثر هر ۲ دقیقه سهمیه/انقضا/وضعیت را با D1 بازبینی می‌کنند و در صورت لغو دسترسی بسته می‌شوند
- برای هر کاربر: لینک‌های VLESS/Trojan + QR + پنج لینک اشتراک + صفحهٔ وضعیت شخصی

| مسیر | توضیح |
|------|-------|
| `/{subPath}/{token}` | مرورگر ← صفحهٔ وضعیت · کلاینت ← اشتراک خودکار (UA-sniff) |
| `/{subPath}/{token}/clash` | پروفایل Clash-Meta |
| `/{subPath}/{token}/singbox` | پروفایل Sing-box |
| `/{subPath}/{token}/xray` | پروفایل Xray-core با auto-best |
| `/{subPath}/{token}/v2ray` | Base64 لینک‌ها |
| `?op=mci` | پریست اپراتور: `mci` · `irancell` · `rightel` · `shatel` · `tci` |
| `?ech=1` | فعال‌سازی ECH (opt-in — پیش‌فرض خاموش) |
| `/gozargah` | پنل (قابل تغییر) |
| `/healthz` | سلامت Worker |

## ⚙️ تنظیمات پنل

| تنظیم | پیش‌فرض | توضیح |
|-------|---------|-------|
| ProxyIPs | `proxyip.cmliussss.net` | برای اتصال به سایت‌های پشت کلادفلر؛ هر خط یک مورد. انتخاب IP برای هر کاربر پایدار است |
| مسیر اشتراک | `sub` | پیشوند لینک اشتراک |
| مسیر پنل | `gozargah` | مسیر مخفی پنل |
| ریست دوره‌ای | خاموش | صفر شدن خودکار مصرف در بازهٔ انتخابی |
| رمز عبور | `admin` | حداقل ۸ کاراکتر |

## 🤖 ربات تلگرام اختیاری (FSM روی D1)

ربات، اگر تنظیم شود، فقط به شناسه‌های عددیِ مجاز در چت خصوصی پاسخ می‌دهد. حالت مکالمه در D1 نگه‌داری می‌شود (با انقضای ۱۵ دقیقه‌ای)، شناسهٔ هر update برای جلوگیری از اجرای مجدد ثبت می‌شود، و حساب مدیریتی از تغییر وضعیت محافظت شده است. فرمان‌ها: `/status`، `/users`، `/disable`، `/enable`، `/cancel`. ربات هیچ‌وقت رمز پنل، UUID یا لینک اشتراک را ارسال نمی‌کند. غیرفعال‌سازی فوراً اتصال‌های جدید را رد می‌کند؛ نشست‌های برقرار حداکثر هر ۲ دقیقه با D1 دوباره بررسی و در صورت غیرفعال‌شدن، اتمام سهمیه، انقضا یا حذف کاربر بسته می‌شوند. این بررسی دوره‌ای مصرف خواندن/نوشتن D1 دارد.

1. در Cloudflare برای هر مقدار یک Secret بسازید: `TELEGRAM_BOT_TOKEN`، `TELEGRAM_WEBHOOK_SECRET` و `TELEGRAM_ADMIN_IDS` (شناسه‌های عددی تلگرام با ویرگول، مثل `12345678,87654321`).
2. پس از Deploy، در محیط امنی که متغیرها در آن تعریف شده‌اند، webhook را ثبت کنید:

```bash
curl -fsS -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/setWebhook" \
  -d "url=https://${WORKER_HOST}/_telegram/webhook" \
  -d "secret_token=${TELEGRAM_WEBHOOK_SECRET}"
```

Webhook با هدر محرمانهٔ Telegram، allowlist فرستنده و الزام چت خصوصی بررسی می‌شود. برای خاموش‌کردن ربات، Secretها را حذف و دوباره Deploy کنید. توکن‌ها را در Git یا چت قرار ندهید.

## 📱 کلاینت‌های همخوان

v2rayNG · v2rayN · Streisand · Shadowrocket · Hiddify · Clash-Meta/Stash · Sing-box · Karing · Nekobox

## 🔐 امنیت در معماری

- رمز با **PBKDF2-SHA256** و ۱۰۰٬۰۰۰ دور هش می‌شود؛ salt تصادفی ۱۶ بایتی — هیچ رمز plaintext ای در دیتابیس نیست
- سشن‌ها با **HMAC-SHA256** امضا و ۷ روزه منقضی می‌شوند؛ کوکی `HttpOnly; Secure; SameSite=Lax` — تغییر رمز همهٔ سشن‌ها را باطل می‌کند
- ورود: حداکثر ۵ تلاش در ۱۵ دقیقه — قفل **ماندگار در D1** (بر اساس هش IP)، نه حافظهٔ فرّار
- UUID و رمز Trojan هر کاربر با یک کلیک قابل چرخش است
- پاسخ همهٔ مسیرهای ناشناخته یک صفحهٔ بی‌اثر است — وجود پنل از رفتار HTTP قابل کشف نیست
- `robots.txt` بسته و همهٔ دارایی‌های UI تعبیه‌شده — هیچ ردی به سرویس ثالث

## 🧪 توسعه

```bash
npm install          # نصب وابستگی‌های توسعه
npm run typecheck    # بررسی تایپ TypeScript
npm test             # ۲۷ چک موتور + تست یکپارچگی Worker/D1 با Vitest و Miniflare
npm run preview      # پیش‌نمایش آفلاین پنل با دادهٔ ماک (preview.html)
npm run build        # اعتبارسنجی و باندل Worker با Wrangler 4
```

<details>
<summary><b>🌐 English</b></summary>

**Gozargah** (Persian for *gateway*) is a complete multi-user proxy panel that runs natively on Cloudflare Workers — the entire product lives in a single JS file: admin dashboard, proxy engine, subscription generator, per-user status page and all UI assets are embedded.

- **Protocols:** VLESS & Trojan over WebSocket + TLS, per-user path detection via host header (no unsupported Shadowsocks/UDP claims)
- **Storage:** Cloudflare D1 (relational — users / events / throttle), in-isolate cache, promise-dedup, optimistic locking
- **Accounting:** real byte counting per user (up/down), live usage bars, quotas & expiry; active sessions revalidate account state and persist usage every 2 minutes (D1 usage/cost trade-off)
- **Expiry modes:** fixed date **or** days-from-first-use (the clock starts on the first actual connection) + rolling auto-reset cycles (daily / weekly / 30d) — no Cron worker needed
- **Operator tuning:** explicit `?op=` presets for MCI, Irancell, Rightel, Shatel & TCI — per-ISP uTLS fingerprint, Xray-capped TLS-fragment preset and an HTTPS port wheel. Honesty gate: no preset is applied unless the user asks; ECH is strictly opt-in (`?ech=1`)
- **Xray format:** profile with observatory + leastPing balancer (`auto-best`) — a throttled path is demoted automatically; fragment clone included for operator presets
- **User status page:** browsers opening the sub link get a glassmorphic live page (real usage ring, one-tap imports, embedded QR, format switcher, operator chips, alt-port links); proxy clients keep raw configs via UA sniffing
- **Security:** PBKDF2-SHA256 (100k iterations), HMAC-signed expiring sessions, persistent D1-backed rate limiting
- **Subscriptions:** Base64 / Clash-Meta / Sing-box / Xray-core generated in-worker, auto `User-Agent` detection
- **UI:** Gozargah Nexus UI — cinematic dark glassmorphism, full RTL, FA/EN
- **Telegram admin bot:** opt-in, allowlisted private-chat commands with D1-backed FSM, update deduplication, short state TTL and protected admin accounts
- **Workers AI advisor (optional):** aggregate-only diagnostics, optional Cloudflare catalog discovery with model fallback, no user identifiers/configs/traffic sent, and an atomic D1 per-IP request budget; not an anti-DPI feature
- **Tests:** `npm test` — engine checks plus Vitest/Miniflare Worker+D1 integration tests

**Deploy:** grab `dist/gozargah-worker.js` from [Releases](../../releases/latest), paste it into a new Worker, create a D1 database bound as `GZ_DB`, open `https://<worker>.workers.dev/gozargah` — login `admin`. Free plan is enough.

</details>

## ⚠️ مرزهای واقعی پلتفرم و صداقتِ قابلیت‌ها

این نسخه روی ورودی HTTP/WebSocket و سوکت TCP خروجیِ Workers بنا شده است؛ Worker در این معماری listener خام TCP یا UDP/53 ندارد. بنابراین **Shadowsocks AEAD ورودی، فوروارد UDP-DNS روی پورت ۵۳ و NAT64 پیاده‌سازی نشده‌اند** و این پروژه آن‌ها را پشتیبانی‌شده معرفی نمی‌کند. پیاده‌سازی واقعی‌شان به لایهٔ ورودی/شبکه‌ای نیاز دارد که دیتاگرام یا TCP خام را پشتیبانی کند؛ شبیه‌سازی با WebSocket نام آن پروتکل را به پشتیبانی واقعی تبدیل نمی‌کند.

مشاور Workers AI این پروژه فقط برای تحلیل تجمیعی و خواندنی پنل است؛ **هوش مصنوعی ضد DPI یا تغییر خودکار مسیر شبکه نیست**. اسکن خودکار رنج‌های IP برای یافتن «IP تمیز» هم اضافه نشده است؛ این کار می‌تواند ترافیک اسکن ناخواسته ایجاد کند و نتیجه‌اش پایداری یا مجازبودن IP را تضمین نمی‌کند. کشف مدل‌ها از API رسمی با ترتیب زمانی/اولویت fallback به معنی سنجش واقعی «قوی‌ترین مدل» نیست؛ معیار معتبر نیازمند بنچمارک مستقل، بررسی هزینه و دسترسی اکانت است. هیچ AI نمی‌تواند عبور از فیلتر را تضمین کند. اگر مسیر بین‌الملل و دسترسی به Cloudflare کاملاً قطع شود، خود Worker و Workers AI هم از سمت کاربر قابل دسترسی نیستند؛ کد داخل Worker نمی‌تواند مسیر شبکه‌ای تازه بسازد. دسترسی در آن وضعیت به یک نقطهٔ ورودِ از قبل مستقر در شبکهٔ قابل دسترس یا یک ارتباط مستقل نیاز دارد. تعویض دامنه فقط در برابر مسدودسازی همان دامنه ممکن است کمک کند و مانع مسدودسازی IP، SNI یا الگوی ترافیک نمی‌شود. پیش از استفادهٔ عملی، محدودیت‌ها و شرایط جاری Cloudflare را برای workload خود بررسی کنید.

## 🛣 نقشهٔ راه

- [x] ربات تلگرام اختیاری با FSM پایدار در D1، allowlist و dedupe — v1.3
- [x] مشاور خواندنی Workers AI با fallback مدل و محدودیت اتمیک درخواست در D1 — v1.4
- [x] دکمهٔ قطع/فعال‌سازی هر کاربر از کارت پنل — v1.4
- [x] تست یکپارچگی Worker/D1 با Vitest + Miniflare — v1.3
- [x] پریست‌های اپراتورهای ایران + فرگمنت داخل کپ‌های Xray — v1.2
- [x] خروجی Xray-core با observatory و بالانسر leastPing — v1.2
- [x] صفحهٔ وضعیت کاربر با QR و ایمپورت یک‌کلیکی — v1.2
- [x] انقضای «از اولین اتصال» + ریست دوره‌ای مصرف — v1.2
- [x] ECH به‌صورت opt-in در همهٔ فرمت‌ها — v1.2
- [x] تست‌های موتور (`npm test`) — v1.2
- [ ] Shadowsocks AEAD به‌عنوان پروتکل سوم
- [ ] فوروارد UDP-DNS (پورت ۵۳) و NAT64
- [ ] ربات تلگرام با FSM روی D1
- [ ] تست‌های یکپارچگی (vitest + miniflare)

## 📄 لایسنس

MIT — آزاد برای استفاده، تغییر و توسعه. جزئیات در [LICENSE](LICENSE).

<div align="center">

<img src="docs/divider.svg" width="60%">

<sub><b>گذرگاه</b> — دروازهٔ امن عبور · ساخته‌شده برای سرعت، سادگی و آزادی</sub>

</div>

## 2.3.0 — Adaptive Health Loop

- Scheduled health loop every 5 minutes for only D1-configured fallback endpoints.
- D1 `network_state` quorum classifier: healthy / degraded / recovery / no_healthy_path.
- Authenticated `GET /{panelPath}/api/network/state`.
- Configurable probe ports via `HEALTH_PROBE_PORTS` (default: 443,2053,2083,2087,8443).
- No arbitrary network scanning; probes are bounded to endpoints already present in settings.
- The classifier is observational and does not claim to prove DPI or an international outage.


## Protocol capability matrix (current: 2.10.0)

Every protocol/transport pair is returned with an explicit boundary: `WORKER_NATIVE`, `ORIGIN_ENGINE_REQUIRED`, or `UNSUPPORTED`. The matrix is conservative: a profile is `ready` only if this repository has a matching generator and the configured origin-transport allowlist permits it. `ORIGIN_ENGINE_HOST` is a declaration, not a remote validation or health check. UDP-only WireGuard/Hysteria2, Shadowsocks, generic HTTP proxying, and unimplemented transports remain `UNSUPPORTED`; no metadata-only template is emitted as a usable profile.


### 2.3.0 capability endpoints
- `GET /<panel>/api/network/capabilities` — authenticated protocol/transport matrix.
- `GET /<sub>/<token>/profiles` — adaptive profile manifest.
- `GET /<sub>/<token>/capabilities` — public capability metadata for the current subscription token.

Optional env: `ORIGIN_ENGINE_HOST`, `ORIGIN_ENGINE_PORT`, and `ORIGIN_ENGINE_TRANSPORTS` enable template generation for the supported subset (VMess/WebSocket, VLESS/gRPC/XHTTP/HTTPUpgrade, and Trojan/XHTTP as allowed by the transport list). These entries are marked `declared-not-tested` because the Worker has no origin-engine validation adapter. Without an origin engine, only Worker-native VLESS/Trojan over WebSocket is marked ready. WireGuard and Hysteria2 are explicitly unsupported until a real UDP-capable adapter and profile generator exist.

## Gozargah 2.3.0 — Adaptive Protocol Orchestrator

2.3.0 adds a capability-aware protocol policy layer. It distinguishes Worker-native
HTTP/WebSocket profiles from origin-engine profiles and emits a bounded, diverse
preference list instead of pretending every transport is native to Workers.

New optional origin-engine variables:
- ORIGIN_ENGINE_HOST
- ORIGIN_ENGINE_PORT
- ORIGIN_ENGINE_SNI
- ORIGIN_ENGINE_PATH
- ORIGIN_ENGINE_GRPC_SERVICE
- ORIGIN_ENGINE_TRANSPORTS (default: xhttp,grpc,httpupgrade,ws)

New endpoint:
- GET /<panelPath>/api/network/policy

The /sub/<token>/profiles manifest now includes an adaptive policy with protocol,
transport, security, ALPN, readiness, and a bounded score. Xray output also emits
origin-engine profiles when an origin is explicitly configured and routes them
through observatory/leastPing. UDP-only protocols remain origin-engine capabilities;
the Worker itself does not claim to terminate inbound raw TCP/UDP.

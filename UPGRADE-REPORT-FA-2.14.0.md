# گزارش ارتقا — گذرگاه 2.14.0

تاریخ: ۲۹ سپتامبر ۲۰۲۶ (UTC)

## وضعیت

نسخهٔ 2.14.0 «چارچوب پروتکل AXR» است: هستهٔ کلاینت بومی Go با موزیسهٔ یادگیری داخلی (UCB1)، جراحی ClientHello در سطح TCP، موتور failover اینترانت ملی با کش سلامت IP زنده، و خوراک ماشین‌خوان `axr-manifest` روی Worker. سمت Worker (مسیر جدید + تست) کاملاً typecheck/تست/build-verify شده است. **هستهٔ Go در سنبخس سازنده کامپایل نشده** (دستگاه‌آلی Go در دسترس نبود)؛ درخت سورس کامل با تست واحد و `go.mod` pin‌شده تحویل شده و گیت اجباری `go vet && go build && go test` در راهنمای deploy تعریف شده است. هیچ deploy زنده‌ای روی Cloudflare انجام نشده است.

## تغییرات اصلی

- **M1 — هستهٔ تصمیم‌گیری داخلی (`client/internal/bandit` + `measure`):** موزیسهٔ UCB1 با context (بوست اکتشاف ×۱٫۸ در رژیم `suspected_change` + bonus تنوع)، shaping پاداش در [0,1] (پایهٔ ۰٫۵ + bonus پایداری throughput − جریمهٔ RTT؛ شکست‌ها به‌صورت پاداش ۰ + قرنطینهٔ backoff ۶۰s/۲m/۵m/۱۵m)، **auto-prune** بازوهای تخریب‌شده (حداقل ۲ بازوی زنده حفظ می‌شود) و persistence JSON اتمیک. بردار وضعیت — RTT/jitter EWMA، نرخ RST، نرخ timeout، CUSUM step-change (محدود، با re-baseline در بازگشت)، کد anomaly — به‌صورت deterministic به برچسب رژیم `stable | watch | suspected_change | recovering` می‌رسد. همهٔ ورودی‌ها **نتیجهٔ خودِ کلاینت** هستند؛ هیچ payloadی بازرسی نمی‌شود.
- **M2 — جراحی low-level سمت کلاینت (`client/internal/surgery`):** `SplitConn` اولین write (رکورد ClientHello) را در آفست تصادفیِ **[25٪، 85٪]** رکورد (با سوگیریِ عبور از بلوک extensionها که SNI آن‌جاست) به **دو سگمنت TCP** با gap تصادفی **۲۰–۱۲۰ms** می‌شکند؛ `ChunkConn` writeهای پس از handshake را به قطعات TCP تصادفی **512–1400B** می‌شکافد. نام‌گذاری صادقانه در کد و سند: این **chunking سطح TCP** است، نه record-padding TLS (نه استک Go و نه utls کنترل padding دارند). چرخش هویت uTLS با `refraction-networking/utls v1.6.7` (pin) پشت build tag `axr_utls` — `HelloChrome_Auto / HelloFirefox_Auto / HelloSafari_Auto / HelloRandomized`؛ build پیش‌فرض ۱۰۰٪ stdlib است و وابستگی خارجی ندارد.
- **M3 — failover اینترانت ملی (`client/internal/failover`):** ماتریس endpoint (host × IP تمیزِ CF × transport × fp) با **کش سلامت IP زنده** (score ترکیبی، RTT EWMA، atomic JSON)؛ ماشین حالت پروب `normal ⇄ aggressive` (۲ round همه-شکست → aggressive: cadence ۳۰s/timeout ۵s/۶ کاندید؛ موفقیت → بازگشت به ۹۰s/۳s/۳ کاندید)؛ failover order = امتیاز bandit × سلامت، بدون هیچ round-trip به control-plane. IPهای کاندید = فهرست اپراتور ∪ hostname — چون Worker نمی‌تواند بداند کدام IP از شبکهٔ **کلاینت** قابل‌رسیدنی است.
- **M4 — لبهٔ Worker (`src/subscription.ts` + `src/index.ts`):** مسیر جدید `GET /{subPath}/{token}/axr-manifest` — خوراک JSON با schema `gozargah-axr-manifest/v1`: `ws_path_base` چرخان، پنجرهٔ fingerprint، رژیم/استراتژی/حالت پروب، `network_state`, سِنجِ نقاط ورود (primary + پلهٔ backup با latency سنجش‌شده)، cadence reconnect (۳۰s در recovery) و `honest_limit` صریح. احراز با همان token اشتراک؛ token ناشناس به landing stealth می‌افتد (بدون user-enumeration).
- **تونل VLESS-WS بومی (`client/internal/vlessws`):** هدر VLESS v1 **byte-compat** با parser Worker؛ **0-RTT early data** با `b64url` هدر در `Sec-WebSocket-Protocol` (مکانیزمی که `acceptWebSocket` Worker مصرف می‌کند — کلاینت آن بایت‌ها را تکرار نمی‌کند)؛ codec کامل RFC6455 سمت کلاینت (mask، ping→pong، close، fragmentation) + تأیید `Sec-WebSocket-Accept`.
- **برنامهٔ `cmd/axr`:** SOCKS5 TCP inbound (UDP ASSOCIATE رد می‌شود — مطابق مرز نبود UDP relay)، هر stream از arm انتخاب‌شدهٔ bandit روی کاندیداهای failover تا اولین تونل موفق، پمپ دو‌سویه، و بازخورد هر نتیجه به bandit + tracker + کش روتینگ. خوراک manifest مسیر WS چرخان و entryهای backup را bootstrap می‌کند.
- **سند:** `docs/AXR-SPEC.md` (معماری + data-flow ASCII + threat model + مرزها) و `docs/AXR-DEPLOY.md` (ماتریس cross-compile GOOS/GOARCH شامل Android/Termux، کانفیگ `axr.json`، چک‌لیست verification).

## مرزهایی که این نسخه هم صریح نگه می‌دارد

- TLS روی لبهٔ کلادفلر terminate می‌شود؛ **تمام** morphing هویت و شکستن ClientHello در هستهٔ کلاینت است و Worker هرگز ClientHello را نمی‌بیند.
- هیچ تشخیص DPI، هیچ بازرسی payload، و هیچ تضمین عبور. برچسب‌های رژیم توصیف‌کنندهٔ **کیفیت تحویل** هستند نه رفتار middlebox؛ در سند `honest_limit` همین صریح است.
- chunking پس از handshake در سطح **TCP** است؛ ادعای record-padding TLS جایی وجود ندارد.
- در قطع **کامل** مسیر (هیچ entry قابل‌رسیدنی از شبکهٔ کاربر)، پروب‌ها `no healthy candidate` گزارش می‌دهند و streamها پاک شکست می‌خورند؛ هیچ کدی مسیر تازه نمی‌سازد.
- transport تحویل‌شده VLESS-over-WS است؛ بازوهای `h2/h3/grpc` stub رزرو‌شدهٔ رابط‌اند (در سند ذکر شده، نه ادعای قابلیت).
- هستهٔ Go در سنبخس سازنده **کامپایل-verify نشده**؛ گیت deploy (`go vet && go build && go test`) اجباری است و در `docs/AXR-DEPLOY.md` و README کلاینت صریح شده.

## راستی‌آزمایی

- `npm run typecheck`: موفق (Worker).
- `npm test`: موفق؛ ۳۶ بررسی موتور + ۹ سوئیت منطقی + **۱۶** تست یکپارچگی Vitest/Miniflare (دو تست جدید axr-manifest: 200+schema برای token معتبر و stealth-fallthrough برای token ناشناس).
- `npm run build`: موفق با `wrangler deploy --dry-run`؛ اندازهٔ upload برابر 504.35 KiB و gzip برابر 131.51 KiB.
- هستهٔ Go: درخت کامل با ۵ پکیج `internal` + تست واحد (bandit/measure/surgery/failover/vlessws) و `go.mod` با pin واحد؛ **کامپایل در سنبخس انجام نشد** (بدون toolchain) — گیت اجباری در راهنمای deploy.
- جزئیات پوشش: [گزارش تست 2.14.0](TEST-REPORT-2.14.0.md).

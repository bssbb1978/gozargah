# گزارش ارتقا — گذرگاه 2.15.0: هستهٔ enterprise نسخهٔ پیشرفته

تاریخ: ۲۹ سپتامبر ۲۰۲۶ (UTC)

## وضعیت

نسخهٔ 2.15.0 «هستهٔ enterprise AXR-v2» است: ارتقای موزیسهٔ تصمیم‌گیری داخلی کلاینت از UCB1 به **LinUCB** (بازوی context‌محور ۷‌بُعدی)، **مورفینگ جریان به کلاس‌های کاربردی** (توزیع طول پکیت + IPD لگ‌نرمال)، **جراحی سوکت TCP** (Nagle خاموش + `SO_SNDBUF` تصادفی)، **برداشت IP تمیز** از رکوردهای A، **سکشن‌reuse ≤ ۳۰s**، **لجٔ تصمیم `decision.jsonl`**، **لایهٔ decoy اسکنر** روی Worker، و فیلدهای جدید manifest. سمت Worker کاملاً typecheck/تست/build-verify شده است. **هستهٔ Go همچنان در سنبخس کامپایل نشده** (دسترس به toolchain Go ممکن نیست — go.dev و آینه‌ها TLS-block و root برای apt نیست)؛ درخت سورس کامل با تست واحد تحویل شده و گیت اجباری `go vet && go build && go test` در راهنمای deploy هست. هیچ deploy زنده‌ای روی Cloudflare انجام نشده است.

## تغییرات اصلی

- **M1 — LinUCB context‌محور (`client/internal/bandit` بازنویسی):** به‌جای «میانگین + بونوس تعداد کشش»، هر بازو (host × transport × fingerprint) وضعیت ridge دارد: ماتریس ۷×۷ `A = λI + Σxxᵀ` و بردار ۷بعدی `b = Σrx`؛ امتیاز بازو در context فعلی: `xᵀA⁻¹b + α√(xᵀA⁻¹x)` — معکوس‌سازی با Gauss-Jordan pivot‌دار **خامِ Go** (بدون هیچ بستهٔ ریاضی). context = ۷ بُعد از **خروجی‌های خودِ کلاینت**: سطح RTT، واریانس RTT، فراوانی RST، افت TLS (دلتای drop)، step افت (CUSUM)، انومالی HTTP، و bias. نتیجه: **یک entry ثابت می‌تواند در لولهٔ تمیز عالی و در رژیم RST-سپایک ضعیف باشد** — دقیقاً چیزی که UCB1 نمی‌توانست بگوید. حفظ‌شده: shaping پاداش [0,1]، قرنطینهٔ backoff (۶۰s→۲m→۵m→۱۵m)، auto-prune (حداقل ۲ بازوی زنده)، boost اکتشاف ×۱٫۸ در `suspected_change`، tie-break قطعی، persistence اتمیک (الان با ماتریس‌های A/b؛ اسنپ‌شات‌های 2.14 legacy بدون خطا restore می‌شوند و prior ridge بازسازی می‌شود). بازوهای آزمایش‌نشده `1+α` می‌گیرند تا هر entry دست‌کم یک‌بار امتحان شود — وگرنه failover هیچ‌وقت entry تازه‌زنده را کشف نمی‌کند.
- **M2 — مورفینگ جریان به کلاس کاربردی (`client/internal/flowprofile` جدید + گسترش `surgery`):** writeهای پس از handshake دیگر «برکه‌های ۱۴۰B یکنواخت» نیستند: هر کلاس یک **هیستوگرام طول** دارد — `web` (قطعات ۳۰–۱۴۰۰B با وزنهٔ درخواست/پاسخ، میانگین ≈ ۷۳۳B)، `video` (حاکمیت ۱۲۰–۱۴۰۰B، میانگین ≈ ۱۱۱۷B)، `chat` (ریز ۱۰۰–۹۰۰B، میانگین ≈ ۳۴۸B) — و **IPD لگ‌نرمال** (Box–Muller) با clipping: video ≈ ۴ms، web ≈ ۳۰ms، chat ≈ ۳۰۰ms. انتخاب کلاس با رژیم: `stable→web`، `watch→chat`، `suspected_change→video`. `surgery.ChunkConn` از طریق رابط `Slicer` این توزیع را مصرف می‌کند (رفتار legacy دست‌نخورده). **جراحی سوکت TCP** (`internal/sockopt` جدید): روی هر dial، `TCP_NODELAY` (Nagle خاموش تا kernel الگوی مورف‌شده را دوباره merge نکند) + `SO_SNDBUF` تصادفی از {64,128,256,512}KB (اندازهٔ buffer در رفتار window/سگمنت نشت می‌کند؛ تغییر آن کلاسیفایرهایی که روی default‌های kernel استاندارد نشسته‌اند را خنثی می‌کند) — با build-tag برای linux/darwin/windows و no-op سند‌شده بقیه.
- **M3 — برداشت IP تمیز (`client/internal/failover`):** `HarvestedIPs`/`Engine.HarvestEntries` با **resolver قابل‌تزریق** (پیش‌فرض: resolver سیستم، فقط A رکورد IPv4) رکوردهای زندهٔ A هر entry را به ماتریس merge می‌کنند — IPهای صریح اپراتور اول و مورداعتماد، dedup، اعتبارسنجی IPv4، سقف ۸؛ خطای resolver فهرست فعلی را دست‌نخورده می‌گذارد (برداشت enhancement است، هرگز regression). hints جدید manifest (`CLEAN_EDGE_IPS` اپراتور، validate‌شده، ≤۸) هم با همین تابع merge می‌شوند.
- **M4a — بازاستفادهٔ جلسه (session reuse) و لجٔ تصمیم (`cmd/axr`):** وقتی تونل با **بستن پاکِ سمت اپلیکیشن** تمام می‌شود (WS هنوز سالم است)، هسته WS را تا **۳۰s** نگه می‌دارد؛ CONNECT بعدی به **همان مقصد** آن را adopt می‌کند — صفر dial/TLS/handshake دوباره. adopt فقط هم-مقصد است (هر WS دقیقاً یک stream backend می‌کند)؛ جلسهٔ کهنه در اولین خطای pump ریخته و فوری dial تازه می‌شود (بدترین حالت = بدون reuse، هرگز تونل شکسته). هر تصمیم یک خط JSON در `~/.axr/decision.jsonl`: context ۷بعدی کامل، بازوی انتخابی، **جدول امتیاز کامل LinUCB**، کاندیداهای امتحان‌شده (host/IP/shape)، نتیجه، و علامت warm — با چرخش در ≈ ۴MB. هر entry حالا بازوی دوم **`ws-alt`** هم دارد: همان host روی شکل مسیر/پرس `gz_profile=fragmented` (telemetry چهارگانهٔ profile در Worker از 2.14 هست) تا bandit شکل سالم‌تر را یاد بگیرد.
- **M4b — لایهٔ decoy اسکنر (Worker، `src/panel/decoy.ts` جدید):** هر GET/HEAD ناسازگار با شکل‌های اسکنر (`/.env`، `/.git/…`، `/wp-login.php`، `/admin`، `/api/…`، `/config.json`، `/axr*`، `/sub/<bad>/…` و…) به‌جای 404/landing ثابت، یک **پاسخ بی‌آزار** می‌گیرد: یکی از ۳ صفحهٔ محصولِ کسب‌وکارهای کوچک (حمل‌ونقل / دفتر معماری / مشاوره) با padding ۳۲هگز تصادفی (طول بایت هر پاسخ فرق می‌کند)، و برای پراب‌های JSON-typ یک‌ی از ۲ شکل API بی‌آزار (edge-cache status / service health v2). مسیرهای واقعی **قبل** از decoy handle می‌شوند، POST هرگز decoy نمی‌شود، و token ناشناس روی feed ماشین‌خوان دیگر user-enumeration نمی‌دهد.
- **M4c — فیلدهای manifest v2 (Worker):** `transports: ["ws","ws-alt"]`؛ `flow_profile.mode` با تشدید رژیم از D1 (`video` در `suspected_change`/recovery/no_healthy_path، `chat` در `watch`، در غیر این‌صورت `web`) — یعنی هر دو طرف (Worker و کلاینت) به یک کلاس جریان همگرا می‌شوند؛ `clean_ip_hints[]` از env اپراتور.
- **stubها با سند، نه ادعا:** relay duplex HTTP-chunked **اندازه‌گیری** شد که در CI قابل‌test نیست (miniflare 4 body درخواست را buffer می‌کند و stream بی‌پایان worker را hang می‌کند) → اگر تحویل می‌شد **بدون verification** تحویل می‌شد؛ gRPC و HTTP/3 (UDP) فقط placeholder مجموعهٔ بازوها هستند. داده‌پلین تحویل‌شده WS + ws-alt است.

## پاسخ به سؤال کلاینت‌های آماده (صادقانه)

**هیچ کلاینت آمادهٔ موجود (Hiddify، v2rayN، sing-box، Clash Meta، Xray و…) هیچ‌کدام از این‌ها را ندارد:**

| قابلیت 2.15 | کلاینت‌های آماده | هستهٔ AXR |
| --- | --- | --- |
| RL context‌محور سمت کلاینت (LinUCB با ۷ بُعد شبکه) | ❌ ندارند (حداکثر failover سادهٔ sequential) | ✅ هستهٔ تصمیم |
| شکستن ClientHello در سطح TCP + مورفینگ طول/IPD به کلاس app | ❌ | ✅ |
| جراحی سوکت (Nagle/SNDBUF) + probe/Failover خودکار با کش سلامت IP | ❌ | ✅ |
| برداشت IP تمیز از رکوردهای A + سکشن‌reuse + لجٔ تصمیم | ❌ | ✅ |

کلاینت‌های آماده **مستقیق** از سمت Worker بهره‌مند می‌شوند — configهای تولیدی (چرخش مسیر ۶ ساعته، هویت uTLS خنثی و چرخان، پلهٔ emergency، reconnect observe-and-failover ۳۰/۹۰s، traffic-shape) بدون هیچ تغییر در کلاینت اعمال می‌شوند. **راه‌اندازی توصیه‌شده برای «کامل خودکار»:** هستهٔ Go را به‌عنوان **backend SOCKS5 محلی** (`axr -config axr.json -socks 127.0.0.1:1080`) اجرا کنید و مرورگر/کلاینت آماده را به آن SOCKS5 وصل کنید — آن‌وقت کل زنجیره (انتخاب مسیر، morphology، failover، reuse) زیر پای کلاینت آماده، خودکار و بی‌هیچ دخالت انسانی کار می‌کند. این دقیقاً همان معماریی است که هسته برای آن ساخته شده است.

## وضع قطع net-e-melli (بیان صریح)

در قطع‌های جزئی (فیلتر پویا، RST تزریقی، sink شدن IPها): پلهٔ entryهای backup + `flow_profile` تشدیدشده + `clean_ip_hints` + **برداشت زندهٔ A رکوردها سمت کلاینت** (تنها جایی که می‌داند کدام IP از شبکهٔ شما درستِ همین لحظه قابل‌رسیدنی است) شانس آن را **بیشینه** می‌کند که دست‌کم یک entry از درون اینترانت ملی زنده بماند. اما در **قطع کامل** بینت — هیچ مسیر فیزیکی از شبکهٔ ملی به لبهٔ بین‌المللی — هیچ کدی (نه کلاینت، نه Worker، نه هیچ proxy) مسیر تازه **می‌سازد**؛ هسته آن را `no healthy candidate` گزارش می‌دهد و streamها پاک شکست می‌خورند. این مرز فیزیکی است، نه کمبود پیاده‌سازی.

## مرزهایی که این نسخه هم صریح نگه می‌دارد

- TLS روی لبهٔ کلادفلر terminate می‌شود؛ Worker هرگز ClientHello را نمی‌بیند؛ همهٔ morphing و جراحی سمت کلاینت است.
- مورفینگ جریان شکل‌دهی **writeهای خودِ کلاینت** است — نه بازرسی payload، نه replay ترافیک واقعی کسی، نه تضمین نامرئی.
- decoy فقط پاسخ **پراب‌های ناسازگار** را عوض می‌کند؛ هیچ route واقعی دست‌نخورده می‌ماند.
- قطع کامل مسیر نمی‌تواند دور زده شود؛ گزارش می‌شود.
- هستهٔ Go **کامپایل-verify نشده در سنبخس**؛ گیت deploy اجباری است.

## راستی‌آزمایی

- `npm run typecheck`: موفق (Worker).
- `npm test`: موفق؛ ۳۶ بررسی موتور + **۱۰** سوئیت منطقی (سوئیت جدید `decoy`: ۷ بلوک) + **۱۷** تست یکپارچگی Vitest/Miniflare (تست‌های جدید: decoy از مسیر واقعی روتر — HTML/JSON/anti-enumeration — و فیلدهای v2 manifest شامل فیلترینگ `clean_ip_hints`).
- `npm run build`: موفق با `wrangler deploy --dry-run`؛ 511.03 KiB upload / 133.49 KiB gzip (مقایسه با 2.14: 504.35 / 131.51).
- هستهٔ Go: بازنویسی `bandit` (۱۲ تست شامل بررسی closed-form شرطی LinUCB)، پکیج‌های جدید `flowprofile` (۹ تست) و `sockopt` (۴ تست)، گسترش `failover` (۶ تست harvest) و `surgery` (Slicer)؛ **کامپایل در سنبخس انجام نشد** (بدون toolchain) — گیت اجباری در `docs/AXR-DEPLOY.md`.
- جزئیات پوشش: [گزارش تست 2.15.0](TEST-REPORT-2.15.0.md)؛ مستندات فنی: [AXR-v2 Advanced Features](docs/AXR-V2-ADVANCED.md).

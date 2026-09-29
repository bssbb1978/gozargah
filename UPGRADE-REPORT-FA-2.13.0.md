# گزارش ارتقا — گذرگاه 2.13.0

تاریخ: ۲۹ سپتامبر ۲۰۲۶ (UTC)

## وضعیت

نسخهٔ 2.13.0 «لایهٔ داینامیک و سخت‌افزای‌شده» است: چرخش فینگرپرینت کلاینت، شکل‌دهی ترافیک درون تونل، ماشین حالت پروب تهاجمی، نمای تصمیم هوش مصنوعی داخلی، و سخت‌سازی صفحهٔ stealth. همهٔ تست‌ها، بررسی TypeScript و build آزمایشی موفق‌اند. هیچ deploy زنده‌ای روی Cloudflare انجام نشده است.

## تغییرات اصلی

- **چرخش فینگرپرینت کلاینت (`src/sub/fp-rotation.ts`):** TLS روی لبهٔ کلادفلر terminate می‌شود و Worker هرگز ClientHello را نمی‌بیند؛ آنچه می‌چرخد، هویت uTLS است که **کانفیگ‌های تولیدشده** به کلاینت دستور می‌دهند (ورودی JA3/JA4: ترتیب extensionها، cipherها و curveها). مجموعهٔ خنثی — اشتراک سه قالب Xray/Sing-box/Clash — یعنی `chrome / firefox / safari` که در ClientHello تفاوت محسوس دارند؛ هر ۶ ساعت و به‌صورت deterministic برای هر کاربر می‌چرخد و با پنجرهٔ چرخش مسیر هم‌زمان است. پریست اپراتور همیشه برتر است (قرارداد برندینگ صادقانه).
- **شکل‌دهی ترافیک درون تونل (`src/utils/shape.ts` + WS pipeline):** بارس‌های بلند downlink به قطعات bounded (حداکثر ۸ قطعه در حالت conservative) با micro-gap تصادفی ≤۱۵ms تقسیم می‌شوند و پاسخ نخست پروتکل jitter زمانی bounded می‌گیرد. همه‌چیز داخل تونل TLS لبه است، هیچ بایت پروتکل عوض نمی‌شود و کلاینت‌های استاندارد بدون تغییر کار می‌کنند؛ فقط آمار اندازه/زمان‌بندیِ جریان رمزنگاری‌شده smooth می‌شود. `TRAFFIC_SHAPE=conservative` (پیش‌فرض) | `aggressive` | `off`.
- **ماشین حالت پروب تهاجمی (`scheduled-health`):** وقتی سیکل پیشین `recovery` / `no_healthy_path` / `UPSTREAM_UNAVAILABLE` / `SEVERELY_DEGRADED` باشد، سیکل جاری نقاط ورود جایگزین را با **پروب fullPath HTTPS** (DNS+TCP+TLS+HTTP روی `/healthz`) زیر نظر می‌گیرد تا اولین مسیر بازشده بلافاصله شناسایی و انتخاب شود؛ گذار حالت در رویداد `probe_mode_changed` ثبت می‌شود و حالت در `/api/network/state` و bundle دیده می‌شود.
- **نمای تصمیم هوش مصنوعی داخلی (`src/ai/decision.ts` + `GET /{panelPath}/api/network/decision`):** یک verdict bounded (`stable | watch | degraded | critical`) با score، برچسب رژیم، استراتژی کنترلر، حالت ماشین پروب، شکل‌دهی ترافیک، پروفایل فعال، پلهٔ fallback و پلهٔ نقاط ورود — به‌علاوهٔ advice دوزبانهٔ صادقانه. تمام ورودی‌ها از موتورهای موجود (network state + condition + regime + guard + policy) ترکیب می‌شوند؛ مدل بیرونی لازم نیست.
- **بازپیوند هوشمند کلاینت:** در Xray-core، `observatory.probeInterval` در حالت recovery به ۳۰ ثانیه و در حالت عادی ۹۰ ثانیه صادر می‌شود؛ در اشتراک زنده، بلاک `client_behavior.reconnect` (strategی observe_and_failover، backoff، ترتیب failover مطابق پله، و `on_route_reopen: immediate_resume`) و بلاک‌های `fingerprint` و `traffic_shape` اضافه شده‌اند.
- **سخت‌سازی stealth (`landing.ts`):** ۳ واریانت کلامی هر زبان + پدینگ تصادفی در هر پاسخ؛ hash/طول بایت‌های صفحه دیگر ثابت نیست (در برابر fingerprint صفحهٔ استاتیک) — همچنان هیچ اطلاعاتی نشت نمی‌کند.

## مرزهایی که این نسخه هم صریح نگه می‌دارد

- Worker **ClientHello را نمی‌بیند و تغییر نمی‌دهد**؛ چرخش فینگرپرینت یعنی تنوع هویت uTLS سمت کلاینت در کانفیگ‌های تولیدشده، نه تغییر استک TLS لبه.
- هیچ FEC، هیچ تغییر extension/cipher/curve توسط Worker، و هیچ تغییر در framing پروتکل‌ها؛ VLESS/Trojan/Shadowsocks با کلاینت‌های استاندارد (Xray/sing-box/Hiddify/Clash) بدون تغییر کار می‌کنند.
- شکل‌دهی ترافیک فقط آمار اندازه/زمان‌بندی داخل تونل را تغییر می‌دهد؛ بایت پروتکل دست‌نخورده است.
- verdict و regime و condition همه **آمار تجمیعی** پروب/اتصال هستند؛ نه تشخیص DPI و نه اثبات فیلتر. هیچ payloadی بازرسی نمی‌شود و عبور تضمین‌شده وجود ندارد.
- در قطع **کامل** مسیر (هیچ مسیر از شبکهٔ کاربر تا Worker/کلادفلر)، هیچ کدی از راه دور مسیر تازه نمی‌سازد؛ پلهٔ اضطراری و پروب تهاجمی در قطع‌های **موضعی** شانس بقای مسیر را بالا می‌برند.

## راستی‌آزمایی

- `npm test`: موفق؛ ۳۶ بررسی موتور + ۹ سوئیت منطقی (شامل سه سوئیت جدید fp-rotation، shape، decision) + ۱۴ تست یکپارچگی Vitest/Miniflare.
- `npm run typecheck`: موفق.
- `npm run build`: موفق با `wrangler deploy --dry-run`؛ اندازهٔ upload برابر 501.00 KiB و gzip برابر 130.89 KiB.
- جزئیات پوشش: [گزارش تست 2.13.0](TEST-REPORT-2.13.0.md).

# دسترسی‌های Cloudflare برای Deploy — بررسی ذره‌بینی

> این سند با اجرای واقعی دستورها روی همین checkout (کامیت `6ee6696`، شاخهٔ `arena/01a0f135-gozargah`) و مقایسه با مستندات رسمی Cloudflare نوشته شده است. هر ادعای این سند یا «با اجرای فرمان در همین محیط» تأیید شده یا به منبع رسمی Cloudflare لینک شده است. چیزی که قابل تأیید نبوده، صریحاً به‌عنوان «تأییدنشده» علامت خورده است.

---

## ۱. پاسخ کوتاه: Deploy چه دسترسی می‌خواهد؟

| کاری که واقعاً انجام می‌شود | نوع | دسترسی لازم | Scope | لازم است؟ |
|---|---|---|---|---|
| Deploy کردن Worker **موجود** (با binding های D1، AI و cron) | Account | **Workers → Editor** | همان Worker (تک‌Worker) یا کل محصول | ✅ توکن دائمی CI |
| ساخت Worker که **هنوز وجود ندارد** (`gozargah-staging` بار اول) | Account | **Workers → Admin** | سطح محصول (همهٔ Workerها) | ⚠️ فقط بار اول |
| ساخت/تغییر Route یا Custom Domain هنگام Deploy | Zone | **Workers Routes → Write** | Zone مربوطه | ❌ در این مخزن تعریف نشده |
| `wrangler d1 create` و `d1 migrations apply --remote` | Account | **D1 → Edit** | حساب | ⚠️ موقت، برای راه‌اندازی |
| `wrangler d1 list` / دیباگ | Account | **D1 → Read** | حساب | اختیاری |

- Cloudflare صریح می‌گوید برای Deploy یک Worker که به D1/KV/R2 **binding** دارد، همان `Editor` روی Worker کافی است و به دسترسی جدا روی خود D1 نیازی نیست: «To deploy a Worker that has bindings … you need `Editor` access to the Worker. You do not need separate permissions on the bound resources to deploy the Worker.» و «Creating new Workers requires product-level `Admin` access» و «You cannot grant per-Worker access to a Worker that does not exist yet.» — منبع: [Workers roles and permissions](https://developers.cloudflare.com/workers/authorization/workers/)
- اگر `wrangler deploy` بخواهد Route/Custom Domain را عوض کند، `Zone → Workers Routes → Write` هم لازم است (همان منبع). در `wrangler.toml` این مخزن هیچ `route`/`routes`/Custom Domain وجود ندارد؛ فقط `workers_dev` است، پس این مجوز لازم نیست.
- برای D1، مستندات Cloudflare مسیر ساخت توکن با **Account → D1 → Edit** را نشان می‌دهد: [Bulk import to D1 using REST API](https://developers.cloudflare.com/d1/tutorials/import-to-d1-with-rest-api/)
- GitHub Actions این مخزن دقیقاً همین دو نام را می‌خواند: `CLOUDFLARE_API_TOKEN` و `CLOUDFLARE_ACCOUNT_ID` (فایل `.github/workflows/deploy.yml` خطوط ۱۷–۱۸ و ۴۱–۴۲).

**توصیهٔ عملی:** یک توکن پایدار برای CI با `Workers → Editor` (ترجیحاً scoped به همان Worker) و یک توکن موقت با `D1 → Edit` که بعد از راه‌اندازی revoke شود. Global API Key استفاده نکنید و مقدار توکن را در چت نفرستید.

> 🔍 **نوع توکن هم مهم است:** User API Token (پیشوند `cfut_`) روی `GET /user/tokens/verify` تأیید می‌شود و Account-owned token (پیشوند `cfat_`) روی `GET /accounts/{account_id}/tokens/verify`. اگر توکن حساب‌محور را روی endpoint کاربر تست کنید، خطای **کد ۱۰۰۰** می‌گیرید که معنایش «توکن خراب» نیست؛ wrangler 4.143.0 هم دقیقاً از همین کد ۱۰۰۰ برای تشخیص «توکن حساب‌محور» استفاده می‌کند (سورس `getTokenType`). راهنمای گام‌به‌گام و ابزار بررسی: `docs/DEPLOY-RUNBOOK-FA.md` و `npm run preflight:cf`.

> ⚠️ اگر Worker مقصد **هنوز ساخته نشده**، توکن scoped-per-Worker کار نمی‌کند (چون خود Worker وجود ندارد و per-Worker access به Worker ناموجود قابل‌دادن نیست). دو راه: (الف) بار اول با دسترسی سطح محصول بسازید و بعد توکن CI را به Editor محدود کنید، یا (ب) Worker را یک بار از داشبورد بسازید و بعد با توکن Editor دیپلوی کنید.

---

## ۲. بررسی خط‌به‌خط متن قبلی: چه چیزی درست بود، چه چیزی نه

| # | ادعا | نتیجهٔ بررسی | شاهد |
|---|---|---|---|
| ۱ | گارد بدون `--env` اجرا می‌شود پس محیط root بررسی می‌شود | ✅ **درست** | `deploy.yml:35` → `run: node scripts/guard-deploy-config.mjs` |
| ۲ | Workflow دستور `wrangler deploy` را بدون `--env staging` اجرا می‌کند | ✅ **درست، و از آن مهم‌تر:** wrangler در CI با نبود `--env` فقط یک WARNING می‌دهد و روی محیط root (Worker به نام `gozargah`) کار خود را ادامه می‌دهد؛ خطا نمی‌دهد | `deploy.yml:43` + اجرای محلی `CI=true npx wrangler deploy --dry-run` → exit 0 با پیام «Multiple environments are defined… but no target environment was specified» |
| ۳ | هر دو `database_id` (روت و staging) placeholder صفر است | ✅ **درست** | `wrangler.toml:14` و `wrangler.toml:38` |
| ۴ | تا وقتی Secretها تنظیم نشده‌اند Workflow فقط Deploy را رد می‌کند (بدون خطا) | ✅ **درست، با شاهد عینی** | اجرای شمارهٔ `36682857775` روی `main`: استپ‌های «Setup Node»/«Guard»/«Deploy» = `skipped`، annotation = «Cloudflare secrets … are not configured — auto-deploy skipped» |
| ۵ | Workflow قبل از Deploy، migrationهای D1 را اجرا نمی‌کند | ✅ **درست** | `deploy.yml` مجموعاً ۵ استپ دارد (checkout، check، setup-node، guard، deploy)؛ هیچ `d1 migrations apply` ای در آن نیست |
| ۶ | Deploy کردن Worker موجود با D1 binding، دسترسی جدا به D1 نمی‌خواهد | ✅ **درست** | نقل‌قول بند ۱ + مستندات رسمی |
| ۷ | ساخت Worker جدید به Admin سطح محصول نیاز دارد | ✅ **درست** | `Create a new Worker → Product-level Admin` (همان مستند) |
| ۸ | نام قدیمی مجوز `Workers Scripts:Edit` معادل `Editor` است | ✅ **درست** | جدول Legacy permissions در همان مستند: `Workers Scripts Edit → Editor at the Workers product scope` |
| ۹ | «PR #8 هنوز جدا از Deploy است» | ❌ **منقضی/نادرست** | PR #8 در `2026-09-30T07:17:28Z` merge شده و همان کامیت merge (`6ee6696`) الان HEAD شاخهٔ `main` است. هیچ PR بازی در مخزن نیست (`gh pr list` خالی بود) |
| ۱۰ | — | ⚠️ **نکتهٔ جاافتاده و مهم:** به‌محض افزودن این دو Secret، چون گارد روی **root** اجرا می‌شود و ID روت placeholder است، گام Guard **شکست می‌خورد** و Workflow روی هر push به `main` قرمز می‌شود (خطا، نه skip) | اجرای محلی `node scripts/guard-deploy-config.mjs` → `exit=1` |
| ۱۱ | — | ⚠️ **نکتهٔ جاافتاده و مهم:** پر کردن فقط ID دیتابیس **staging** هیچ‌وقت Deploy را در CI باز نمی‌کند، چون گارد فقط روت را می‌سنجد. و اگر ID **روت** را پر کنید، CI روی هر push به `main` محیط production (Worker `gozargah`) را دیپلوی می‌کند — نه staging | `scripts/guard-deploy-config.mjs:33-48` (`checkDeployConfig` فقط محیط هدف را می‌سنجد) + جدول سناریوها در بند ۳ |
| ۱۲ | — | ⚠️ **کشف مهم:** `[triggers] crons = ["*/5 * * * *"]` از روت به `env.staging` **ارث می‌رسد** (برخلاف bindingها که ارث نمی‌رسند)، پس Worker استیجینگ هم زمان‌بندی ۵ دقیقه‌ای فعال دارد | سورس wrangler 4.143.0: `triggers: inheritable(...)` اما `d1_databases: notInheritable(...)`؛ به‌علاوه تست مصنوعی: wrangler برای `kv_namespaces`/`d1_databases` هشدار «not inherited by environments» می‌دهد ولی برای `triggers`/`observability` هیچ هشداری نمی‌دهد |
| ۱۳ | «migrationها را پیش از Deploy اعمال کنید» | ✅ **توصیهٔ درست، ولی سخت‌گیرانه نیست:** Worker خودش در اولین درخواست کل اسکیما را با `CREATE TABLE IF NOT EXISTS` می‌سازد (`ensureSchema` در `src/db/store.ts:245`)، پس دیپلوی بدون migration هم بالا می‌آید. اجرای migrationها همچنان توصیه می‌شود چون دفتر `d1_migrations` را با مخزن هم‌گام می‌کند و idempotent است | `src/db/store.ts:35-220` (DDL) و `migrations/0001…`, `migrations/0002…` |
| ۱۴ | — | ⚠️ **هشدار امنیتی کوچک:** در `.gitignore` این مخزن `.dev.vars` هست اما `.env` **نیست**. اگر توکن را در `.env` بگذارید، احتمال commit اشتباه وجود دارد | `.gitignore` فعلی |
| ۱۵ | «Token را در چت نفرستید» | ✅ درست و رعایت شد؛ در این بررسی هیچ اعتبارنامه‌ای درخواست یا استفاده نشد | — |

**چیزهایی که در این جلسه قابل تأیید نبود:** موفقیت واقعی توکن روی حساب شما. هیچ اعتبارنامه‌ای در این محیط وجود ندارد، بنابراین همهٔ چیزهای مربوط به «مجوزها» از مستندات رسمی Cloudflare نقل شده‌اند، نه از اجرای واقعی روی حساب شما.

---

## ۳. چرا «فقط اضافه‌کردن Secret» کافی نیست — با شاهد

`scripts/guard-deploy-config.mjs` روی فایل فعلی، هر دو حالت را رد می‌کند:

```
$ node scripts/guard-deploy-config.mjs
::error title=Unsafe Wrangler deploy::root (default): D1 database_id is the all-zero placeholder …   (exit 1)

$ node scripts/guard-deploy-config.mjs --env staging
::error title=Unsafe Wrangler deploy::env.staging: D1 database_id is the all-zero placeholder …      (exit 1)
```

### جدول سناریوها: بعد از افزودن Secretها روی push به `main` چه اتفاقی می‌افتد؟

| Secretها | ID روت (`wrangler.toml:14`) | ID staging (`wrangler.toml:38`) | رفتار Workflow |
|---|---|---|---|
| تنظیم نشده | — | — | ✅ موفق؛ Deploy با notice رد می‌شود (وضعیت فعلی، همان‌طور که در ران `36682857775` دیده می‌شود) |
| تنظیم شده | placeholder | هر مقداری | ❌ شکست در گام Guard؛ هیچ Deploy ای انجام نمی‌شود |
| تنظیم شده | واقعی | هر مقداری | ⚠️ Deploy محیط **root** = Worker `gozargah` (production) |
| تنظیم شده | placeholder | واقعی | ❌ push به `main` همچنان در گام گارد شکست می‌خورد (گارد روت را می‌سنجد)؛ ولی `Run workflow` با انتخاب `staging` موفق می‌شود |

> پس از patch شدن `deploy.yml` در این شاخه، محیط **staging فقط با `Run workflow` دستی و انتخاب `staging`** هدف گرفته می‌شود؛ push به `main` هرگز staging را دیپلوی نمی‌کند و همیشه محیط root (production) را هدف می‌گیرد.

---

## ۴. گام‌به‌گام: مسیر پیشنهادی «اول staging»

هدف: یک Worker مستقل `gozargah-staging` با D1 مستقل، بدون دست‌زدن به production.

### گام ۰ — پیش‌نیازها
```bash
node -v            # باید ≥ 22.12 باشد (وگرنه wrangler 4.143 اجرا نمی‌شود)
npm ci
```
> تأییدشده: `npx wrangler --version` → `4.143.0` و این نسخه Node ≥ 22 می‌خواهد (در `ci-v31.yml` هم همین قید مستند شده).

### گام ۱ — احراز هویت محلی (بدون توکن)
```bash
npx wrangler login     # OAuth در مرورگر؛ از مجوزهای خودِ کاربر استفاده می‌کند
npx wrangler whoami    # باید حساب و Account ID را نشان دهد
```
این روش امن‌ترین راه برای کارهای محلی است: هیچ توکنی ساخته و جایی ذخیره نمی‌شود.
اگر ترجیح می‌دهید با توکن کار کنید:
```bash
export CLOUDFLARE_API_TOKEN='...'    # فقط در همان session شل
export CLOUDFLARE_ACCOUNT_ID='...'
```
❌ فایل `.env` در ریشهٔ مخزن نسازید: `.gitignore` این مخزن `.env` را پوشش نمی‌دهد (فقط `.dev.vars` را پوشش می‌دهد).

### گام ۲ — پیدا کردن Account ID
داشبورد → **Workers & Pages → Account Details** (ستون کنار) → مقدار **Account ID**.
این را با **Zone ID** و **D1 database ID** اشتباه نگیرید؛ سه چیز متفاوت‌اند. (ارجاع: مستندات D1 می‌گوید Account ID از «Account Details in Workers & Pages» برداشته می‌شود.)

### گام ۳ — ساخت دیتابیس D1 استیجینگ
```bash
npx wrangler d1 create gozargah-staging
```
خروجی چیزی شبیه این است؛ **فقط مقدار `database_id`** را کپی کنید:
```toml
[[d1_databases]]
binding = "GZ_DB"
database_name = "gozargah-staging"
database_id = "<UUID-برگردانده‌شده>"
```
سپس آن را در `wrangler.toml` **خط ۳۸** جای‌گذاری کنید:
```toml
[[env.staging.d1_databases]]
binding = "GZ_DB"
database_name = "gozargah-staging"
database_id = "0000…0000"   # ← اینجا UUID واقعی staging
migrations_dir = "migrations"
```
❌ هرگز ID دیتابیس production را اینجا نگذارید. دو Worker با دیتابیس مشترک = داده‌های استیجینگ روی production.

بررسی صحت جای‌گذاری (بدون نیاز به اعتبارنامه):
```bash
node scripts/guard-deploy-config.mjs --env staging
# انتظار: Deploy config guard: D1 ID is configured for env.staging.
```

### گام ۴ — اعمال migrationها روی D1 استیجینگ
```bash
npx wrangler d1 migrations apply gozargah-staging --env staging --remote
```
- این دستور باید **بعد از** جای‌گذاری UUID اجرا شود (اگر UUID placeholder باشد، تماس API شکست می‌خورد).
- در محیط غیرتعاملی، تأییدِ مرحلهٔ confirmation رد می‌شود و بکاپ گرفته می‌شود (طبق `--help` خودِ wrangler).
- این گام به مجوز **D1 → Edit** (یا حساب کاربری خودتان) نیاز دارد؛ در صورت استفاده از توکن موقت، بعداً revoke کنید.

### گام ۵ — Deploy
```bash
npx wrangler deploy --env staging --dry-run   # فقط bundle؛ اعتبارنامه لازم ندارد
npx wrangler deploy --env staging             # Deploy واقعی
```
- خروجی، آدرس Worker را چاپ می‌کند؛ با `name = "gozargah-staging"` و `workers_dev = true` چیزی شبیه `https://gozargah-staging.<subdomain>.workers.dev` می‌شود.
- اگر Worker `gozargah-staging` **از قبل وجود نداشته باشد**، این Deploy آن را می‌سازد و اعتبارنامه باید اجازهٔ ساخت Worker داشته باشد (لاگین کاربر یا Admin سطح محصول). با توکن فقط-Editor روی Worker ناموجود، این گام شکست می‌خورد.
- تأییدشده در همین محیط: `wrangler deploy --env staging --dry-run` بدون هیچ اعتبارنامه‌ای کار می‌کند و bindingهای `GZ_DB (gozargah-staging)`، `AI` و `FORCE_INITIAL_PASSWORD_CHANGE="true"` را نشان می‌دهد.
- ⚠️ به‌خاطر ارث‌بری `[triggers]`، استیجینگ هم cron پنج‌دقیقه‌ای فعال دارد. روی D1 خالی استیجینگ، حلقهٔ سلامت فقط endpointهایی را probe می‌کند که در settings ذخیره شده‌اند؛ یعنی کاری انجام نمی‌دهد. اگر نمی‌خواهید، در `[env.staging]` اضافه کنید: `[env.staging.triggers]` با `crons = []`.

### گام ۶ — Smoke test
```bash
STAGING_BASE_URL="https://gozargah-staging.<subdomain>.workers.dev" npm run smoke:staging
```
این اسکریپت `/healthz` را برای `ok: true` و نسخهٔ `package.json`، و `/<panelPath>/api/status` را برای `dbOk: true` بررسی می‌کند و هیچ اعتبارنامه‌ای ارسال نمی‌کند.

### گام ۷ — اولین ورود و تغییر رمز
`https://gozargah-staging.<subdomain>.workers.dev/gozargah` → رمز پیش‌فرض `admin` → چون `FORCE_INITIAL_PASSWORD_CHANGE = "true"` است، تغییر اجباری رمز (حداقل ۸ کاراکتر) تا وقتی انجام نشود بقیهٔ APIهای پنل بسته است. رمز production را اینجا استفاده نکنید.

### گام ۸ — فعال‌کردن CI برای staging (این patch اعمال شد)

Secretها را در **Settings → Secrets and variables → Actions → New repository secret** با همین دو نام اضافه کنید:
- `CLOUDFLARE_API_TOKEN`
- `CLOUDFLARE_ACCOUNT_ID`

یا از خط فرمان خودتان (مقدار توکن را هیچ‌وقت در چت نفرستید):
```bash
gh secret set CLOUDFLARE_API_TOKEN -R bssbb1978/gozargah     # در prompt مقدار را paste کنید
gh secret set CLOUDFLARE_ACCOUNT_ID -R bssbb1978/gozargah
```

`deploy.yml` در همین شاخه به‌روزرسانی شد و حالا محیط را صریح هدف می‌گیرد:

| رویداد | محیط هدف | دستور wrangler |
|---|---|---|
| push به `main` | production (محیط root، Worker `gozargah`) | `deploy --env=` |
| Actions → Run workflow با انتخاب `staging` | staging (Worker `gozargah-staging`) | `deploy --env=staging` |
| Actions → Run workflow با انتخاب `production` | production | `deploy --env=` |

- گارد هم با همان فلگ اجرا می‌شود (`node scripts/guard-deploy-config.mjs --env=staging` یا `--env=`)، پس هر محیط فقط با D1 ID خودش اجازهٔ Deploy می‌گیرد.
- ورودی اختیاری `apply_migrations` (پیش‌فرض `false`) migrationها را پیش از Deploy روی همان محیط اعمال می‌کند: `d1 migrations apply <db> --env=<env> --remote`. این گزینه به **D1 → Edit** روی توکن نیاز دارد؛ اگر آن را روشن نمی‌کنید، توکن می‌تواند فقط Editor باشد.
- `--env=` (خالی) صریحاً محیط root را انتخاب می‌کند و هشدار «no target environment was specified» را هم خاموش می‌کند.
- ⚠️ اگر Worker مقصد (مثلاً `gozargah-staging`) **از قبل وجود نداشته باشد**، توکن CI باید بار اول Admin سطح محصول داشته باشد، وگرنه Deploy شکست می‌خورد؛ پس یا با توکن ادمین یک‌بار ساخته شود و بعد توکن Editor جایگزین شود، یا همان‌طور محلی (بند ۴، گام ۵) ساخته شود.
- ⚠️ push به `main` همچنان production را هدف می‌گیرد. اگر ID روت هنوز placeholder باشد، گارد جلوی Deploy را می‌گیرد (وصله قرمز می‌شود ولی چیزی دیپلوی نمی‌شود) و اگر ID روت واقعی باشد، Worker `gozargah` دیپلوی می‌شود.

`.gitignore` هم سخت‌تر شد: `.env` و `.env.*` (به‌جز `.env.example`) نادیده گرفته می‌شوند تا توکن اشتباهی commit نشود.

---

## ۵. مسیر جایگزین: production

1. دیتابیس تولیدی مستقل بسازید (یا موجود را انتخاب کنید) و UUID آن را در **`wrangler.toml` خط ۱۴** (`[[d1_databases]]` سطح روت) بگذارید.
2. migrationها را عمداً روی همان D1 تولیدی اعمال کنید:
   ```bash
   npx wrangler d1 migrations apply gozargah --remote
   ```
3. بعد از این‌کار، هر push به `main` (یا اجرای دستی Workflow) محیط root یعنی Worker `gozargah` را دیپلوی می‌کند. دقت کنید که این رفتار **خودکار** است، پس تا مطمئن نشده‌اید Secretها را اضافه نکنید.

---

## ۶. چه کارهایی را نکنید

- ❌ Global API Key — همیشه Account API Token بسازید.
- ❌ توکن را در چت، issue، commit، یا فایل بدون ignore نگذارید.
- ❌ به توکن دائمی CI دسترسی `D1 → Edit` یا `Workers → Admin` ندهید؛ این‌ها را موقت بگیرید.
- ❌ استیجینگ را روی D1 تولیدی وصل نکنید.
- ❌ تا زمانی که مقصد (staging/production) را مشخص نکرده‌اید، `deploy.yml` را در `main` با Secretها فعال نکنید.

---

## پیوست — یافته‌های دور دوم بررسی (از سورس wrangler 4.143.0 و مستندات تأیید شد)

| یافته | جزئیات | شاهد |
|---|---|---|
| تشخیص نوع توکن در wrangler | `getTokenType`: اول `/user/tokens/verify`؛ اگر خطای کد ۱۰۰۰ برگشت، توکن «حساب‌محور» است | `node_modules/wrangler/wrangler-dist/cli.js` |
| خروجی `wrangler whoami` | «You are logged in with an Account API Token…»، جدول `Account Name`/`Account ID`، پیام «The API Token is read from the CLOUDFLARE_API_TOKEN environment variable» و لینک زندهٔ مجوزها: `https://dash.cloudflare.com/<account_id>/api-tokens` (توکن کاربر: `/profile/api-tokens`) | همان سورس |
| هشدارهای بی‌ضرر | «Unable to retrieve email… User->User Details->Read» و «Unable to get membership roles… User->Memberships->Read» فقط تشخیصی‌اند و Deploy را متوقف نمی‌کنند | همان سورس |
| مسیرهای داشبورد | توکن کاربر: My Profile → API Tokens؛ توکن حسابی: Manage account → Account API tokens؛ ساخت توکن حسابی نیازمند Provisioning یا Super Admin و فقط زیرمجموعهٔ مجوزهای خودِ عضو | [مستندات توکن حسابی](https://developers.cloudflare.com/fundamentals/api/get-started/account-owned-tokens/) |
| ابزار جدید | `scripts/cf-preflight.mjs` (+ `scripts/test-cf-preflight.mjs` با mock محلی و `npm run preflight:cf`) توکن، Workerها، D1ها و تطبیق UUID با `wrangler.toml` را فقط‌خواندنی بررسی می‌کند و مقدار توکن را هرگز چاپ نمی‌کند؛ تست آن در CI داخل job همان Worker اجرا می‌شود | اجرای محلی: ۷/۷ تست سبز |
| محدودیت محیط بررسی | این sandbox به `api.cloudflare.com` دسترسی شبکه ندارد (`SSL_ERROR_SYSCALL`)، پس هیچ تماس واقعی API برای بررسی انجام نشد و شکل پاسخ‌ها از سورس/مستندات نقل شده است | `curl` ناموفق |

## ۷. شواهد اجراشده در همین جلسه

```
node scripts/test-deploy-guard.mjs      → Deploy guard tests: 6/6 passed
node scripts/test-smoke-staging.mjs     → Staging smoke-script tests: 6/6 passed
node scripts/guard-deploy-config.mjs            → exit 1 (root placeholder)
node scripts/guard-deploy-config.mjs --env staging → exit 1 (staging placeholder)
npx wrangler --version                  → 4.143.0
npx wrangler deploy --dry-run (CI=true) → WARNING محیط تعیین نشده، سپس root؛ exit 0
npx wrangler deploy --env staging --dry-run → بدون اعتبارنامه OK؛ bindings: GZ_DB(gozargah-staging), AI, FORCE_INITIAL_PASSWORD_CHANGE
npx wrangler d1 migrations apply --help → نیازمند <database> + پرچم --env (تأیید ترتیب گام‌ها)
تست ارث‌بری (wrangler.toml مصنوعی)      → هشدار «not inherited» برای kv_namespaces و d1_databases؛ هیچ هشداری برای triggers/observability
سورس wrangler 4.143.0                   → triggers: inheritable(…) / d1_databases: notInheritable(…)
gh run view 36682857775                 → Guard/Deploy = skipped؛ annotation: secrets not configured
gh pr view 8                            → MERGED (2026-09-30T07:17:28Z)
gh pr list --state open                 → خالی (دور اول)
node scripts/test-cf-preflight.mjs      → Cloudflare preflight tests: 7/7 passed (mock محلی، بدون شبکه)
npx js-yaml .github/workflows/ci-v31.yml → YAML valid (استپ تست preflight اضافه شد)
grep سورس wrangler                      → getTokenType + رشته‌های whoami + لینک مجوزها
curl https://api.cloudflare.com/...     → ناموفق: این محیط دسترسی شبکه به API کلادفلر ندارد
```

## ۸. منابع

- [Workers roles and permissions](https://developers.cloudflare.com/workers/authorization/workers/) — جدول نقش‌ها، scopeها، Routes، Bindings، جداول Legacy و Wrangler
- [Create API token](https://developers.cloudflare.com/fundamentals/api/get-started/create-token/)
- [Account API tokens](https://developers.cloudflare.com/fundamentals/api/get-started/account-owned-tokens/) — توکن حساب‌محور برای CI/CD (پیشوند `cfat_`)، پشتیبانی Workers و D1
- [Wrangler configuration](https://developers.cloudflare.com/workers/wrangler/configuration/) — کلیدهای ارث‌بری‌شده/نشده و `triggers`
- [D1 — Bulk import… (ساخت توکن D1:Edit)](https://developers.cloudflare.com/d1/tutorials/import-to-d1-with-rest-api/)
- [Wrangler system environment variables](https://developers.cloudflare.com/workers/wrangler/system-environment-variables/)
- داخلی: `docs/STAGING-DEPLOY.md`، `scripts/guard-deploy-config.mjs`، `.github/workflows/deploy.yml`، `wrangler.toml`

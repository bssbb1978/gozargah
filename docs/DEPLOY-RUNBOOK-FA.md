# راهنمای قدم‌به‌قدم Deploy گذرگاه روی Cloudflare

> **وضعیت تأیید این سند.** هر جا نوشته شده «تأییدشده»، یعنی با اجرای فرمان در همین checkout، یا با خواندن سورس `wrangler@4.143.0` داخل `node_modules`، یا با مستندات رسمی Cloudflare راستی‌آزمایی شده است. این محیط **به `api.cloudflare.com` دسترسی شبکه ندارد** (خطای `SSL_ERROR_SYSCALL`)، پس هیچ تماس واقعی با API کلادفلر انجام نشده و هیچ اعتبارنامه‌ای به‌کار نرفته است؛ بنابراین شکل پاسخ‌های API از سورس wrangler و مستندات نقل شده، نه از اجرای واقعی روی حساب شما. مسیرهای قابل‌تست آفلاین (منطق preflight) با یک mock محلی تست شده و لاگ آن در بند ۹ آمده است.

---

## ۰. خلاصهٔ دو دقیقه‌ای

| # | کار | زمان | دسترسی لازم |
|---|---|---|---|
| ۱ | Account ID را بردار (`npx wrangler whoami`) | ۱ دقیقه | — |
| ۲ | توکن بساز: **Workers → Editor** | ۳ دقیقه | — |
| ۳ | توکن را با `npm run preflight:cf` تست کن | ۱ دقیقه | — |
| ۴ | D1 بساز (`npx wrangler d1 create gozargah-staging`) و UUID را در `wrangler.toml` بگذار | ۲ دقیقه | **D1 → Edit** (موقت) |
| ۵ | migrationها را اعمال کن | ۱ دقیقه | **D1 → Edit** |
| ۶ | `npx wrangler deploy --env=staging` | ۱ دقیقه | Workers Editor (بار اول: Admin اگر Worker وجود ندارد) |
| ۷ | smoke test + تغییر رمز پیش‌فرض | ۲ دقیقه | — |
| ۸ | Secretها را در GitHub بگذار (اختیاری) | ۲ دقیقه | — |

**قاعدهٔ طلایی:** توکن دائمی CI = `Workers → Editor`، توکن راه‌اندازی = `D1 → Edit` و بعد از کار **revoke** شود. Global API Key هرگز.

---

## ۱. تصمیم اول: مقصد را انتخاب کن

| معیار | staging (پیشنهاد) | production |
|---|---|---|
| Worker | `gozargah-staging` | `gozargah` (محیط root) |
| D1 | دیتابیس مستقل `gozargah-staging` | دیتابیس مستقل `gozargah` |
| جای UUID در `wrangler.toml` | خط ۳۸ (`[[env.staging.d1_databases]]`) | خط ۱۴ (`[[d1_databases]]`) |
| تأثیر روی CI | فقط با `Run workflow` دستی | هر push به `main` |
| شروع از این؟ | ✅ بله | بعد از آنکه staging سبز شد |

⚠️ تا وقتی تصمیم نگرفته‌ای **Secretها را در GitHub نگذار**؛ چون گارد روی محیط root اجرا می‌شود و تا پر شدن ID روت، هر push به `main` وصلهٔ Deploy را قرمز می‌کند (بند ۴ را ببین).

---

## ۲. تصمیم دوم: کدام نوع توکن؟

| ویژگی | User API Token | Account-owned API Token |
|---|---|---|
| از کجا ساخته می‌شود | My Profile → API Tokens | Manage account → Account API tokens |
| پیشوند (امروز) | `cfut_` | `cfat_` |
| وابسته به کاربر | بله | نه (service principal؛ مناسب CI) |
| endpoint تأیید | `GET /user/tokens/verify` | `GET /accounts/{account_id}/tokens/verify` |
| پشتیبانی Workers/D1 در wrangler | ✅ | ✅ (هر دو در کامپتیبیلیتی‌متریس کلادفلر ✅ هستند) |
| چه کسی می‌تواند بسازد | خود کاربر یا ادمین | نیاز به قابلیت API Token Provisioning یا Super Admin؛ عضو فقط می‌تواند زیرمجموعهٔ مجوزهای خودش را بدهد |

منبع: [Create API token](https://developers.cloudflare.com/fundamentals/api/get-started/create-token/) و [Account API tokens](https://developers.cloudflare.com/fundamentals/api/get-started/account-owned-tokens/).

### 🔍 نکتهٔ ذره‌بینی (تأییدشده از سورس wrangler 4.143.0)

wrangler نوع توکن را این‌طور تشخیص می‌دهد:

```js
async function getTokenType(complianceConfig) {
  try { await fetchResult(complianceConfig, "/user/tokens/verify"); return "user"; }
  catch (e) { if (e.code === 1000) return "account"; throw e; }
}
```

یعنی اگر توکن **حساب‌محور** (`cfat_`) باشد، تماس با `/user/tokens/verify` خطای **کد ۱۰۰۰ (`Invalid API Token`)** می‌دهد و wrangler همان را «توکن حساب‌محور سالم» تفسیر می‌کند. پس:

- اگر توکن حساب‌محور داری و با دستور «تست توکن» صفحهٔ کلادفلر (که به `/user/tokens/verify` می‌زند) خطای 1000 گرفتی، **توکن خراب نیست** — این رفتار طبیعی است؛ آن را روی `/accounts/{account_id}/tokens/verify` تست کن.
- `npx wrangler whoami` این‌ها را چاپ می‌کند (رشته‌ها از سورس wrangler تأیید شد):
  - `👋 You are logged in with an Account API Token, associated with the account <name>.`
  - `ℹ️ The API Token is read from the CLOUDFLARE_API_TOKEN environment variable.`
  - جدول `Account Name` / `Account ID`
  - `🔓 To see token permissions visit https://dash.cloudflare.com/<account_id>/api-tokens` (برای توکن کاربر: `.../profile/api-tokens`) — همین لینک، صفحهٔ درست توکن را باز می‌کند.

---

## ۳. مرحله‌به‌مرحله (مسیر CLI — پیشنهادی)

### گام ۱ — پیش‌نیاز محلی

```bash
node -v     # باید ≥ 22.12 باشد؛ wrangler 4.143.0 حداقل Node 22 می‌خواهد (تأییدشده: npx wrangler --version → 4.143.0)
npm ci
```

### گام ۲ — Account ID را بردار

سه راه، هر سه معتبر:

1. **CLI (تأییدشده از سورس که جدول Account ID را چاپ می‌کند):**
   ```bash
   npx wrangler login      # اگر قبلاً لاگین نکرده‌ای (OAuth، بدون توکن)
   npx wrangler whoami
   ```
2. **داشبورد:** Workers & Pages → Account details → **Account ID**.
3. لینک مستقیم بعد از ساخت توکن: `https://dash.cloudflare.com/<account_id>/api-tokens`

> ⚠️ سه شناسه را قاطی نکن: **Account ID** (حساب) ≠ **Zone ID** (دامنه) ≠ **D1 database ID** (دیتابیس). در این مخزن فقط دو تای اول و سوم لازم می‌شود.

### گام ۳ — توکن بساز

**الف) User token:** داشبورد → **My Profile → API Tokens → Create Token → Create Custom Token**
**ب) Account-owned token (بهتر برای CI):** داشبورد → **Manage account → Account API tokens → Create Token**

پر کن:

| فیلد | مقدار |
|---|---|
| Token name | مثلاً `gozargah-ci-deploy` |
| Permissions | **Account → Workers → Editor** |
| Worker scope | اگر Worker از قبل وجود دارد: همان Worker (`gozargah` یا `gozargah-staging`). اگر وجود ندارد: سطح محصول (Account) |
| TTL/Expiry | اختیاری؛ برای توکن CI می‌توانی تاریخ بگذاری و قبلش یادآور بگذاری |
| IP filtering | اختیاری؛ برای GitHub Actions توصیه نمی‌شود (IP رانرها ثابت نیست) |

سپس **Continue to summary → Create Token → کپی** — مقدار توکن فقط **یک‌بار** نشان داده می‌شود.

> 🔍 اگر رابط قدیمی است، نام مجوز `Workers Scripts:Edit` را می‌بینی؛ Cloudflare می‌گوید معادل `Editor` در سطح محصول است (تأییدشده در جدول Legacy همان مستند).
> 🔍 مجوز **بیش از این لازم نیست**: نه `Zone → Workers Routes` (چون در `wrangler.toml` هیچ route/custom domain نداریم)، نه `Account Settings:Read`، نه `Workers AI`. برای bindingهای D1/AI هنگام Deploy به مجوز جدا نیاز نیست (نقل مستقیم مستند: «You do not need separate permissions on the bound resources to deploy the Worker»).

مقدار توکن را **فقط در همان session شل** بگذار:

```bash
export CLOUDFLARE_API_TOKEN='<همین‌جا paste کن>'    # در چت نفرست
export CLOUDFLARE_ACCOUNT_ID='<account id>'
```

> ❌ در `.env` نگذار (حتی با اینکه در این شاخه `.env` به `.gitignore` اضافه شد، عادت امن‌تر همان export است). ❌ هرگز Global API Key.

### گام ۴ — توکن را قبل از هر کاری تست کن

```bash
npx wrangler whoami          # نوع توکن + Account ID + لینک مجوزها
npm run preflight:cf         # بررسی کامل و فقط‌خواندنی
```

`preflight:cf` (تازه اضافه شده) این‌ها را چک می‌کند و **هیچ‌وقت مقدار توکن را چاپ نمی‌کند**:

- وجود و زنده‌بودن توکن (user token → `/user/tokens/verify`، حساب‌محور → `/accounts/{id}/tokens/verify`)
- دسترسی دیدن Workerها و وجود `gozargah` / `gozargah-staging`
- دیدن D1ها و **تطبیق UUID داخل `wrangler.toml` با دیتابیس واقعی همان حساب**
- اجرای گارد Deploy برای هر دو محیط

نمونهٔ خروجی وقتی همه‌چیز آماده است (اجرای واقعی روی mock محلی):

```
OK   Token verified as an account-owned API token (status: active).
OK   Worker "gozargah-staging" exists — a Workers Editor token scoped to it is enough to deploy.
OK   env.staging: deploy guard passes for D1 ID bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb (binding GZ_DB).
OK   env.staging: D1 ID bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb exists in this account as "gozargah-staging".

Preflight: all checks passed.
```

و در وضعیت فعلی مخزن (placeholderها):

```
FAIL root (production): deploy guard would block a live deploy — … all-zero placeholder …
FAIL env.staging: deploy guard would block a live deploy — … all-zero placeholder …
Preflight: 2 blocking problem(s), 0 warning(s).
```

> 🔍 اگر `whoami` گفت `Unable to retrieve email for this user. Are you missing the User->User Details->Read permission?` یا `Unable to get membership roles … User->Memberships->Read` — این‌ها فقط **هشدار تشخیصی** هستند (رشته‌ها از سورس wrangler تأیید شد) و Deploy را متوقف نمی‌کنند؛ اگر آزارت می‌دهند همان دو مجوز Read را اضافه کن.

### گام ۵ — D1 استیجینگ را بساز و ID را جای‌گذاری کن

```bash
npx wrangler d1 create gozargah-staging
```

خروجی یک بلوک TOML می‌دهد؛ فقط `database_id` را بردار و در `wrangler.toml` **خط ۳۸** بگذار:

```toml
[[env.staging.d1_databases]]
binding = "GZ_DB"
database_name = "gozargah-staging"
database_id = "00000000-0000-0000-0000-000000000000"   # ← UUID واقعی staging را اینجا بگذار
migrations_dir = "migrations"
```

سپس بلافاصله با گارد تأیید کن (بدون نیاز به اعتبارنامه):

```bash
node scripts/guard-deploy-config.mjs --env=staging
# انتظار: Deploy config guard: D1 ID is configured for env.staging.
```

> ❌ ID دیتابیس production را اینجا نگذار. staging باید D1 مستقل داشته باشد.
> این گام (و گام ۶) به مجوز **D1 → Edit** نیاز دارد: یا با توکن موقت D1-Edit، یا با `wrangler login` و حساب خودت. بعد از راه‌اندازی می‌توانی توکن D1-Edit را revoke کنی.

### گام ۶ — migrationها

```bash
npx wrangler d1 migrations apply gozargah-staging --env=staging --remote
```

- ترتیب اجرا مهم است: **اول UUID واقعی**، بعد این دستور (با placeholder، تماس API شکست می‌خورد).
- در محیط غیرتعاملی، مرحلهٔ تأیید رد می‌شود و **بکاپ خودکار** گرفته می‌شود (تأییدشده از `wrangler d1 migrations apply --help`).
- Worker خودش هم با `CREATE TABLE IF NOT EXISTS` اسکیما را می‌سازد (`src/db/store.ts:245`)، پس این گام «توصیهٔ قوی» است نه شرط فنی؛ در عوض دفتر `d1_migrations` را هم‌گام می‌کند.

### گام ۷ — Deploy

```bash
npx wrangler deploy --env=staging --dry-run    # فقط bundle؛ اعتبارنامه لازم ندارد (تأییدشده)
npx wrangler deploy --env=staging              # Deploy واقعی
```

- خروجی آدرس Worker را چاپ می‌کند: `https://gozargah-staging.<subdomain>.workers.dev`
- **بار اول** چون Worker وجود ندارد، اعتبارنامه باید اجازهٔ ساخت Worker داشته باشد؛ با توکن فقط-Editor روی Worker ناموجود، Deploy شکست می‌خورد. راه‌حل: یک‌بار با `wrangler login` (یا توکن موقت Admin) بساز، بعد توکن Editor کافی است.
- 🔍 **نکتهٔ ذره‌بینی (تأییدشده):** `[triggers] crons` از روت به `env.staging` **ارث می‌رسد** (برخلاف bindingها)، پس staging هم cron پنج‌دقیقه‌ای می‌گیرد. اگر نمی‌خواهی این‌طور باشد، در `[env.staging]` اضافه کن:
  ```toml
  [env.staging.triggers]
  crons = []        # توجه: اینجا آرایهٔ رشته است، نه [[env.staging.triggers.crons]]
  ```

### گام ۸ — Smoke test و اولین ورود

```bash
STAGING_BASE_URL="https://gozargah-staging.<subdomain>.workers.dev" npm run smoke:staging
```

بررسی‌ها: `/healthz` باید `ok: true` و نسخهٔ `package.json` را بدهد؛ `/<panelPath>/api/status` باید `dbOk: true` بدهد. بعد در مرورگر:

`https://gozargah-staging.<subdomain>.workers.dev/gozargah` → رمز `admin` → تغییر اجباری رمز (چون `FORCE_INITIAL_PASSWORD_CHANGE = "true"` است) → رمز production را اینجا استفاده نکن.

### گام ۹ — (اختیاری) فعال‌کردن CI

```bash
gh secret set CLOUDFLARE_API_TOKEN -R bssbb1978/gozargah    # مقدار را در prompt paste کن، نه در چت
gh secret set CLOUDFLARE_ACCOUNT_ID -R bssbb1978/gozargah
```
یا: **Settings → Secrets and variables → Actions → New repository secret**.

رفتار CI در این شاخه (فایل `deploy.yml` به‌روزشده):

| رویداد | محیط هدف | دستور | گارد |
|---|---|---|---|
| push به `main` | production (Worker `gozargah`) | `deploy --env=` | `--env=` |
| Run workflow → `staging` | staging (Worker `gozargah-staging`) | `deploy --env=staging` | `--env=staging` |
| Run workflow → `production` | production | `deploy --env=` | `--env=` |
| گزینهٔ `apply_migrations` (پیش‌فرض خاموش) | — | `d1 migrations apply <db> --env=<env> --remote` | — |

⚠️ اگر Secretها را بگذاری ولی ID روت (خط ۱۴) هنوز placeholder باشد، **گارد جلوی Deploy را می‌گیرد و وصله قرمز می‌شود** (چیزی دیپلوی نمی‌شود؛ این fail-closed بودن است، نه خرابی).

---

## ۴. مسیر بدون CLI (فقط داشبورد)

اگر نمی‌خواهی wrangler نصب کنی، همان روش Paste در README کار می‌کند:

1. فایل `dist/gozargah-worker.js` را از Releases بردار (یا `npm run build`).
2. Workers & Pages → **Create → Worker** → نام دلخواه → Create.
3. **Edit code** → محتوای فایل را جایگزین کن → **Deploy**.
4. Storage & Databases → **D1 → Create** → نام `gozargah`.
5. در Worker: **Settings → Bindings → Add → D1 Database** → Variable name دقیقاً `GZ_DB` → دیتابیس `gozargah` → Deploy.
6. `https://<worker>.workers.dev/gozargah` → ورود با `admin`.

در این مسیر به هیچ توکن یا Secret نیازی نیست و دسترسی‌های Cloudflare نقشی ندارند (چون خودت با حساب ادمین داشبورد کار می‌کنی).

---

## ۵. عیب‌یابی: خطا → علت → راه‌حل

| نشانه | علت محتمل | راه‌حل |
|---|---|---|
| `Authentication error [code: 10000]` | توکن مجوز لازم برای همان عملیات را ندارد، یا Account ID اشتباه است (پیام خود wrangler: «Please ensure it has the correct permissions for this operation») | در `https://dash.cloudflare.com/<account_id>/api-tokens` مجوز `Workers → Editor` را چک کن؛ مطمئن شو Worker در همان حساب است |
| خطای ۱۰۰۰ روی `/user/tokens/verify` با توکن `cfat_` | طبیعی است: توکن حساب‌محور است | با `/accounts/{account_id}/tokens/verify` یا `npm run preflight:cf` تست کن |
| Deploy می‌گوید Worker را نمی‌شود ساخت | توکن per-Worker scope دارد ولی Worker هنوز وجود ندارد | یک‌بار با دسترسی Admin/`wrangler login` بساز؛ یا از داشبورد Create کن |
| گارد می‌گوید `all-zero placeholder` | UUID واقعی در `wrangler.toml` نگذاشته‌ای | خط ۱۴ (root) یا خط ۳۸ (staging) را پر کن |
| گارد می‌گوید `no D1 database_id found` | بخش `d1_databases` در آن محیط تعریف نشده | بلوک `[[d1_databases]]` یا `[[env.staging.d1_databases]]` را اضافه کن |
| `d1 migrations apply` با خطای fetch/parse شکست می‌خورد | UUID هنوز placeholder است یا توکن D1:Edit ندارد | اول UUID را بگذار، بعد دستور را با توکن دارای D1:Edit اجرا کن |
| وصلهٔ CI روی push به `main` قرمز است | Secretها تنظیم شده ولی ID روت placeholder است (گارد عمداً fail-closed) | یا ID روت را پر کن (که آن‌وقت production دیپلوی می‌شود!)، یا Secretها را تا آماده‌شدن staging برندار |
| cron استیجینگ ناخواسته فعال است | `triggers` از روت ارث می‌رسد | `[env.staging.triggers]` + `crons = []` |
| `wrangler deploy` هشدار «Multiple environments … no target environment» می‌دهد | فلگ محیط نداده‌ای | `--env=staging` یا برای روت صریحاً `--env=` بگذار |
| `whoami` می‌گوید ایمیل/نقش‌ها را نمی‌تواند بخواند | مجوزهای `User Details:Read` / `Memberships:Read` نیستند | لازم نیست؛ اگر خواستی اضافه کن (Deploy را متوقف نمی‌کند) |
| `npm run preflight:cf` می‌گوید `Token cannot list Workers` | توکن per-Worker scope دارد | برای Deploy مانع نیست؛ فقط فهرست دیدن Workerها را ندارد |

---

## ۶. چک‌لیست نهایی staging

- [ ] `npx wrangler whoami` نوع توکن و Account ID را نشان می‌دهد
- [ ] `npm run preflight:cf` برای توکن خطای blocking ندارد
- [ ] `wrangler.toml` خط ۳۸ UUID واقعی staging دارد
- [ ] `node scripts/guard-deploy-config.mjs --env=staging` سبز است
- [ ] migrationها اعمال شده‌اند
- [ ] `wrangler deploy --env=staging --dry-run` بدون خطا اجرا می‌شود
- [ ] `wrangler deploy --env=staging` انجام شده و URL را گرفته‌ام
- [ ] `STAGING_BASE_URL=… npm run smoke:staging` سبز است
- [ ] رمز پیش‌فرض `admin` عوض شده است
- [ ] توکن موقت D1-Edit (اگر ساختم) revoke شده است
- [ ] فقط بعد از این مرحله سراغ Secretهای GitHub / production رفته‌ام

---

## ۷. منابع

- [Workers roles and permissions](https://developers.cloudflare.com/workers/authorization/workers/) — Editor/Admin، scopeها، Routes، Bindings، Legacy
- [Create API token](https://developers.cloudflare.com/fundamentals/api/get-started/create-token/) — مسیر منو و دستور تست `/user/tokens/verify`
- [Account API tokens](https://developers.cloudflare.com/fundamentals/api/get-started/account-owned-tokens/) — `cfat_`، شرط Provisioning/Super Admin، کامپتیبیلیتی‌متریس
- [Wrangler configuration](https://developers.cloudflare.com/workers/wrangler/configuration/) — کلیدهای ارث‌بری‌شده/نشده، `triggers`
- [D1 — create/Edit token](https://developers.cloudflare.com/d1/tutorials/import-to-d1-with-rest-api/)
- داخلی: `docs/CLOUDFLARE-DEPLOY-ACCESS-FA.md` (بررسی ذره‌بینی دسترسی‌ها)، `docs/STAGING-DEPLOY.md`، `scripts/cf-preflight.mjs`، `.github/workflows/deploy.yml`

---

## ۸. شواهد اجراشده در همین جلسه

```
node scripts/test-cf-preflight.mjs   → Cloudflare preflight tests: 7/7 passed (mock محلی؛ بدون توکن واقعی، بدون شبکه)
node -e "JSON.parse(package.json)"   → package.json valid
npx js-yaml .github/workflows/ci-v31.yml → YAML valid
npx wrangler --version               → 4.143.0
grep سورس wrangler                   → getTokenType: /user/tokens/verify و کد 1000 → "account"
                                       + رشته‌های whoami (Account API Token، لینک مجوزها، هشدار User Details/Memberships)
node scripts/guard-deploy-config.mjs [--env=staging] → exit 1 روی placeholderها (fail-closed)
npx wrangler deploy --dry-run --env=staging → OK؛ bindingها: GZ_DB(gozargah-staging), AI, FORCE_INITIAL_PASSWORD_CHANGE
curl https://api.cloudflare.com/...  → ناموفق: این محیط دسترسی شبکه به API کلادفلر ندارد (SSL_ERROR_SYSCALL)
```

## ۹. آنچه در این محیط قابل تأیید نبود

- اجرای واقعی هر تماس Cloudflare API (شبکه بسته است) و در نتیجه پاسخ‌های دقیق API روی حساب شما.
- اینکه توکن شما در عمل مجوز کافی دارد یا نه — این را با `npm run preflight:cf` روی سیستم خودت می‌بینی.
- زمان Deploy واقعی یا رفتار Workers در حساب شما.

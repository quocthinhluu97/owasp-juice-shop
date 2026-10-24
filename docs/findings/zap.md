# ZAP baseline: passive scan of the running app

## What ran

ZAP **2.17.0**, pinned by digest
(`ghcr.io/zaproxy/zaproxy:2.17.0@sha256:7aaa659b0d43078febd82e29bad112285c370727e86ab8340444220e17d9f0d2`,
the 2026-10-08 rebuild), plus the **pscanrulesBeta v50** add-on pinned by SHA-256
(`a979f7cd5d8be10e0338b417e006ec1e2f6ec79101010d570ddb5199892e921b`). Run on 2026-10-12/13.

```
zap-baseline.py -t http://juice:3000 -j -z "-silent" -c rules.tsv -J zap.json
```

- **Passive only.** The baseline spiders the app and inspects responses; it sends no attacks.
- **Network:** Juice Shop (`juice`) and ZAP share a user-defined `--internal` Docker network
  called `scan`. No port is published on the host, and neither container can reach the internet.
- **Spiders:** the traditional spider plus the Client Spider (`-j`, headless Firefox).
- **`-silent`:** no add-on update run, no check-for-updates, no telemetry.

| Run | Spider | Network | Rules run | Juice endpoints | Alert types | Time |
|---|---|---|---|---|---|---|
| 1 | traditional | `scan` (egress) | 66 | 65 | 11 | 0:36 |
| 2 | + Client Spider | `scan` (egress) | 67 | 134 | 16 | 2:48 |
| 3 | + Client Spider | `--internal` | **61** | 135 | 9 | 2:48 |
| 4 | + Client Spider | `--internal`, pinned add-on, `-silent` | 67 | 177 | 17 | 2:36 |
| 5 | as 4, with `-c rules.tsv` | same | 67 | 174 | 17 | 2:34 |

Run 5 is the configuration CI uses. It gives FAIL 2, WARN 7, IGNORE 4, PASS 54 and exit code 1.

## Findings: verdicts

Levels are from [`.zap/rules.tsv`](../../.zap/rules.tsv), which gives the reason for every rule in
column 4. FAIL means gating rule 6 (`.claude/rules/gating-policy.md`).

| Plugin | Alert | Risk (conf.) | Where | Verdict | Level |
|---|---|---|---|---|---|
| 10038 | CSP header not set | Medium (High) | `/`, `sitemap.xml`, `/ftp/*` | Real | **FAIL** |
| 10028 | Off-site redirect | High (Medium) | `/redirect?to=https://github.com/…` | Real | **FAIL** |
| 10098 | Cross-domain misconfiguration (`Access-Control-Allow-Origin: *`) | Medium (Medium) | everything | Real, limited | WARN |
| 10110 | Dangerous JS functions (`bypassSecurityTrustHtml`) | Low (Low) | `main.js`, `chunk-*.js` | Real | WARN |
| 10063 | Deprecated `Feature-Policy` header set | Low (Medium) | everything | Real, minor | WARN |
| 2 | Private IP disclosure (`192.168.99.100`) | Low (Medium) | `/rest/admin/application-configuration` | Real, minor | WARN |
| 90004 | COEP / COOP missing | Low (Medium) | `/`, `/ftp` | Hardening only | WARN |
| 10020 | Missing anti-clickjacking header | Medium (Medium) | `socket.io` polling only | Noise here | WARN |
| 10021 | `X-Content-Type-Options` missing | Low (Medium) | `socket.io` polling only | Noise here | WARN |
| 3 | Session ID in URL | Medium (High) | `socket.io?sid=…` | Noise | IGNORE |
| 10096 | Unix timestamp disclosure | Low (Low) | `styles.css`, `/` | Noise | IGNORE |
| 10109 | Modern web application | Info | `/` | Informational | IGNORE |
| 10049 | Cacheability (-1/-2/-3) | Info | various | Informational | IGNORE |
| 120000 | Information in browser sessionStorage | Info (High) | `/#/basket` (`itemTotal`) | Informational | IGNORE |

### 10038: no Content-Security-Policy (FAIL)

**Real.** The Angular shell and the `/ftp` pages are served without a CSP. Juice Shop has several
XSS bugs on purpose (DOM XSS through `bypassSecurityTrustHtml`, reflected and stored XSS). With no
CSP, each of them can run any script it likes. A CSP is the standard second line of defence, and
ZAP's confidence is High: the header is either there or not. **Gating:** blocks under rule 6 until
phase 8 adds a CSP or a waiver covers it.

### 10028: open redirect (FAIL)

**Real.** `/redirect?to=` is Juice Shop's open-redirect challenge. It checks the target against
an allowlist with a substring match, so the allowlist can be bypassed. A link that starts on our
own origin and lands on an attacker's site is a phishing tool, and it can leak tokens through the
`Referer` header. The traditional spider never sees it. The link is in the Angular side menu, so
only the Client Spider finds it. **Gating:** blocks under rule 6. The fix is an exact-match
allowlist.

### 10098: `Access-Control-Allow-Origin: *` (WARN)

**Real, but limited.** `cors()` is used with no options, so every response allows any origin.
Auth uses a Bearer token in the `Authorization` header, not a cookie, so another site can't make
the browser send authenticated requests just because of `*`. It's a weak default, not an open door,
and a developer would rightly push back on a red build for it.

### 10110: `bypassSecurityTrustHtml` (WARN)

**Real, and intended.** This is the Angular sanitizer bypass behind Juice Shop's DOM-XSS challenge
in search results. The rule only matches the function name (Low confidence), so it fires on safe
uses too. Gating code is Semgrep's job (rule 4). ZAP is useful here as a cross-check that the sink
ships in the built bundle.

### 10063: deprecated `Feature-Policy` header (WARN)

**Real, minor.** The research expected "Permissions-Policy not set". In fact the app *does* send a
policy, but under the old `Feature-Policy` name, which current browsers ignore. The fix is to rename
the header and convert its syntax.

### 2: private IP in `/rest/admin/application-configuration` (WARN)

**Real, minor.** The IP is a dummy config value. The bigger point is that an admin configuration
endpoint answers without authentication. The Client Spider only finds this API call because the
frontend fetches it.

### 90004: COEP / COOP missing (WARN)

**Hardening only.** Cross-origin isolation matters for apps that use `SharedArrayBuffer` or
high-resolution timers. Juice Shop uses neither.

### 10020 / 10021: socket.io responses without X-Frame-Options / nosniff (WARN)

**Noise here.** helmet sets both headers on the HTML pages (`frameguard`, `noSniff`). The socket.io
polling handler answers before helmet runs. Those responses are never framed or rendered as HTML.
They stay WARN rather than FAIL, because FAIL would block on a false positive.

### IGNORE: known noise

- **3 (session ID in URL):** the `sid` is socket.io's Engine.IO connection ID, not an auth session.
- **10096:** numeric constants in `styles.css`, not server timestamps.
- **10109, 10049, 120000:** informational. 120000 comes from the `client` add-on: the basket stores
  `itemTotal=0` in sessionStorage.

IGNORE only changes the console summary and the exit code. These alerts are still in the JSON.

### Found by reading the output, not by a rule

The traditional spider followed links such as `/juice-shop/build/routes/fileServer.js:68:18` and
`/juice-shop/node_modules/express/lib/router/index.js:280:10`. They come from a **stack trace on the
403 error page** for `/ftp/encrypt.pyc`, which leaks server file paths and framework internals. Rule
90022 (Application Error Disclosure) still passed. It's a real information leak that no rule
reported.

### Expected but not raised

- **10003 (vulnerable JS library):** Retire.js can't see library versions inside bundled, minified
  JS. Trivy covers dependencies (rules 2–3).
- **10037 (X-Powered-By):** helmet removes the header.
- **10202 (anti-CSRF tokens):** the SPA has no server-rendered forms.
- **10027 (suspicious comments):** the bundles are minified. The rule still spends 5–7 s per scan
  on `main.js`.
- **10017, 90003 (cross-domain scripts, SRI):** all scripts are first-party.
- **10035 (HSTS):** the scan runs over plain HTTP.

## Lessons from setting it up

### An SPA needs the Client Spider

The traditional spider downloads HTML and follows `<a href>` links. Juice Shop's HTML is an empty
`<app-root>`. Without `-j`, the scan saw 65 endpoints, all GET, and no API. With `-j`, it saw
134–177 endpoints, including the API (JSON responses, POSTs) and socket.io. Two of the most
interesting findings (10028, 2) only appear with `-j`. The cost is about 2 extra minutes.

### A browser doesn't respect the scan scope

In run 2, the Client Spider clicked the in-scope `/redirect?to=https://github.com/…` link. Firefox
followed the 302 and loaded GitHub, and the report listed 8 sites. ZAP raised no alerts on them,
because they were out of context, but the scan still browsed a third party from our machine.
**Fix:** the `--internal` network. Neither container has egress, so the redirect response is still
seen (10028 still fires) but the browser can't complete the trip.

### The pinned image wasn't the whole scanner

`--internal` silently dropped 6 rules (run 3: 61 rules). The stable image doesn't ship
`pscanrulesBeta`, and `zap-baseline.py` first starts ZAP with
`-addonupdate -addoninstall pscanrulesBeta` to fetch it from the internet. Without egress that run
fails and the scan carries on with fewer rules. Exit code and endpoint count looked normal. So in
every earlier run, part of the scanner was **unpinned code downloaded at runtime**: the image digest
never covered it.
**Fix (plan D12):**
- download `pscanrulesBeta-beta-50.zap`, check its SHA-256 (ZAP does no hash check on files in
  its plugin directories), and mount it read-only at `/zap/plugin/`;
- run with `-z "-silent"`, which skips the update run and turns off telemetry and update checks;
- in CI, also require ≥ 67 rules run, so a missing add-on fails the job instead of quietly
  weakening the scan.

Locally, the add-on is cached in `${XDG_CACHE_HOME:-$HOME/.cache}/zap-addons/`. Dependabot can't
see it, so bump it by hand when bumping the ZAP image.

### Exit codes don't prove the scan ran

- **0:** no WARN or FAIL.
- **1:** at least one FAIL.
- **2:** WARN only.
- **3:** error.

But a Python crash in `zap-baseline.py` also exits **1**; a missing `-c` file did this. So CI
treats the exit code only as a hint. The coverage check decides whether a scan really happened:
- `zap.json` parses;
- the `http://juice:3000` site is present;
- its `insight.endpoint.total` is ≥ 100;
- ≥ 67 rules ran.

## What the JSON carries (for phase 7 triage)

- **No WARN/FAIL/IGNORE level.** Triage reads `.zap/rules.tsv` and matches on `pluginid`.
  IGNOREd alerts are still in the report.
- **Plugin IDs not in `rules.tsv` can appear** (120000, from the client add-on). Triage treats
  them as report only.
- **Instances are capped at 5 per alert, and `count` is the capped number,** not the real total.
  The console showed ×11–×18 where the JSON says 5. Which 5 instances appear changes between runs
  (socket.io `sid`s, for example), so the fingerprint must not include instance lists or `count`.
- **The juice site isn't always first in `site[]`.** Select it by `@name`.
- **The coverage numbers are in the top-level `insights[]`,** keyed by `site`
  (`insight.endpoint.total`, `insight.log.error`, `insight.network.failure`).

## Phase 8 candidate

**Chosen (2026-10-13): CSP (10038).** It's the finding that turns the gate red. It teaches the
most: a starting policy in `Content-Security-Policy-Report-Only`, Angular's inline-style needs, the
cookie-consent inline script. The proof is clear: 10038 stops firing, and 10055 (CSP weaknesses)
starts judging the policy.

Not chosen:
- **Permissions-Policy (10063):** a cheaper alternative (a header rename).
- **The open redirect (10028):** a code fix rather than a header, so it fits the "code fix" slot
  in `fixing-findings.md` better than the "security header" slot.

## Fixed in phase 8

### F5: Content-Security-Policy (2026-10-24)

**Finding.** 10038 "Content Security Policy (CSP) Header Not Set" (FAIL in `.zap/rules.tsv`,
gating rule 6) on `/`, `/ftp`, `/ftp/coupons_2013.md.bak`, `/sitemap.xml`: the app set no CSP.

**Why it mattered.** Juice Shop has several XSS paths. Without a CSP, any injected script runs
with the page's full power. A CSP is the second line of defence: it doesn't fix the XSS, it
limits what an injected script can do.

**Fix.** Three changes (plan D9–D11, D16, D17):

1. `app/server.ts`: `helmet.contentSecurityPolicy` (helmet 4.6.0, `useDefaults: false`), enforcing,
   not Report-Only. Report-Only raises ZAP 10038-3 and triage matches on `pluginid`, so it would
   still gate.
   ```
   default-src 'self';
   script-src 'self' 'sha256-2ADpm…' 'sha256-9MsdB…' 'sha256-j0AtA…'
              https://binaries.soliditylang.org 'wasm-unsafe-eval';
   script-src-attr 'none';
   style-src 'self' 'unsafe-inline' https://fonts.googleapis.com;
   font-src 'self' https://fonts.gstatic.com;
   img-src 'self' data:;
   connect-src 'self' https://www.googleapis.com https://ethereum-sepolia.blockpi.network;
   worker-src 'self' blob:;
   object-src 'none'; base-uri 'self'; frame-ancestors 'self'; form-action 'self'
   ```
   - The three hashes are the inline scripts the server actually sends (computed from the served
     HTML, not the source): cookie-consent init on `/`, the subtitle parser on `/promotion`, and
     serve-index's sort script on `/ftp`. No `'unsafe-inline'` for scripts (D11).
   - The `text/vtt` subtitle `<script>` needs no hash: it's a data block, never executed.
   - `blob:` only in `worker-src` (the Web3 sandbox's compiler worker), not in `script-src`.
   - `connect-src` has no `ws:`/`wss:`: the first ZAP run flagged them (10055-4 wildcard: a
     WebSocket to any host). CSP Level 3 `'self'` covers same-origin WebSockets.
   - `/profile` keeps the CSP-bypass challenge's own policy: `res.set` replaces our header (checked
     logged in as `demo`: one header, `img-src 'self' assets/public/images/uploads/default.svg;
     script-src 'self' 'unsafe-eval'`). That route is deliberately weaker.
2. `app/frontend/angular.json` (D16): production `optimization.styles.inlineCritical: false`.
   Angular's critical-CSS inlining loads the full stylesheet with
   `<link media="print" onload="this.media='all'">`; `script-src-attr 'none'` blocks that handler and
   the app would render mostly unstyled. Turning inlining off removes the cause instead of adding
   `'unsafe-hashes'` for it.
3. `app/lib/startup/registerWebsocketEvents.ts` (D17): the first ZAP run after (1) still reported
   10038, now only on `POST /socket.io/?EIO=4&transport=polling` responses. engine.io answers
   `/socket.io/` before Express, so helmet never runs there (the same blind spot as 10020/10021 in
   phase 6). A `server.prependListener('request', …)` registered right after `new Server(...)` adds
   `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`, `nosniff` and
   `X-Frame-Options: DENY` to every `/socket.io/` response. It must come after: engine.io 4.1.2 and
   socket.io 3.1.2 remove and re-wrap all `request` listeners when they attach. engine.io 4.1.2 has no
   `headers` hook (added in 5.1.0, and those miss errors and the CORS preflight anyway). Waiving
   wasn't an option: the ZAP fingerprint is per site, so a waiver would also hide a real CSP
   regression on the HTML pages.

**Proof.**
- Served pages (`reports/phase8-f5/after/`): every executable inline script's hash is in the
  header, no inline event handlers left on `/`; socket.io handshake carries the strict CSP,
  `nosniff`, `DENY`.
- Browser (Chrome, 127.0.0.1:3001): `/`, `/promotion` (page and player render), `/ftp` and
  `/api-docs` render; DevTools console on `/` clean (no "Refused to …"), with the socket.io
  connection opened on load.
- ZAP baseline, same setup as phase 6 (`reports/phase8-f5/zap/`): **10038 gone**, and 10020/10021
  gone too. FAIL 2 → 1, WARN 8 → 6, PASS 53 → 56. The remaining FAIL is 10028 (open redirect,
  deliberate, waived).
- Triage on the newest local report from each scanner: **Gate PASSED, 0 blocking** (CI is the
  authoritative run).

**What ZAP now says about the policy.** 10055-6 `style-src 'unsafe-inline'` (Medium, WARN, not
gating): Angular Material and the server-rendered views use inline styles (D11, accepted).

**Costs and limits.**
- The hashes pin exact bytes. Any change to those inline scripts (a Juice Shop upgrade, an edited
  template) silently breaks that script until the hash is recomputed; the browser console shows it.
- The cookie-consent hash is for `config/default.yml`. `lib/startup/customizeApplication.ts`
  rewrites that inline script from `application.cookieConsent.*` at startup, so the configs that
  override it (7ms, addo, bodgeit, defcon33, mozilla, oss) need their own hash or the banner is
  blocked.
- XSS challenges that are verified server-side (localXss, reflectedXss, xssBonus, videoXss) still
  register as solved; the injected `alert` and the SoundCloud iframe no longer visibly run.
- Not checked in the browser: search, login (including Google OAuth, which depends on
  `connect-src https://www.googleapis.com`), basket, score board, a "challenge solved" notification
  arriving over socket.io, video subtitles, `/ftp` client-side sorting, and the Web3 sandbox
  (`binaries.soliditylang.org`, `'wasm-unsafe-eval'`, `blob:` workers). ZAP's Client Spider crawled
  the app with the CSP enforced, but that is not a functional check.
- 10063 (deprecated `Feature-Policy` instead of `Permissions-Policy`) is still a WARN: the cheap
  alternative this phase didn't pick.

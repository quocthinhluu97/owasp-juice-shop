# Semgrep: insecure code patterns

## What ran

Semgrep **1.179.0** (Community Edition, no login), pinned by digest
(`semgrep/semgrep:1.179.0@sha256:93963d92…e01b`). Rulesets `p/default`, `p/javascript` and
`p/typescript` from the registry: 1,075 rules. `--metrics=off`, one run writing both JSON and
SARIF. Scanned `app/` on 2026-10-04.

| | First run (no `.semgrepignore`) | With `.semgrepignore` |
|---|---|---|
| Files scanned | 971 | 688 |
| Scan errors | 41 | 8 |
| Findings | 55 | 37 |
| `ERROR` | 12 | 5 |
| `WARNING` / `MEDIUM` / `INFO` | 38 / 2 / 3 | 29 / 2 / 1 |

**Exit code is 0 with findings** (no `--error`). The docs contradict each other on this; the
run settles it.

**Coverage check.** Every tracked first-party server file was scanned: `routes/` (61), `lib/`
(24), `models/` (23), plus `data/*.ts`, the server-rendered `views/`, `server.ts` and `app.ts`
(121 files in all; the CI step checks this list). The 8 remaining errors are Angular `.html` templates that only partly parse: a real blind
spot, because Angular XSS lives in templates.

## Things that would have misled us

- **A custom `.semgrepignore` replaces the built-in defaults.** Without one, Semgrep silently
  skips `test/`, `*.min.js`, `node_modules/` and `dist/`. (Files over 1 MB are skipped too, but
  that's `--max-target-bytes`, not the ignore file; the largest tracked code file, `three.js`, is
  853 KB.) With a one-line
  `.semgrepignore`, 149 test files and both `*.min.js` files were suddenly scanned. Our file
  restates the defaults that matter.
- **Without a login, `extra.fingerprint` is the literal string `"requires login"`**, identical for
  every finding. That's the gitleaks `--redact` problem again: triage must build its own
  fingerprint (rule + file + line, as `triage-script.md` says).
- **SARIF results have `level: null`.** The severity sits on the rule
  (`tool.driver.rules[].defaultConfiguration.level`), not on each result. **Triage parses the
  JSON**, where every finding carries `extra.severity`.
- **Two severity schemes in one report:** `ERROR` / `WARNING` / `INFO` and the newer `MEDIUM`
  (the `.npmrc` rule). Triage's mapping must handle both and fail on unknown values.
- **Rules change between runs.** The registry rulesets are fetched fresh each time, so two scans
  of the same commit can disagree. Accepted for now: we get new rules for free, and the
  report records the Semgrep version (but not the ruleset version).
- **The researcher's prediction was wrong.** From reading the rule source, it expected the
  Sequelize rule to miss the SQL injection in `routes/login.ts`. It caught it. Only a real run
  tells you.

## What it found

All 5 `ERROR`s in first-party code were judged with three questions: does the code run in
production, can an attacker control the input, and is it a Juice Shop challenge?

| Finding | Verdict |
|---|---|
| `routes/login.ts:34`, `express-sequelize-injection` | **Real, deliberate.** Email concatenated into SQL. "Login Admin" challenge. |
| `routes/search.ts:23`, `express-sequelize-injection` | **Real, deliberate.** Search query concatenated into SQL. "Union SQL Injection" challenge. |
| `routes/currentUser.ts:31`, `remote-property-injection` | **Real, deliberate.** `?fields=` from the URL picks which user properties are returned; `fields=password` solves "password hash leak". |
| `routes/userProfile.ts:65`, `code-string-concat` | **Real, deliberate.** `eval()` on the username. SSTI/username challenge. |
| `data/static/users.yml:151`, `detected-generic-secret` | **Gitleaks' job.** The same fake secret Gitleaks reports; triage merges the two (below). |

Every first-party `ERROR` is real and exploitable, and every one is a deliberate challenge. On
this target, the phase 7 waivers will mostly say "deliberate challenge X", and a phase 8 code fix
will break a challenge on purpose.

`WARNING`s (29) include:
- `express-open-redirect` (`routes/redirect.ts`, also a challenge);
- directory listing ×5 in `server.ts`, and `res.sendFile` in the four file-server routes (the FTP
  and log-file challenges);
- `eval-detected` in `routes/userProfile.ts` and `routes/captcha.ts`;
- `hardcoded-jwt-secret` and `hardcoded-hmac-key` in `lib/insecurity.ts`. These are code rules,
  not `generic.secrets.*`, so they stay. They overlap with Gitleaks' `private-key` finding at
  `lib/insecurity.ts:21`, and triage should expect two tools pointing at one key;
- 8 Terraform rules (non-gating, below).

## What it missed

Four well-known server-side challenges are in files Semgrep scanned, and it flagged none of them:

| Challenge | Where | Why a pattern scanner misses it (likely) |
|---|---|---|
| NoSQL injection (forged review) | `routes/updateProductReviews.ts` | The three rulesets have no JavaScript NoSQL/MongoDB rules at all (only `python.pymongo`). |
| XXE | `routes/fileUpload.ts` → `lib/xml.ts` | The unsafe flags (`XML_PARSE_NOENT \| XML_PARSE_DTDLOAD`) are right there in `lib/xml.ts:35`, but the XXE rules only know the older `libxmljs` API (`parseXml(…, {noent: true})`), not `libxml2-wasm`'s `ParseOption` flags. |
| SSRF | `routes/profileImageUrlUpload.ts` | A one-step flow (`url = req.body.imageUrl`, then `fetch(url)`) that taint analysis handles easily, but the only JS SSRF rule matches member calls like `request.get(…)`/`axios.get(…)`, not the global `fetch()`. |
| Code execution (B2B order) | `routes/b2bOrder.ts` | The code string passed to `vm.runInContext` is a literal; user data reaches `notevil`'s `eval` (imported as `safeEval`), a library no rule models. |

**Lesson.** In every case the vulnerable flow is simple; what's missing is a rule for that
*library* or *API*. SAST finds the bugs that look like the patterns it knows: injection into
well-known sinks of well-known libraries. A clean Semgrep result says nothing about logic bugs,
custom data stores or flows across files. ZAP (phase 6) and manual review cover different ground.

## Configuration decisions

- **`.semgrepignore`** (each line has its reason in the file):
  - `app/data/static/codefixes/`: coding-challenge answer options, read as text and displayed,
    never executed.
  - Tests: `app/test/` and `*.spec.ts`.
  - Third-party files: `*.min.js` and `three.js`, which caused all 3 timeouts.
  - `node_modules/`, `dist/` and `build/`.

  The re-run removed exactly 18 findings (15 in `codefixes/`, 3 JWTs in `*.spec.ts`), with no
  other change.
- **Secret rules (`generic.secrets.*`, 44 rules) stay enabled; triage merges them, never gates on
  them.** Gitleaks owns secrets (rule 1). Triage labels these findings `category=secret` and merges
  each with a Gitleaks finding on the same file + line. Without a match it still reports them,
  so a secret only Semgrep sees doesn't vanish, but it doesn't block. Today the only hit,
  `users.yml:151`, matches Gitleaks' `generic-api-key` on the same line. (First decided as
  "drop them"; changed after review because dropping would hide Semgrep-only secrets.) Filtering
  on the prefix beats 44 `--exclude-rule` flags, which would break silently when the registry
  adds a rule.
- **Terraform stays scanned but never gates.** `terraform/` and `infrastructure/` are challenge
  material (the "misplaced IaC files" challenge), and nothing deploys them. Nothing else scans
  Terraform: Checkov in phase 5 covers only Dockerfile and GitHub Actions. So the findings stay
  visible and never block.
- **Rule 4 keeps its exclusion form** ("first-party code, not node_modules, tests, build output"),
  with these named exclusions added to `gating-policy.md`: Terraform, `.npmrc`, and
  `generic.secrets.*`. An allow-list of directories was considered and rejected: `app.ts`,
  `data/*.ts`, `rsn/` and the server-rendered `views/` (the SSTI challenge lives in
  `userProfile.pug`) would silently never gate, and so would any new directory.

## Notes for phase 7

- Parse the JSON, not the SARIF. Build the fingerprint from `check_id + path + start.line`;
  `extra.fingerprint` and `extra.lines` are redacted without a login.
- Map `ERROR`/`WARNING`/`INFO` and `LOW`/`MEDIUM`/`HIGH`/`CRITICAL` explicitly; fail on anything
  else.
- `generic.secrets.*` → `category=secret`; merge with Gitleaks on file + line; never gate.
- Rule 4 scope as in `gating-policy.md`: everything first-party except the named exclusions.
- Coverage: fail if `routes/`, `lib/`, `models/`, `data/*.ts`, `views/`, `server.ts` or `app.ts` are missing from `paths.scanned`, or if
  `errors[]` has anything other than the known Angular template partial parses.

## Phase 8 candidate

**`routes/search.ts` SQL injection → parameterised query** (`replacements` in
`sequelize.query`). It's the textbook fix, and Semgrep should show the finding gone.

- **Don't copy the "correct" answer from `codefixes/`.** `unionSqlInjectionChallenge_2_correct.ts`
  puts the placeholder inside a quoted literal (`LIKE '%:criteria%'`). Sequelize v6 doesn't
  substitute replacements inside string literals, so search would match the literal text
  `:criteria` and return nothing. Semgrep would still report the finding as fixed: a fix that
  satisfies the scanner and breaks the feature. (Not yet run; confirm in phase 8.) Use
  instead:
  ```ts
  models.sequelize.query(
    'SELECT * FROM Products WHERE ((name LIKE :q OR description LIKE :q) AND deletedAt IS NULL) ORDER BY name',
    { replacements: { q: `%${criteria}%` } })
  ```
- **Cost:** `search.ts:23` is the vulnerable line for both "Union SQL Injection" and "Database
  Schema", so both challenges break, as does `test/cypress/e2e/search.spec.ts`. Note it in
  `VENDORED.md`.

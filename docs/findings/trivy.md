# Trivy: vulnerable packages in the image and the lockfiles

## What ran

Trivy **0.75.0**, pinned by digest (`aquasec/trivy:0.75.0@sha256:af6acf9a…855daa`), vuln scanner
only (Gitleaks and Checkov cover secrets and misconfig). JSON output, `--list-all-pkgs`. Run on
2026-10-03 against `juice-shop:local` built from v20.2.0 with the committed lockfiles.

| Scan | Target | Packages | Vulnerability rows |
|---|---|---|---|
| `trivy image` | Debian 13.7 OS packages (distroless base) | 14 | 31 |
| `trivy image` | npm packages installed in the image | 695 | 106 |
| `trivy fs app/` | `package-lock.json` (dev deps excluded by default) | 645 | 114 |
| `trivy fs app/` | `frontend/package-lock.json` (dev deps excluded) | 660 | 39 |

Both scans covered what they should: the OS was detected and every result lists packages. A scan
that silently found nothing to scan would also produce a "clean" JSON file.

**Why pin by digest (Trivy specifically).** In March 2026, Trivy v0.69.4–0.69.6 were published
as malicious builds, and 76 of 77 `trivy-action` tags were force-pushed to code that stole CI
secrets ([GHSA-69fq-xp46-6x23](https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23)).
A tag can be moved; a digest cannot. That's also why CI runs the pinned image directly instead
of `trivy-action`.

## Counts

| | Critical | High | Medium | Low |
|---|---|---|---|---|
| Image: OS packages | 0 | 0 | 23 | 8 |
| Image: npm | 9 | 46 | 43 | 8 |
| fs: `package-lock.json` | 9 | 51 | 46 | 8 |
| fs: `frontend/package-lock.json` | 1 | 13 | 21 | 4 |

- **All Critical/High are in npm packages.** The distroless base is in good shape.
- **50 of the 55 Critical/High in the image have a fix**, so gating rule 3 will block on them in
  phase 7. The build is expected to go red.
- **Nothing is in CISA KEV.** Checked against KEV catalogue 2026.10.02 (1,733 entries). 5 of
  the 155 IDs aren't CVEs (`GHSA-…`, `NSWG-ECO-…`) and can never match KEV; triage must say so,
  not treat them as "not in KEV".
- **`FixedVersion` is a comma-separated list, one fix per release line, not sorted**, e.g.
  `5.3.2, 4.9.4, 6.0.0-rc.5`. The triage parser must keep it as a list.

## Image versus lockfiles

Each finding keyed by CVE + package + installed version:

| In both | Image only | fs only |
|---|---|---|
| 106 | 31 | 36 |

- **The 31 image-only rows are all Debian OS packages** (`libc6` ×21, plus `gcc-14-base`,
  `libgcc-s1`, `libgomp1`, `libstdc++6` and `zlib1g` ×2 each). No lockfile lists them. For npm
  packages, nothing is image-only: the lockfile accounts for every npm finding in the image.
- **28 fs-only are from `frontend/package-lock.json`.** Trivy's "not dev" flag does *not* mean
  "ships to the browser". **23 rows are build/test tooling**, installed in the build stage and
  never reaching a user. They count as production for two different reasons:
  - **12 rows are devDependencies that npm marks `devOptional`** (`undici` 7.29.0 ×10 via
    `jsdom`, plus `vitest` and `@vitest/mocker`). `vitest` and `jsdom` are in the frontend's
    `devDependencies`, but they are also optional peers of `@angular/build`, a production
    dependency. So the lockfile marks them `"devOptional": true` instead of `"dev": true`.
    Trivy only excludes `dev: true`.
  - **11 rows come from build tools listed under `dependencies`.** Juice Shop puts
    `@angular/build`, `@angular/cli`, `@angular/compiler-cli`, `@cyclonedx/cyclonedx-esbuild`,
    `sass` and `typescript` there, not in `devDependencies`, so what they pull in counts as
    production: `fast-uri` ×6 (via `ajv`), `hono` ×4 (via `@modelcontextprotocol/sdk` ←
    `@angular/cli`) and `piscina`.
  - **3 rows plausibly ship in the browser bundle:** `elliptic` (via ethers), `parseuri` (via
    socket.io-client) and `@angular/router`.
  - **2 rows are unverified:** `ws` 8.18.0 via `@ethersproject/providers`. Its browser build
    normally uses the native WebSocket instead.

  **For phase 7:** gating rule 3 blocks on "production dependencies", and Trivy marks all 28 as
  production. Triage needs its own label for frontend-lockfile findings, at least "frontend
  build tooling" versus "browser bundle", and the rule has to say whether build tooling blocks.
  Triage can walk `Packages[].DependsOn` in the fs report (present because of
  `--list-all-pkgs`; e.g. `jsdom@29.1.1` lists `undici@7.29.0`) to find each package's top-level
  parent. It can't see `devOptional`, so for that it needs the lockfile or a rule. The root
  lockfile's prod/dev split has the same `devOptional` gap.
- **8 fs-only are from the root lockfile** (`brace-expansion` ×6, `moment`, `js-yaml`). They
  revealed a real problem, below.

### Finding: the image doesn't fully follow the committed lockfile

The image has different versions than `app/package-lock.json` for **11 production packages**
(compared against the lockfile copied out of the built image). Some went up: `moment` 2.30.1 →
2.31.0, `js-yaml` 3.15.1 → 3.15.2, `brace-expansion` 1.1.18 → 1.1.21 and
`glob/node_modules/brace-expansion` 2.1.4 → 2.1.7 (each accounts for 3 of the 6
`brace-expansion` rows). Some went down: `core-util-is` 1.0.3 → 1.0.2, `lowercase-keys` 1.0.1 →
1.0.0. Two nested copies disappeared (`cacheable-request/node_modules/lowercase-keys`,
`mime-types/node_modules/mime-db`), which is hoisting. Up, down and hoisted together is the
signature of `npm dedupe`, which re-resolves the tree within the `^` ranges. The likely cause is
`RUN npm dedupe --omit=dev` in the Dockerfile, but that's not verified by a build without it.

Why it matters:
- **The build isn't reproducible**, which contradicts the claim in `app/VENDORED.md`. Two builds
  on different days can ship different code.
- **The lockfile scan can be wrong about production.** Here drift happened to *remove* 8
  findings. It could equally add a vulnerable version the lockfile scan never sees. The image
  scan is the ground truth for what ships.

`app/VENDORED.md` still says "builds are reproducible"; it now points here.

**Phase 8 candidate:** `npm ci --omit=dev` instead of `npm install` + `npm dedupe`, then confirm
that the image lockfile equals the repo lockfile. Done in phase 8 F2 (see below).

## Real versus noise

"Imported by first-party code" below is grep-level evidence (`routes/`, `lib/`, `data/`,
`server.ts`), not proof of reachability.

**Real, reachable, deliberate.** These are the vulnerabilities Juice Shop's challenges are built
on. Bumping them breaks challenges. Waive them in phase 7 with that reason.
- `jsonwebtoken` 0.1.0 (via `express-jwt`) and 0.4.0: **CVE-2015-9235**, signature check
  bypass with an altered token. Used by `lib/insecurity.ts` and `routes/verify.ts`. JWT forging
  challenges.
- `sanitize-html` 1.4.2: a direct dependency pinned to an ancient version, used by
  `lib/insecurity.ts`. XSS challenges.

**Real, reachable, not deliberate.**
- `multer` 1.4.5-lts.2 (11 rows, 10 High): direct dependency, used in `server.ts` for file
  uploads. Upload handling is an attack surface. Every fix is on 2.x, so this is a major
  upgrade (1 → 2) that may change the upload API and break upload challenges.

**Present, probably not reachable at runtime.**
- `crypto-js` 3.3.0, two Criticals, pulled in by `pdfkit` 0.11.0, which `routes/order.ts` uses
  for order PDFs. crypto-js code *does* run on every PDF: pdfkit calls `CryptoJS.MD5` in its
  constructor to make the file ID. Neither vulnerable function is reached, though (checked in
  the installed `pdfkit/js/pdfkit.js`):
  - **CVE-2023-46233** (weak PBKDF2): pdfkit never calls `PBKDF2`, encrypted or not. It only
    appears in `pdfkit.standalone.js`, which bundles all of crypto-js.
  - **CVE-2026-71851** (weak `WordArray.random()`): pdfkit only uses it to encrypt a PDF with a
    password, and `routes/order.ts` calls `new PDFDocument()` with none.
- `decompress` 4.2.1 (Critical, **no fix**): pulled in by `download`, which `lib/utils.ts` uses
  to fetch images at startup. `download` only calls `decompress` when asked to extract an
  archive, and Juice Shop doesn't ask. Rule 3 doesn't block it anyway (no fix).
- `tar` 6.2.1 (12 rows, incl. 1 Critical): a direct dependency of `sqlite3` 5.1.7 (and of its
  nested `node-gyp`/`cacache`), not required by anything in `sqlite3/lib` (grep-level), so at most
  it's used at install time and doesn't run when the app runs. Every fix is on the 7.x line. Whether a newer `sqlite3` moves to tar 7 is not checked.

**OS packages.** `libc6` has 21 rows, all Medium/Low. Nothing to do now. They clear when the
distroless base image is updated.

## "Fix available" isn't always something you can act on

`undici` 5.29.0 has 13 rows, 3 of them High, all with a "fix". But every fix is on the 6.x line or
later, and `@ai-sdk/provider-utils` requires `undici ^5.29.0`. Getting the fix means upgrading
the parent package, or overriding the version and hoping nothing breaks. `tar` is the same story
with `sqlite3`.

Gating rule 3 says "blocks if a fix is available". For transitive dependencies, a fix on another
major line isn't always actionable. Consider this for phase 7: triage could report "fix requires
a major upgrade of `<parent>`" so a developer knows what the fix actually costs.

## Notes for phase 7

- **Tell image from fs by `ArtifactType` (`container_image` / `filesystem`) and `Class`, never by
  name.** In CI the image is scanned from a tar (`--input`), so `ArtifactName` and the OS
  `Target` become `/in/juice-shop.tar`, not `juice-shop:local` as in the local reports.
- **Take the parser fixtures from the CI `trivy-reports` artifact**, not from local runs.
- `FixedVersion` is a list (above); non-CVE IDs can't be checked against KEV (above);
  frontend-lockfile findings need their own label (above).

## `.trivyignore`

**Nothing is ignored.** The deliberate findings are gating decisions, and they belong in
`triage/waivers.yaml` (phase 7) with an owner and an expiry date. They don't belong in a scanner
config that hides them from the report. The "probably not reachable" findings stay visible as
well: grep-level evidence is a reason to deprioritise, not to suppress.

## Phase 8 candidates

1. **Reproducible install:** `npm ci --omit=dev` instead of `npm install` + `npm dedupe` (finding
   above). Done in phase 8 F2 (see below).
2. **Dependency bump:** none of the top packages is a simple same-major bump: `multer` needs
   1 → 2, and `undici` and `tar` need parent upgrades. Before picking one, list the High/Critical
   findings whose fix is on the *installed* major line. Those are the cheap bumps.

## Fixed in phase 8

### F1: in-range lockfile refresh (2026-10-24)

**Finding.** Phase 7's triage blocked on five lockfile-only rows, all marked "presence: fs only"
(the image already had fixed versions):

- `brace-expansion` 1.1.18 and 2.1.4: CVE-2026-102276 and CVE-2026-102278 (High), 4 rows.
- `js-yaml` 3.15.1: CVE-2026-84375 (High), 1 row.

Three more were waived until 2026-11-30 as "deferred to phase 8", because they were in the image
and reachable:

- `compression` 1.8.1: CVE-2026-87776 (High), used directly in `server.ts`.
- `proxy-addr` 2.0.7: CVE-2026-90711 (Critical), used by express core.
- `handlebars` 4.7.9: CVE-2026-106445 and CVE-2026-106446 (Critical), used by the `hbs` view
  engine (`server.ts:164`).

**Why it mattered.** The image already shipped `brace-expansion` 1.1.21 / 2.1.7 and `js-yaml`
3.15.2, because `npm install` plus `npm dedupe` drift off the lockfile (the drift section above).
The lockfile was stale. Switching to `npm ci` (F2) without refreshing it first would have put the
vulnerable versions into the image.

**Fix.** Inside the pinned container `node:24.22.1-trixie@sha256:016f604a11c4c725f0a4c62e29ff11adab153d297bf97046c9bf2ddb9f1011d3`,
root lockfile only, `package.json` unchanged:

```bash
npm update brace-expansion js-yaml compression proxy-addr hbs --package-lock-only --ignore-scripts --no-audit --no-fund
```

| Lockfile path | Before | After | Note |
|---|---|---|---|
| `brace-expansion` | 1.1.18 | 1.1.21 | |
| `glob/node_modules/brace-expansion` | 2.1.4 | 2.1.7 | |
| `@typescript-eslint/typescript-estree/node_modules/brace-expansion` | 5.0.9 | 5.0.12 | moved by `npm update` (below) |
| `js-yaml` | 3.15.1 | 3.15.2 | |
| `@eslint/eslintrc/node_modules/js-yaml` | 4.3.1 | 4.3.2 | moved by `npm update` (below) |
| `xmlbuilder2/node_modules/js-yaml` | 4.3.1 | 4.3.2 | moved by `npm update` (below) |
| `compression` | 1.8.1 | 1.8.2 | adds `destroy` 1.2.0, already in the lockfile |
| `proxy-addr` | 2.0.7 | 2.0.8 | |
| `hbs` | 4.2.1 | 4.4.0 | pins `handlebars` 4.7.10 |
| `handlebars` | 4.7.9 | 4.7.10 | |

- `npm update <name>` moves every copy of that name in the tree, so the extra copies of
  `brace-expansion` 5.x and `js-yaml` 4.x moved too.
- `hbs` 4.4.0 was 2 days old when taken. That's an accepted risk (D3). It
  pins `handlebars` 4.7.10 exactly, so no `overrides` entry was needed.

**Proof.** Local Trivy 0.75.0 on the new lockfile (`reports/phase8/`), compared with the phase 7
CI reports (run 38422003321):

- `trivy fs`: the F1 rows are gone, 12 rows across Critical/High/Medium: `brace-expansion` ×6
  (CVE-2026-102276, -102277, -102278), `js-yaml` ×1, `compression` ×1, `handlebars` ×3
  (CVE-2026-106444, -106445, -106446) and `proxy-addr` ×1 (the root copy). One `proxy-addr` row
  remains; see lesson 1.
- `trivy image`: the `compression`, `proxy-addr` and `handlebars` rows are gone (5 rows).
  `brace-expansion` and `js-yaml` were already fixed in the image.
- Image build OK. Smoke test HTTP 200 on `127.0.0.1:3001`, and no errors in the logs.
- Triage dry run (phase 7 CI inputs with the new Trivy reports, `--offline`): 8 → 5 blocking.
  The five F1 rows are gone, and two new `@angular/router` rows are blocking (lesson 2). The four
  removed waivers match nothing now: 0 expired waivers, 0 waiver warnings.

**Lessons.**

1. **`proxy-addr` 2.0.7 still appears in the fs scan.** It's a second copy in the **frontend**
   lockfile, via `@angular/cli` → `express` 5. It's build stage only (D7), so it doesn't gate.
   The removed waiver's fingerprint (CVE + package + version) had silently covered both copies,
   though its reason only described the backend one. A waiver can match more than its reason
   talks about.
2. **The newer Trivy DB added findings F1 didn't cause.** Six days after phase 7 it reported
   `@angular/router` 22.1.1 CVE-2026-111751 and CVE-2026-111752 (High, a frontend direct
   dependency). They gate rule 3; the decision is pending. It also reported build-stage-only
   `vite` 8.1.5, `@modelcontextprotocol/sdk` 1.29.0 and `hono` 4.13.1 (reported, not gated).
   Scan results move even when the code doesn't.

### F2: install exactly what the lockfile says (2026-10-24)

**Finding.** After F1, the image still didn't follow the committed lockfile (the drift section
above). Compared with `app/package-lock.json`, 14 root packages drifted:

- **12 at a different version.** Three moved down: `mime-db` 1.54.0 → 1.52.0, `core-util-is` 1.0.3
  → 1.0.2, `lowercase-keys` 1.0.1 → 1.0.0. Nine moved up: `moment` 2.30.1 → 2.31.0,
  `sqlite3/…/http-cache-semantics` 4.2.0 → 4.3.0, `@types/node`, `undici-types`, `ansi-regex`,
  `is-core-module`, `@noble/hashes`, `pug-filters/…/resolve`, and `readable-web-to-node-stream/…/readable-stream`.
- **2 lock entries merged away:** `cacheable-request/…/lowercase-keys` and `mime-types/…/mime-db`.

**Why it mattered.** The build wasn't reproducible, and the lockfile scan and the image disagreed.
F1 showed the disagreement goes both ways: the fs scan can miss a finding the image has, or report
one the image doesn't.

**Fix.** Two changes, in `app/Dockerfile` and `app/package.json`:

- Installer stage: `RUN npm install --omit=dev` and `RUN npm dedupe --omit=dev` become
  `RUN npm ci --omit=dev`. `npm dedupe` is dropped because it re-resolves every duplicated package
  from the registry, which undoes the lock (npm's arborist source, read during research).
- Upstream postinstall: `cd frontend && npm install` becomes `cd frontend && npm ci` (phase 8 plan,
  D5). The frontend lockfile is now enforced too: `npm ci` fails on a lock/`package.json` mismatch
  instead of silently rewriting the lock.

**Proof.** The image was built with the F1 lockfile and the new Dockerfile, then scanned with Trivy
0.75.0 (`reports/phase8-f2/`). A stdlib script compared the npm packages in the image under
`juice-shop/node_modules` (Trivy `FilePath`) with the lockfile's non-dev entries:

- before (old Dockerfile): 687 compared, 12 mismatched, 2 missing;
- after: 689 compared, 0 mismatched, 0 missing, 0 extra. The image's npm packages are identical to
  the lockfile.

**Consequence (the lesson).** Matching the lockfile made the image scan worse by 2 rows (140 → 142),
because the drift had been hiding two findings:

- `moment` 2.30.1: CVE-2026-17495 (Medium, fix 2.31.0), via `sequelize` and `finale-rest`.
- `http-cache-semantics` 4.2.0, nested under `sqlite3`: CVE-2026-93748 (High). Trivy lists no fix,
  and 4.3.0 wasn't flagged in the old image, because the advisory has no fixed-version field.

Neither gates. Medium isn't a gating class, and rule 3 only gates a High with a fix listed. The
triage dry run is unchanged at 3 blocking. Both could be refreshed in range like F1
(`npm update moment http-cache-semantics --package-lock-only`). That refresh is a separate
follow-up commit (F2b below), so this commit's proof stays tied to the image that was scanned.

The "no fix listed" gap is worth remembering. Rule 3 trusts Trivy's `FixedVersion`, so a missing
field turns a fixable High into report-only.

**Also.** Upstream's `|| cd .` still hides a failed server compile. Out of scope (phase 8 plan, D15).

### F2b: refresh the two findings the drift had hidden (2026-10-24)

**Fix.** `npm update moment http-cache-semantics --package-lock-only --ignore-scripts --no-audit
--no-fund` in the same pinned `node:24.22.1-trixie` image as F1. Three lockfile changes, all in
range: moment 2.30.1 → 2.31.0, `sqlite3/node_modules/http-cache-semantics` 4.2.0 → 4.3.0, and the
dev-only `make-fetch-happen/node_modules/http-cache-semantics` 4.2.0 → 4.3.0. The waived 3.8.1
copy under `got` 8 didn't move (its parent's range doesn't allow 4.x).

**Proof.** Rebuilt image, Trivy 0.75.0 image scan (`reports/phase8-f2b/`): moment CVE-2026-17495
and http-cache-semantics CVE-2026-93748 gone; image still identical to the lockfile (689/689).
The comparison script also caught a first attempt where the image hadn't been rebuilt: the
lockfile said 2.31.0 / 4.3.0 and the image still had 2.30.1 / 4.2.0. A scan only proves something
about the image it scanned.

**Database drift, again.** The rescan downloaded a newer Trivy DB, which added two gating rows
that F2b didn't cause: body-parser 1.20.6 CVE-2026-111181 and zod 4.4.3 CVE-2023-54404 (both High,
DoS, fix in range). They're handled in the next commit.

### F2c: body-parser and zod, new in the Trivy DB (2026-10-24)

**Finding.** The F2b rescan's newer DB added two High rows on unchanged code, both gating under
rule 3: body-parser 1.20.6 CVE-2026-111181 (DoS via an unhandled decompression stream error, fix
1.20.9; reachable through express) and zod 4.4.3 CVE-2023-54404 (DoS via unbounded array
validation, fix 4.6.6; used by `lib/config.schema.ts` and `routes/chat.ts`).

**Fix.** `npm update body-parser zod --package-lock-only` (same pinned image as F1). In range:
body-parser 1.20.6 → 1.20.9 (root `^1.20.4`, express `~1.20.5`), zod 4.4.3 → 4.6.7 (root `^4.4.3`,
the `ai` SDK packages `^3.25.76 || ^4.1.8`). body-parser 1.20.9 requires `qs ~6.16.0`, so npm added
a nested `body-parser/node_modules/qs` 6.16.1; express keeps its own qs.

**Proof.** Rebuilt image, Trivy 0.75.0 (`reports/phase8-f2c/`): both rows gone, nothing new
(142 → 140). Image identical to the lockfile (690/690, +1 for the nested qs). Smoke test: HTTP 200 on
127.0.0.1:3001, no errors in the logs (zod validates the config at startup). Triage dry run back
to 3 blocking (search.ts:23, CKV_DOCKER_7, ZAP 10038).

**Lesson.** Three times in one day the DB moved under unchanged code (the router CVEs after F1,
these two after F2b). A scan result is a snapshot of code *and* advisory data. Phase 9's
Dependabot and a scheduled scan address the second half.

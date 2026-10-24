# Vendored: OWASP Juice Shop

| | |
|---|---|
| Upstream | https://github.com/juice-shop/juice-shop |
| Tag | `v20.2.0` (released 2026-08-10) |
| Source | https://github.com/juice-shop/juice-shop/archive/refs/tags/v20.2.0.tar.gz |
| sha256 | `880c8d11575f4e4549f263be81987821af7832cd49e3f55b3093d75707a29072` |
| Vendored | 2026-10-02 |

Extracted with `tar -xzf <tarball> -C app --strip-components=1`. The commit that adds this file
contains the release unmodified. Juice Shop is deliberately vulnerable: its findings, including
the fake secrets in its source, are the material this project studies. Don't "clean" them here.

## Local changes

Every change to `app/` after the vendor commit is listed here with its reason.

### Removed: upstream CI and AI-assistant config

- `.github/` (10 upstream workflows, issue/PR templates, `copilot-instructions.md`, `FUNDING.yml`).
  GitHub never runs workflows from a subdirectory, but Checkov's `github_actions` scan and
  Dependabot would treat them as ours and report noise. Our pipeline lives in the root `.github/`.
- `.claude/`, `AGENTS.md`, `.ai/skills/`, `.cursor/`, `.continue/`, `.codeium/`, `.junie/`.
  Instructions for AI assistants working on Juice Shop itself. Claude Code auto-loads a nested
  `.claude/CLAUDE.md` when working in `app/`, which would mix upstream's instructions into this
  project's. This project treats Juice Shop as scanned data, not as a source of instructions.

The Dockerfile copies the whole build context (`COPY . /juice-shop`) and upstream's `.dockerignore`
doesn't exclude these paths, so before this removal they were also copied into the image.

### Added: lockfiles pinned to the release date

- Added `package-lock.json` and `frontend/package-lock.json`.
- Changed `.npmrc` and `frontend/.npmrc` from `package-lock=false` to `package-lock=true`.
- Removed `package-lock.json` from `.gitignore` and `frontend/.gitignore`.

Upstream ships no lockfiles, so every build installs the newest versions matching the `^` ranges in
`package.json`. On 2026-10-02 that broke the build: `@angular/build` 22.2.0 (released 2026-09-23)
no longer writes `frontend/dist/frontend/stats.json`, and the frontend's `sbom` step
(`cyclonedx-esbuild … stats.json`) fails with "Missing metafile". The same frontend built with
22.1.9 writes the file.

The lockfiles were generated so that versions resolve to what was published on npm when v20.2.0 was
released:

```bash
docker run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp -v "$PWD/app:/app" node:24 bash -c '
  for d in /app /app/frontend; do cd $d
    npm install --package-lock-only --ignore-scripts --before=2026-08-11 --no-audit --no-fund
  done'
```

`--ignore-scripts` matters: without it npm runs upstream's `postinstall`, which installs `frontend/`
without the `--before` date. Result: `frontend/` resolves `@angular/build` 22.1.3, `@angular/core` 22.1.1.

Both `.npmrc` files need the change: `.dockerignore` excludes only the root `.npmrc`, so
`frontend/.npmrc` is copied into the build and would otherwise make the frontend install ignore its
lockfile.

Side effects: the npm packages in the image are reproducible (`npm ci`, phase 8 F2, below), and
Trivy's `fs` scan can read exact dependency versions. Base images are pinned by digest since phase 8 F3.
**Caveat (phase 3), fixed in phase 8 F2:** until then, 11 production package versions in the image
differed from the lockfile, likely changed by the Dockerfile's `npm dedupe`; see
`docs/findings/trivy.md`. Checked 2026-10-24: the image's npm packages now match the lockfile.
(That count is against the phase 3 lockfile. The lockfile was refreshed in phase 8 F1, below.)
Dependencies stay at their 2026-08 versions until deliberately updated (a phase 8 candidate).

### Changed: lockfile refresh (phase 8, F1)

- Changed `app/package-lock.json` (root lockfile only). `package.json`, `frontend/` and
  `frontend/package-lock.json` are unchanged.
- Run in the pinned `node:24.22.1-trixie` container with `--ignore-scripts`:

  ```bash
  npm update brace-expansion js-yaml compression proxy-addr hbs --package-lock-only --ignore-scripts --no-audit --no-fund
  ```

- Ten in-range version changes, including direct and transitive dependencies. `hbs` 4.2.1 → 4.4.0
  pins `handlebars` 4.7.10. The table and the scanner proof are in `docs/findings/trivy.md` ("Fixed in
  phase 8", F1).
- Why: the committed lockfile was stale. The image had drifted off it, and `npm ci` (F2) without
  this refresh would have shipped the vulnerable versions. These packages are in the image and
  reachable (`compression`, `proxy-addr`, `handlebars`), so the refresh fixes them directly.

### Changed: npm ci instead of npm install + dedupe (phase 8, F2)

- `app/Dockerfile`, installer stage: `RUN npm install --omit=dev` and `RUN npm dedupe --omit=dev`
  replaced by `RUN npm ci --omit=dev`. `npm dedupe` re-resolves duplicated packages from the
  registry, which undoes the lockfile.
- `app/package.json`, `postinstall`: `cd frontend && npm install` changed to `cd frontend && npm ci`.
  Exact strings:

  ```
  before: "postinstall": "cd frontend && npm install && cd .. && npm run build:frontend && (npm run --silent build:server || cd .)"
  after:  "postinstall": "cd frontend && npm ci && cd .. && npm run build:frontend && (npm run --silent build:server || cd .)"
  ```

- Why: `npm ci` installs exactly what the lockfile says and fails on a `package.json` mismatch,
  instead of rewriting the lock. The frontend lockfile is enforced too, not just the root one.
- Proof and the drift it fixed: `docs/findings/trivy.md` ("Fixed in phase 8", F2).

### Changed: lockfile refresh of moment and http-cache-semantics (phase 8, F2b)

- `app/package-lock.json` only: moment 2.30.1 → 2.31.0 and two nested http-cache-semantics copies
  4.2.0 → 4.3.0, via `npm update moment http-cache-semantics --package-lock-only`, all in range.
- Why: once F2 made the image follow the lockfile, these two findings (hidden by the old dedupe
  drift) shipped again. See `docs/findings/trivy.md` (F2b).

### Changed: lockfile refresh of body-parser and zod (phase 8, F2c)

- `app/package-lock.json` only: body-parser 1.20.6 → 1.20.9 (adds nested qs 6.16.1) and zod
  4.4.3 → 4.6.7, via `npm update body-parser zod --package-lock-only`, all in range.
- Why: two High DoS CVEs added to the Trivy DB on 2026-10-24, both reachable. See
  `docs/findings/trivy.md` (F2c).

### Changed: base images pinned by tag and digest (phase 8, F3)

- `app/Dockerfile`: `FROM node:24 AS installer` →
  `FROM node:24.22.1-trixie@sha256:016f604a…1011d3 AS installer`, and
  `FROM gcr.io/distroless/nodejs24-debian13` →
  `FROM gcr.io/distroless/nodejs24-debian13:nonroot@sha256:cb606325…6fb9f8`.
- Why: reproducible builds and scans; clears Checkov CKV_DOCKER_7 (gating rule 5). The installer
  moves from Debian 12 to 13 to match the runtime. See `docs/findings/checkov.md` (F3).

### Changed: parameterised product search (phase 8, F4)

- `routes/search.ts:23`: the search query uses a Sequelize replacement (`LIKE :q`) instead of
  string interpolation. Clears Semgrep `express-sequelize-injection` (gating rule 4).
- **Breaks challenges:** "Union SQL Injection" (`unionSqlInjectionChallenge`) and "Database Schema"
  (`dbSchemaChallenge`) are no longer solvable; the UNION cases in `test/cypress/e2e/search.spec.ts`
  would fail. The `vuln-code-snippet` markers are unchanged, so the coding challenge shows the fixed
  line. See `docs/findings/semgrep.md` (F4).

### Changed: Content-Security-Policy (phase 8, F5)

- `server.ts`: `helmet.contentSecurityPolicy` with an explicit, enforcing policy. Inline scripts are
  allowed by hash (index.html cookie consent, `views/promotionVideo.pug`, serve-index on `/ftp`);
  recompute a hash if its script changes.
- `frontend/angular.json`: production `optimization` is an object with
  `styles.inlineCritical: false`, so the build no longer emits the `onload` stylesheet loader the
  CSP would block.
- `lib/startup/registerWebsocketEvents.ts`: security headers (strict CSP, nosniff, DENY) on
  socket.io's own HTTP responses, which bypass Express.
- Changes the XSS challenges' visible effect (the injected scripts are blocked) but they still
  register as solved; `/profile` keeps the CSP-bypass challenge's own policy. See
  `docs/findings/zap.md` (F5).

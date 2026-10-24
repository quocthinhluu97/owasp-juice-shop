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

Side effects: builds are reproducible, and Trivy's `fs` scan can read exact dependency versions.
**Caveat (phase 3):** not fully. 11 production package versions in the image differ from the
lockfile, likely changed by the Dockerfile's `npm dedupe`; see `docs/findings/trivy.md`.
(That count is against the phase 3 lockfile. The lockfile was refreshed in phase 8 F1, below;
the drift itself is fixed in phase 8 F2.)
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

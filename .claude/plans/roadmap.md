# Roadmap: Juice Shop DevSecOps pipeline

Every phase from setup to a locked-down pipeline, step by step. Rules referenced here live in `.claude/rules/`.
Steps marked **(you)** need you (Windows, GitHub web UI, judgement calls); the rest Claude can do and report back.

Status: ✅ done · ▶ in progress · ☐ not started

| # | Phase | Status |
|---|---|---|
| 0 | Setup: Docker, git repo, vendor Juice Shop | ✅ |
| 1 | App + Dockerfile + minimal workflow | ✅ |
| 2 | Gitleaks: secrets in git history | ✅ |
| 3 | Trivy: vulnerable packages in image and repo | ▶ |
| 4 | Semgrep: insecure code patterns | ☐ |
| 5 | Checkov: Dockerfile and workflow misconfiguration | ☐ |
| 6 | ZAP baseline: passive scan of the running app | ☐ |
| 7 | Triage script: one pass/fail decision | ☐ |
| 8 | Fix a few findings | ☐ |
| 9 | Lock down the pipeline | ☐ |

---

## How every scanner phase (2–6) runs

The same loop each time (`ground-rules.md`: one scanner per change):

1. **Research:** the `researcher` agent finds the current version, the image digest, and the flags for the output format we need.
2. **Run locally** into `reports/` (gitignored; never committed).
3. **Summarise before touching anything:** counts, top rules, top files, and which findings look real versus noise, and why.
4. **Write `docs/findings/<scanner>.md`:** what it found, what's noise and why, what's worth fixing in phase 8.
5. **Configure, don't suppress:** rule selection and path excludes in the scanner's config file, each with a written reason. Inline suppressions only as a last resort, also with a reason.
6. **Re-run** and confirm only the expected findings changed.
7. **Wire into CI** as its own job: the scan step never fails the job (`continue-on-error` / `--exit-code 0`) and uploads its report as an artifact. Triage (phase 7) is the only gate.
8. **Review and commit:** the `code-reviewer` agent reviews the change; one branch and PR per phase.

---

## Phase 0: Setup ✅

- ✅ systemd enabled in WSL (`/etc/wsl.conf`).
- ✅ Docker via Docker Desktop's WSL integration. Docker Desktop must be running on Windows **(you)**; turn on "Start when you sign in" to avoid "cannot connect to docker.sock".
- ✅ `git init -b main`; `.gitignore` keeps `reports/`, `node_modules/`, `.venv/` and the KEV cache out of git.
- ✅ Juice Shop **v20.2.0** vendored unmodified into `app/`, with its sha256 recorded in `app/VENDORED.md`.
- ✅ Upstream `.github/` and AI-assistant config removed from `app/` in a separate commit, with the reason in `VENDORED.md`.

Learned along the way (feeds later phases):
- The Dockerfile copies the whole `app/` into the image (`COPY . /juice-shop`): tests, docs and challenge files all ship. This matters for Trivy and image size.
- There's **no lockfile** (`.npmrc`: `package-lock=false`), so dependency versions float between builds. This matters for Trivy.
- Upstream's `postinstall` runs `build:server || cd .`, so a failed server compile does not fail `docker build`. This matters for phase 1's smoke test.

## Phase 1: App + minimal workflow ✅

Goal: the image builds in CI and nothing else happens.

1. ✅ Docker works (Docker Desktop must be running on Windows).
2. ✅ `docker build -t juice-shop:local ./app`: **102 s, 513 MB on disk / 115 MB compressed**. First attempt failed because the floating `@angular/build` 22.2 no longer writes `stats.json`; fixed by committing lockfiles dated to the release (see `app/VENDORED.md`). The server compile prints 158 `tsc` type errors, which upstream's `|| cd .` hides; the JS is still emitted and the server works.
3. ✅ Smoke test on **port 3001** (Grafana from another project holds 3000): HTTP 200 after ~12 s, version 20.2.0. Original plan: `docker run -d --rm -p 127.0.0.1:3000:3000 --name juice juice-shop:local`, poll until `curl` gets HTTP 200, then check `docker logs`. Bind to `127.0.0.1` only. A 200 matters because the build can "succeed" with a broken server.
4. ☐ Open `http://localhost:3000` in the Windows browser and click around **(you)**. Then `docker stop juice`.
5. ✅ Write `.github/workflows/security.yml` (checkout@v7, plus `timeout-minutes: 30` brought forward from phase 9): triggers `push` to `main` and `pull_request`; `permissions: {}`, with job `build` given `contents: read`; on `ubuntu-24.04`, checkout then `docker build`. Actions stay on version tags for now; hardening is deliberately left for phase 9 so Checkov has something to find in phase 5.
6. ✅ `code-reviewer` reviewed it (no defects); `layout.md` updated; committed.
7. ✅ Repo `quocthinhluu97/owasp-juice-shop`, pushed over HTTPS. Created public by mistake, switched to **private** on 2026-10-02: from phase 2 on, report artifacts would be downloadable by anyone. Trade-off: push protection and code scanning need GitHub Advanced Security on private repos, so they're unavailable; triage stays the only gate. Original step: create an empty **private** GitHub repo (no README or licence); tell Claude the URL and whether you push over HTTPS or SSH **(you)**.
8. ✅ Pushed `main` (`7ec515a`). Original step: push. If push protection blocks the push because of Juice Shop's deliberate fake secrets, check each flagged item and allow it as "used in tests / false positive". Don't rewrite history **(you)**.
9. ✅ Green `security` run on `main` (~1m40s), checked in the Actions tab. Original step: the Actions tab shows a green `security.yml` run whose log contains only checkout and docker build **(you)**.

**Done when:** local `curl` returns 200, the CI build is green, and `main` is pushed.

## Phase 2: Gitleaks ✅

Goal: find secrets anywhere in git history, not just the current files.

1. ✅ Research: current Gitleaks version and digest; the `gitleaks git` command and its SARIF flags.
2. ✅ Run locally against the full history → `reports/gitleaks.sarif`.
3. ✅ Summarise by rule and file. Expect many hits from Juice Shop's deliberate fakes (`ctf.key`, `encryptionkeys/`, `data/static/`, `ftp/`, test files). Sort each into deliberate fake, test data, or looks real.
4. ✅  Write `docs/findings/gitleaks.md`.
5. ✅ Write `.gitleaks.toml`: extend the default rules; allowlist **by path only**, one reason per path. No disabled rules. Exception: one value-based allowlist for Ethereum addresses (public identifiers, spread over ~20 files); reason in `docs/findings/gitleaks.md`.
6. ✅ Re-run and confirm only the allowlisted paths dropped out.
7. ✅ CI job `gitleaks`: checkout with `fetch-depth: 0`; scan scoped to `HEAD`'s full history (not other branches); `--exit-code 0`, but a git error or 0 commits scanned fails the job (otherwise an empty report passes as clean); report is **JSON with secrets replaced by sha256** (not SARIF, not `--redact`, so triage can fingerprint per `triage-script.md`), uploaded as artifact `gitleaks-report` (7 days). Verified locally: 8 findings, same as before. Review findings left for later: PRs can edit `.gitleaks.toml` themselves (CODEOWNERS, phase 9); `key-files` findings have line 0, so the triage parser should treat that as "whole file" (phase 7).
8. ✅ Review, PR, merge.

**Decision point:** decide how to handle a hit that looks real. Rotating it is always the answer, even in a learning repo.

## Phase 3: Trivy ▶

Goal: find known-vulnerable packages (CVEs) in the built image and in the repo's dependency files.

1. ✅ (researcher agent) Trivy **0.75.0**, digest `sha256:af6acf9a…855daa` (verified with `imagetools inspect`). Note the March 2026 Trivy supply-chain incident (GHSA-69fq-xp46-6x23): pin by digest, don't use `trivy-action`. Original step: research current Trivy version and digest; JSON fields `FixedVersion`, `PkgPath`, dev versus prod dependency flags.
2. ✅ **Decided in phase 1: lockfiles committed** (forced by a build break). Original note: `trivy fs` needs a lockfile to see npm versions, and Juice Shop has none. Options: (a) generate `package-lock.json` (and `frontend/`'s) in a Node container and commit it, recorded in `VENDORED.md` as a local change; (b) rely on `trivy image` only. Option (a) also makes builds reproducible.
3. ✅ `trivy image --scanners vuln` on `juice-shop:local` → `reports/trivy-image.json`. Secret and misconfig scanning stay off, because Gitleaks and Checkov cover those.
4. ✅ `trivy fs --scanners vuln app/` → `reports/trivy-fs.json`.
5. ✅ Summarise by severity, fix available or not, OS package (distroless Debian) versus npm package, prod versus dev, and the overlap between the image and fs results.
6. ✅ Write `docs/findings/trivy.md`. Found: the image doesn't fully follow the committed lockfile (11 prod packages differ, likely `npm dedupe`), a phase 8 candidate. Flag candidate dependency bumps for phase 8.
7. ✅ No `.trivyignore`: deliberate findings go to `triage/waivers.yaml` in phase 7 instead. Original step: `.trivyignore` only for specific CVEs with a reason (e.g. a vulnerable function that isn't reachable); no blanket severity cut-offs.
8. ✅ CI job `trivy`: `build` saves the image as an artifact (1 day); `trivy` scans it with `--input` (no Docker socket), then the lockfiles; DB cached daily; a coverage check fails the job if no OS was detected or a lockfile wasn't scanned. Original step: needs the image, so either build it in the same job or pass it via `docker save` as an artifact. JSON uploaded as an artifact.
9. ☐ Review, PR, merge.

## Phase 4: Semgrep ☐

Goal: find insecure patterns in first-party code.

1. ☐ Research: current Semgrep version and digest; registry rulesets `p/default`, `p/javascript`, `p/typescript` (no login needed).
2. ☐ Run locally → `reports/semgrep.sarif`.
3. ☐ Summarise by rule, severity and folder. Expect noise from `data/static/codefixes/` (161 deliberately vulnerable snippets that never run), `test/` and `frontend/` assets. Real hits will cluster in `routes/` and `lib/`, much of it deliberate.
4. ☐ Write `docs/findings/semgrep.md`. Pick one real `ERROR` finding as the phase 8 code fix.
5. ☐ `.semgrepignore` with a reason per path (`codefixes/`, `test/`, built frontend output). Leave `routes/` and `lib/` fully scanned.
6. ☐ Re-run and compare counts.
7. ☐ CI job `semgrep`, SARIF artifact.
8. ☐ Review, PR, merge.

## Phase 5: Checkov ☐

Goal: find misconfiguration in the Dockerfile and the GitHub workflows.

1. ☐ Research: current Checkov version and digest; check IDs for root user / no `USER`, unpinned actions, script injection, base image not pinned by digest.
2. ☐ Run with `--framework dockerfile github_actions` → SARIF in `reports/`.
3. ☐ Summarise. Check which deferred items in `security.yml` Checkov actually flags; the code-reviewer believes tag-pinned actions and `persist-credentials` are not covered and need zizmor (unverified). Expect hits on **our own** phase 1 workflow (unpinned actions, etc.) and on the Dockerfile (base image by tag, maybe no `HEALTHCHECK`). `app/terraform/` is out of scope for these frameworks.
4. ☐ Write `docs/findings/checkov.md`.
5. ☐ Draft the **short list of high-impact check IDs** for gating rule 5, with a reason for each. This becomes code in phase 7.
6. ☐ `.checkov.yaml`: frameworks, paths, and skips with reasons.
7. ☐ CI job `checkov`, SARIF artifact.
8. ☐ Review, PR, merge.

## Phase 6: ZAP baseline ☐

Goal: passively scan the running app over HTTP (no attacks).

1. ☐ Research: current ZAP image and digest; `zap-baseline.py` flags (`-J`, `-c`/`-g` for the rules file).
2. ☐ Run against the local container → `reports/zap.json`, using `--add-host=host.docker.internal:host-gateway`.
3. ☐ Generate the default rules file (`-g`), then set every rule to IGNORE, WARN or FAIL in `.zap/rules.tsv`, **each with a reason**. Juice Shop is a single-page app, so the passive spider sees little; note this as a limitation.
4. ☐ Summarise: missing security headers (CSP, etc.), cookie flags, information leaks. Pick one header as the phase 8 fix.
5. ☐ Write `docs/findings/zap.md`.
6. ☐ CI job `zap`: start the built image as a container, wait until it's ready, run the scan, upload the JSON. The app is only reachable inside the runner.
7. ☐ Review, PR, merge.

## Phase 7: Triage script ☐

Goal: one Python script decides pass or fail, using `gating-policy.md` and `triage-script.md`.

1. ☐ Python 3.12 `.venv`; `pytest` and `pyyaml` in `triage/requirements.txt`.
2. ☐ The `Finding` dataclass with the fields from `triage-script.md`.
3. ☐ Parsers, one per scanner, each tested against a **real trimmed report** from phases 2–6, stored in `triage/tests/fixtures/`. Raw secrets are removed from fixtures; fake ones are allowlisted in `.gitleaks.toml`.
4. ☐ Explicit severity mapping per tool; unknown levels are errors, not guesses.
5. ☐ Fingerprints and dedupe, with tests across tools (the same CVE from `trivy image` and `trivy fs` counts once).
6. ☐ Waivers: `triage/waivers.yaml` with `reason`, `owner`, `expires`. Expired waivers stop applying; a warning when one expires within 14 days.
7. ☐ KEV enrichment: download CISA's catalogue of actively exploited CVEs, cache it with a timestamp, refresh at most daily. Tests use a fixture copy and never touch the network. EPSS (exploit likelihood score) is optional.
8. ☐ Reachability hints: prod versus dev dependency, build stage only versus final image, and a grep for imports labelled "grep-level evidence".
9. ☐ Gating rules 1–6 in `policy.py`, each tested with a passing and a failing case. Each blocking finding names its rule number.
10. ☐ Output: stdout summary plus `$GITHUB_STEP_SUMMARY`; `reports/triage.json`. Exit code 0 pass / 1 gate failed / 2 script error; never 0 on a parse error.
11. ☐ CI job `triage`: `needs:` every scan job, downloads their artifacts, the only job that can fail the build.
12. ☐ `code-reviewer` reviews; PR; merge.
13. ☐ Make `triage` a required status check on `main` in GitHub branch protection **(you)**.

**Expected:** the build goes red on the first run. That's the point. Read why, then go to phase 8 or add waivers with real reasons.

## Phase 8: Fix a few findings ☐

Goal: about 4 fixes that each teach something different. Each gets its own commit, a note in `docs/findings/` (finding, why it mattered, fix, proof the scanner no longer reports it), and an entry under "Local changes" in `app/VENDORED.md`.

Candidates (final picks once the phases above have real data):
1. ☐ **Dependency bump** (Trivy): a High/Critical CVE with a fix available in a production dependency.
2. ☐ **Dockerfile hardening** (Checkov/Trivy): pin the base images by digest; tighten `.dockerignore` so tests and docs stay out of the image; maybe add a `HEALTHCHECK`.
3. ☐ **Code fix** (Semgrep): one real `ERROR` in `routes/` or `lib/`, which may break the matching Juice Shop challenge (note it).
4. ☐ **Security header** (ZAP): e.g. a Content-Security-Policy or a missing header, set in the Express setup.
5. ☐ Optional: make a failed server compile fail the build (the `|| cd .` in `postinstall`).

For each: re-run the scanner and show the finding is gone; triage should report it resolved.

## Phase 9: Lock down the pipeline ☐

Goal: the pipeline itself is hard to abuse (`ci-workflows.md`).

1. ☐ Pin every action to a 40-character commit SHA with the version in a comment; pin scanner images by digest.
2. ☐ `.github/dependabot.yml` for the `github-actions` and `docker` ecosystems.
3. ☐ Per-job least-privilege `permissions`; `security-events: write` only where SARIF is uploaded.
4. ☐ `persist-credentials: false` on checkout; `timeout-minutes` per job; a `concurrency` group.
5. ☐ Audit: no `pull_request_target`; no `${{ github.event.* }}` inside `run:` (pass it via `env:` instead).
6. ☐ Optional: upload a combined SARIF to GitHub code scanning.
7. ☐ Checkov `github_actions` passes on our workflows; optionally `zizmor` and `actionlint` too.
8. ☐ Optional deploy with OIDC: **publish the image only** (e.g. to a private registry, assuming a cloud role scoped to this repo and branch). **Never run Juice Shop anywhere reachable from the internet** (`ground-rules.md`).
9. ☐ Write `docs/findings/pipeline-hardening.md`: before and after Checkov/zizmor results.

---

## Open decisions

| When | Decision |
|---|---|
| Phase 2 | What to do if a hit looks like a real secret (rotate it, even here). |
| Phase 5 | The exact list of high-impact Checkov check IDs for gating rule 5. |
| Phase 6 | Which ZAP rules are FAIL. |
| Phase 8 | Which ~4 findings to fix. |
| Phase 9 | Whether to do the OIDC publish step at all. |

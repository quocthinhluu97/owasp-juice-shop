# Roadmap: Juice Shop DevSecOps pipeline

Every phase from setup to a locked-down pipeline, step by step. Rules referenced here live in `.claude/rules/`.
Steps marked **(you)** need you (Windows, GitHub web UI, judgement calls); the rest Claude can do and report back.

Status: ✅ done · ▶ in progress · ☐ not started

| # | Phase | Status |
|---|---|---|
| 0 | Setup: Docker, git repo, vendor Juice Shop | ✅ |
| 1 | App + Dockerfile + minimal workflow | ✅ |
| 2 | Gitleaks: secrets in git history | ✅ |
| 3 | Trivy: vulnerable packages in image and repo | ✅ |
| 4 | Semgrep: insecure code patterns | ✅ |
| 5 | Checkov: Dockerfile and workflow misconfiguration | ✅ |
| 6 | ZAP baseline: passive scan of the running app | ▶ |
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

## Phase 3: Trivy ✅

Goal: find known-vulnerable packages (CVEs) in the built image and in the repo's dependency files.

1. ✅ (researcher agent) Trivy **0.75.0**, digest `sha256:af6acf9a…855daa` (verified with `imagetools inspect`). Note the March 2026 Trivy supply-chain incident (GHSA-69fq-xp46-6x23): pin by digest, don't use `trivy-action`. Original step: research current Trivy version and digest; JSON fields `FixedVersion`, `PkgPath`, dev versus prod dependency flags.
2. ✅ **Decided in phase 1: lockfiles committed** (forced by a build break). Original note: `trivy fs` needs a lockfile to see npm versions, and Juice Shop has none. Options: (a) generate `package-lock.json` (and `frontend/`'s) in a Node container and commit it, recorded in `VENDORED.md` as a local change; (b) rely on `trivy image` only. Option (a) also makes builds reproducible.
3. ✅ `trivy image --scanners vuln` on `juice-shop:local` → `reports/trivy-image.json`. Secret and misconfig scanning stay off, because Gitleaks and Checkov cover those.
4. ✅ `trivy fs --scanners vuln app/` → `reports/trivy-fs.json`.
5. ✅ Summarise by severity, fix available or not, OS package (distroless Debian) versus npm package, prod versus dev, and the overlap between the image and fs results.
6. ✅ Write `docs/findings/trivy.md`. Found: the image doesn't fully follow the committed lockfile (11 prod packages differ, likely `npm dedupe`), a phase 8 candidate. Flag candidate dependency bumps for phase 8.
7. ✅ No `.trivyignore`: deliberate findings go to `triage/waivers.yaml` in phase 7 instead. Original step: `.trivyignore` only for specific CVEs with a reason (e.g. a vulnerable function that isn't reachable); no blanket severity cut-offs.
8. ✅ CI job `trivy`: `build` saves the image as an artifact (1 day); `trivy` scans it with `--input` (no Docker socket), then the lockfiles; DB cached daily; a coverage check fails the job if no OS was detected or a lockfile wasn't scanned. Original step: needs the image, so either build it in the same job or pass it via `docker save` as an artifact. JSON uploaded as an artifact.
9. ✅ Review, PR, merge (PR #2). CI matched the local run except 1 fewer npm row in the image scan (lockfile scan unchanged), likely build-to-build drift.

## Phase 4: Semgrep ✅

Goal: find insecure patterns in first-party code.

1. ✅ (researcher agent) Semgrep **1.179.0**, digest `sha256:93963d92…e01b` (verified). Without login, `extra.fingerprint` is "requires login"; registry rules change between runs. Original step: research current Semgrep version and digest; registry rulesets `p/default`, `p/javascript`, `p/typescript` (no login needed).
2. ✅ Run locally → `reports/semgrep.json` + `.sarif` (one run). 55 findings, 971 files; exit 0 with findings.
3. ✅ Summarise by rule, severity and folder. All 5 first-party `ERROR`s are real and deliberate; 4 known challenges (NoSQLi, XXE, SSRF, B2B RCE) missed. Original step: summarise by rule, severity and folder. Expect noise from `data/static/codefixes/` (161 deliberately vulnerable snippets that never run), `test/` and `frontend/` assets. Real hits will cluster in `routes/` and `lib/`, much of it deliberate.
4. ✅ Write `docs/findings/semgrep.md`. Pick one real `ERROR` finding as the phase 8 code fix.
5. ✅ `.semgrepignore`: a custom file **replaces** Semgrep's defaults (verified), so they're restated. Secret rules stay on; triage merges `generic.secrets.*` with Gitleaks, never gates. Terraform and `.npmrc` non-gating: named exclusions added to gating rule 4 (exclusion form kept, not an allow-list). Original step: `.semgrepignore` with a reason per path (`codefixes/`, `test/`, built frontend output). Leave `routes/` and `lib/` fully scanned.
6. ✅ Re-run: 55 → 37 findings, exactly the 15 `codefixes/` + 3 `*.spec.ts` ones; errors 41 → 8.
7. ✅ CI job `semgrep`: JSON (for triage) + SARIF artifact; coverage check fails if any tracked first-party server file (`routes/`, `lib/`, `models/`, `data/*.ts`, `views/`, `server.ts`, `app.ts`; 121 files) wasn't scanned or any error other than Angular-template partial parsing appears.
8. ✅ Review, PR, merge (PR #3). CI matched the local run exactly (688 files, 8 errors, 37 findings).

## Phase 5: Checkov ✅

Plan: [phase-5-checkov.md](phase-5-checkov.md) — approved 2026-10-07; merged in PR #4 (f66bb8d)

Goal: find misconfiguration in the Dockerfile and the GitHub workflows.

1. ✅ (researcher) Checkov **3.3.22**, `sha256:617c76e3f9b1f7907ebca9abb6b9d746844edcb48e9bd775e4692c69c1c6ac47`. Gaps: no digest-pinning check (base pin in phase 8), no action-pinning check (zizmor phase 9).
2. ✅ Local: dockerfile 324/3, github_actions 108/0. Final local re-run with CI's exact flags (after the `checkov` job was added): dockerfile 324/3, github_actions 132/0 (more workflow resources). JSON + SARIF to `reports/checkov/`.
3. ✅ Verdict: CKV_DOCKER_7 (untagged distroless base at line 22) blocks gating; CKV_DOCKER_2 (no HEALTHCHECK) report-only. GitHub Actions: all checks pass. See `docs/findings/checkov.md`.
4. ✅ `docs/findings/checkov.md`: scan summary, 3 Dockerfile failure verdicts, GitHub Actions results, Checkov limitations, severity=null, output-write lesson, framework-wide scope limits, phase 7 notes.
5. ✅ Rule 5 check list decided: **gate** CKV_DOCKER_3, CKV_DOCKER_8, CKV_DOCKER_1, CKV_DOCKER_7, CKV_GHA_2, CKV2_GHA_1, CKV_GHA_1; **report-only** CKV_DOCKER_2 (scoped to `/app/Dockerfile` and `/.github/workflows/`). Recorded in `gating-policy.md` rule 5.
6. ✅ `.checkov.yaml`: framework [dockerfile, github_actions], skip-path app/test/, soft-fail true, skip-download true. Local re-run: 3 failures (skip-path dropped test/smoke, down from 6).
7. ✅ CI job `checkov`: pinned image by digest, `--network none`, `--config-file`, JSON + SARIF to `reports/checkov/`. Coverage check: file existence, parsing_errors==0, both frameworks present, no log errors. Never fails on findings.
8. ✅ Reviewed (3 fix rounds); merged PR #4 (f66bb8d). Final verification matched expected counts (dockerfile 324/3, github_actions 132/0).

## Phase 6: ZAP baseline ▶

Plan: [phase-6-zap.md](phase-6-zap.md) — approved 2026-10-12; amendment D12 + step 3c approved 2026-10-12

Goal: passively scan the running app over HTTP (no attacks).

1. ✅ (researcher) ZAP **2.17.0** (stable, rebuilt monthly; digest verified). Confirmed: `-j` = Client Spider. `-T` not needed (CI `timeout-minutes: 20`; runs take ~2:40).
2. ✅ Run traditional spider against local container → `reports/zap.json`, on network `scan` (target `http://juice:3000`). Exit 2, 36 s, 88 URLs, 65 endpoints scanned. Findings: 10038 CSP, 10098 ACAO, 10110 DOM-XSS, 90004 hardening, 10063 Deprecated Feature-Policy (not Permissions-Policy), 10096 timestamps, Info alerts. Stack trace leaked on 403 /ftp/encrypt.pyc. D3 amendment: network must be `--internal` to block scope creep (Client Spider followed open redirect to GitHub in the -j run).
3. ✅ Client Spider run: 2:48 total (+2:12), 134 endpoints, 16 alert types. New: 10028 open redirect (High), private IPs, session ID noise, socket.io noise. **Decision D4 resolved:** use `-j` (2× coverage, only 1 High alert, +2:12 < 5 min budget). Coverage signal for D7: set after --internal verification (step 3b).
4. ✅ Verify --internal network (step 3b): `docker network create --internal scan`, one `-j` run. Exit 2, 2:48, only juice:3000 in sites, 135 endpoints, but 7 alerts from 4 rules vanished (missing pscanrulesBeta add-on). **Decision D12 proposed (step 3c):** pin add-on v50 by hash, verify all 67 rules load, mount read-only in CI, run with `-z "-silent"`.
5. ✅ Verify pinned add-on (step 3c, 2026-10-13): pscanrulesBeta v50 hash-checked and mounted read-only with `-z "-silent"`; 67 rules loaded (PASS 54 + WARN 13); 10110/10063/90004/10049 back; exit 2, 2:36.
6. ✅ Generate rules file from `gen.conf`, set every rule to IGNORE/WARN/FAIL with reason in `.zap/rules.tsv`. Drafted 2026-10-13: 68 rules (FAIL 3: 10038, 10028, 10115, confirmed by user 2026-10-13; IGNORE 10; WARN 55), reviewed in step 9 (clean 2026-10-13).
7. ✅ Re-run with rules file (2026-10-13): exit 1, 2:34. Console FAIL 2 (10028, 10038), WARN 7, IGNORE 4 (10049, 10096, 10109, 3), PASS 54 = 67; only juice:3000 in `site[]`, 174 endpoints, same 17 alertRefs as the pinned run. Exit 1 is expected (FAIL rules fired), but a missing rules file also exits 1, so the CI coverage check must run (see plan D7 correction).
8. ✅ Write `docs/findings/zap.md`: summary, per-alert verdicts, JSON caps and fingerprint notes (D10), chosen phase 8 header.
9. ▶ CI job `zap` written (2026-10-13): network `--internal`, pinned add-on, spider `-j`, rules file, coverage check on Juice site endpoint count and rule load (≥67). The app is only reachable inside the runner. CI check pending the first PR run (plan step 7).
10. ✅ Docs written (2026-10-13): `local-scanning.md` (add-on, --internal), `phases.md` phase 6 (rules.tsv read by triage), `layout.md`.
11. ✅ Review: round 1 (2026-10-13) found no bugs; fixes applied; round 2 clean (2026-10-13) (plan step 9). Then PR and merge.

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
| Phase 5 | The exact list of high-impact Checkov check IDs for gating rule 5. — **decided:** see `gating-policy.md` rule 5 |
| Phase 6 | Which ZAP rules are FAIL. |
| Phase 8 | Which ~4 findings to fix. |
| Phase 9 | Whether to do the OIDC publish step at all. |

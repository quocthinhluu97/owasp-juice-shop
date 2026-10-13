# Phase 5: Checkov (plan)

Status: ✅ **done — approved 2026-10-07; merged in PR #4 (f66bb8d)** · Branch: `phase-5-checkov` · Pipeline: `.claude/rules/feature-pipeline.md`

## Context

Checkov scans the Dockerfiles and the GitHub workflow for misconfiguration. Gating rule 5 blocks the build only on "a short, named list of high-impact checks, with a reason for each". This phase:
- decides that list;
- configures the scan;
- writes the findings up;
- adds a CI job that never fails on findings (triage, in phase 7, is the only gate).

## Done so far

- **Step 1, research (researcher agent).**
  - Checkov **3.3.22**, `bridgecrew/checkov:3.3.22@sha256:617c76e3f9b1f7907ebca9abb6b9d746844edcb48e9bd775e4692c69c1c6ac47` (digest verified with imagetools). No advisories.
  - **Checkov has no check for:** SHA-pinned actions, `persist-credentials`, `pull_request_target`, missing job permissions, general `${{ github.event.* }}` injection (CKV_GHA_2 is a fixed list of 17 patterns), or base image pinned by digest.
  - `USER` and `HEALTHCHECK` checks are file-wide, not per stage.
  - Without an account, `severity` is null.
- **Step 2, local run (user).** `--framework dockerfile github_actions --skip-download --soft-fail --network none`, outputs in `reports/checkov/`.
  - It needs no network.
  - The JSON is a list, one report per framework.
  - Files scanned: `app/Dockerfile`, `app/infrastructure/Dockerfile`, `app/test/smoke/Dockerfile`, `.github/workflows/security.yml`. 0 parsing errors.
  - **Dockerfile:** 344 passed, 6 failed.
    - CKV_DOCKER_2 (no HEALTHCHECK) ×3, one per file.
    - CKV_DOCKER_7 (base image has no tag): `app/Dockerfile` line 22 (distroless `FROM`) and `test/smoke`.
    - CKV_DOCKER_3 (no `USER`): `test/smoke`.
  - **GitHub Actions:** 108 passed, 0 failed, though none of phase 9's hardening is done. `resource_count` is 0 for `github_actions` even with 108 checks run, so it can't be a coverage signal.
  - `severity` is null on every check, so SARIF marks every failure `error`.
- **Lessons learned in step 2:**
  - When Checkov can't write its output, it still exits 0 and writes no files; the only sign is an `[ERROR]` line in stderr.
  - Docker creates a missing bind-mount folder as root.
  - In both cases the CI job needs `if-no-files-found: error` and a coverage check.

## Decisions

| # | Decision | Reason | Status |
|---|---|---|---|
| D1 | `app/test/` is excluded via `skip-path` in `.checkov.yaml` (not scanned) | `test/smoke/Dockerfile` is upstream's smoke-test container (Alpine + curl, used only by upstream's `docker-compose.test.yml`); this pipeline never builds or runs it. Same rule as Semgrep (`.semgrepignore`) and gating rule 4: tests aren't scanned for gating. | **decided by user (option A)** |
| D2 | `app/infrastructure/Dockerfile` stays scanned, never gates | Challenge material (the "misplaced IaC files" challenge), like `app/terraform/`; nothing builds it. Keeping it visible matches the Terraform decision in phase 4. | **decided by user: keep scanned, never gates** |
| D3 | Rule 5 list: which check IDs block, scoped to `app/Dockerfile` and `.github/workflows/` | See the candidates below. | **decided by user: accepted Claude's recommendation** (gate CKV_DOCKER_3, CKV_DOCKER_8, CKV_DOCKER_1, CKV_DOCKER_7, CKV_GHA_2, CKV2_GHA_1, and CKV_GHA_1 once its ID is confirmed in step 2; CKV_DOCKER_2 report-only) |
| D4 | Gating rule 5's own example "unpinned actions" can't come from Checkov | No such check exists (researcher, issue #7057). Options: (a) change rule 5's text to drop it and cover SHA pinning in phase 9 with zizmor; (b) add zizmor now as a second tool. Option (b) breaks "one scanner per change" (`ground-rules.md`). Our workflow's actions are tag-pinned today (`actions/checkout@v7` etc.), so gating SHA pinning now would block every build before phase 9 does the pinning; adding zizmor now breaks one-scanner-per-change. Rule 5's text should not drop the concern silently: reword to "unpinned actions: not detectable by Checkov; enforced from phase 9 by zizmor (`unpinned-uses`), added to the gate then". | **decided by user: (a), reworded** |
| D5 | Triage keys Checkov findings on `check_id`; fingerprint = `check_id + file_path + file_line_range[0]` | No severity and no fingerprint without an account. | proposed |

**Rule 5 candidates (D3).** "Fails today" means on the shipped image or our workflow.

| Check | Meaning | Fails today? | Recommended |
|---|---|---|---|
| CKV_DOCKER_3 | no `USER` in the Dockerfile | no | **gate** |
| CKV_DOCKER_8 | last `USER` is root (string "root" only; `USER 0` isn't caught) | no | **gate** |
| CKV_DOCKER_1 | port 22 exposed | no | **gate** |
| CKV_DOCKER_2 | no HEALTHCHECK | **yes** | **report only** |
| CKV_DOCKER_7 | base image without a tag, or `latest` | **yes** (distroless `FROM`, line 22) | **gate** |
| CKV_GHA_2 | shell injection in `run:` (17 known patterns) | no | **gate** |
| CKV2_GHA_1 | top-level `permissions: write-all` | no | **gate** |

A check that fails today blocks the build from phase 7 until phase 8 fixes it, or a waiver covers it.

### Recommendation (D3)

**Gate these checks:**

- **CKV_DOCKER_3** — Container running as root turns any app RCE into root in the container and makes escapes easier. Limitation: file-wide, so a `USER` in any stage satisfies it; CKV_DOCKER_8 partly covers the final state.
- **CKV_DOCKER_8** — Explicit `USER root` as the last `USER` undoes a non-root user. Limitation: `USER 0` isn't caught.
- **CKV_DOCKER_1** — An SSH port in an app container is a remote-login path that should never ship; never a false positive in practice.
- **CKV_DOCKER_7** — An untagged base (implicit `latest`) means the shipped image isn't reproducible and scan results don't describe what runs. Fails today on the distroless `FROM` (line 22): it blocks from phase 7 until phase 8 pins that base (by digest, which also passes this check) — a planned phase 8 fix. Limitation: any tag passes, including mutable ones like `node:24`; digest pinning has no Checkov check.
- **CKV_GHA_2** — Script injection in `run:` gives an attacker code execution on the runner with the job's token. Limitation: 17 fixed patterns; zizmor in phase 9 broadens it.
- **CKV2_GHA_1** — `write-all` token permissions widen the blast radius of any compromised step.

**Report only:**

- **CKV_DOCKER_2** — Missing HEALTHCHECK is an operability gap, not something an attacker can use; orchestrators like Kubernetes ignore it; distroless has no shell/curl to run one. A developer would rightly push back on a red build for it.

**Possible addition:** CKV_GHA_1 (`ACTIONS_ALLOW_UNSECURE_COMMANDS` set to true, which re-enables the deprecated `set-env`/`add-path` commands behind CVE-2020-15228) — **gate**, ID to be confirmed against the local report's check list during step 2.

## Steps

1. ✅ **`.checkov.yaml`** at the repo root (implementer):
   - `framework: [dockerfile, github_actions]`, `skip-path` for `app/test/` with the D1 reason as a comment, `soft-fail: true`, `skip-download: true`.
   - The YAML key syntax is unverified (the docs page is a 404). Generate a reference with `--create-config`, then match its keys.
   - **Check:** the file parses, and Checkov picks it up when passed via `--config-file`.
   - **Result:** `.checkov.yaml` created. Implementer had no Docker so did not generate the `--create-config` reference; the keys were instead validated by the user's step 2 run (config loaded, 0 `[ERROR]` lines, no unknown-key warnings).
2. ✅ **Re-run locally (you)** with `--config-file /src/.checkov.yaml`.
   - **Check:** files scanned = 3 (`test/smoke` gone); Dockerfile failures 6 → 3 (CKV_DOCKER_2 ×2, CKV_DOCKER_7 ×1); nothing else changes.
   - **Result:** Files scanned = 3 (`/app/Dockerfile`, `/app/infrastructure/Dockerfile`, `/.github/workflows/security.yml`); dockerfile 324 passed / 3 failed (CKV_DOCKER_2 at app/Dockerfile:1 and app/infrastructure/Dockerfile:1; CKV_DOCKER_7 at app/Dockerfile:22); github_actions 108 passed / 0 failed; parsing errors 0. CKV_GHA_1 ID confirmed ("Ensure ACTIONS_ALLOW_UNSECURE_COMMANDS isn't true on environment variables").

### Lessons learned in step 2 re-run

- With several `-o` formats, `--output-file-path` needs one entry per format, in order, and each entry is a **file** path (a directory gives `IsADirectoryError`); a single path for all formats is treated as a directory. A count mismatch crashes with `IndexError`. Both failures print `[ERROR]` but don't stop the run — more reasons the CI coverage check must look for `[ERROR]` and for each output file.
- Also: in zsh the pipe exit-status array is `${pipestatus[1]}`, not bash's `${PIPESTATUS[0]}`.
3. ✅ **Write `docs/findings/checkov.md`** (implementer drafts from this plan and the reports; you review the judgements). Cover:
   - what ran and the coverage;
   - the 6 → 3 failures and the verdict on each;
   - **what Checkov can't see** (the list in "Done so far"; it confirms that zizmor is needed in phase 9);
   - the file-wide `USER`/`HEALTHCHECK` limitation;
   - severity null;
   - the output-write failure that still exits 0;
   - decisions D1–D5.
4. ✅ **Gating rule 5** in `.claude/rules/gating-policy.md` (implementer, after D3/D4 are decided): replace the example list with the decided check IDs and their reasons, and the scope (`app/Dockerfile`, `.github/workflows/`). Phase 7 turns this into code.
5. ✅ **CI job `checkov`** in `.github/workflows/security.yml` (implementer):
   - pinned image; `--network none`; `--config-file`; `:ro` source mount; runs as the runner UID;
   - JSON + SARIF written to `reports/checkov/`.
   - **Coverage check step:**
     - output files exist;
     - the JSON lists both frameworks;
     - `parsing_errors == 0` for each;
     - the union of passed and failed `file_path`s contains `/app/Dockerfile`, `/app/infrastructure/Dockerfile` and `/.github/workflows/security.yml`;
     - no `[ERROR]` line in Checkov's console log.
   - Upload `checkov-reports` (`if-no-files-found: error`, 7 days), plus `checkov-reports-incomplete` on failure.
   - **Verification:** actionlint not available locally (not run; CI will be the first real run). Coverage logic tested locally against the real step-2 report (pass) and doctored copies — workflow missing, parsing error > 0, empty dir, non-array JSON, framework missing, Checkov-format `[ERROR]` in stderr log, same in console.log (all fail as expected). Plus a console.log containing a literal `[ERROR]` inside a printed code line (passes, as required). Design detail: stderr goes to `checkov-stderr.log` (plain redirect), CLI stdout to `console.log`; the error check matches only Checkov's anchored log-line format (`YYYY-MM-DD HH:MM:SS,mmm [thread] [ERROR]`) so finding text can't fail the job. Outputs are written straight into `reports/checkov/`.
6. ✅ **Update `phases.md`** (Checkov output: JSON for triage, SARIF from the same run) and the roadmap, steps 3–7.
7. ✅ **Review (code-reviewer)** — three fix rounds (rule 5 split into gated / not-gating lists; `--framework` and `--skip-download` removed from CI job so `.checkov.yaml` is single source of truth, `--soft-fail` kept on CLI; `[CRITI]` added to error pattern; doc/comment fixes; local-scanning.md command matched to CI). Final verification: offline run with pinned image, exact CI flags, no `--framework`; config's `framework:` honored (dockerfile + github_actions only), skip-path and skip-download applied, exit 0, dockerfile 324 passed / 3 failed, github_actions 132 passed / 0 failed (larger than earlier 108 due to new resources), 0 ERROR/CRITICAL/WARNING log lines. Review clean. Committed and merged (PR #4).

8. ✅ **PR, merge** (PR #4, f66bb8d). Branch `phase-5-checkov` merged to `main` (merge commit).

## Open questions for the user

None.

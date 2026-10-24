# Checkov: Dockerfile and GitHub Actions misconfiguration

## What ran

Checkov **3.3.22**, pinned by digest
(`bridgecrew/checkov:3.3.22@sha256:617c76e3f9b1f7907ebca9abb6b9d746844edcb48e9bd775e4692c69c1c6ac47`).
Frameworks: `dockerfile`, `github_actions`. Scanned with `--skip-download`, `--soft-fail`,
`--network none`, and the configured skip-paths. JSON and SARIF output. Run on 2026-10-07.

| Framework | Files scanned | Passed checks | Failed checks | Parsing errors |
|---|---|---|---|---|
| Dockerfile | 2 | 324 | 3 | 0 |
| GitHub Actions | 1 | 108 | 0 | 0 |

**Files scanned** (4 files found, 3 after skip-path filtering):
- `/app/Dockerfile` (checked)
- `/app/infrastructure/Dockerfile` (checked, challenge material; see D2 below)
- `/.github/workflows/security.yml` (checked)
- `app/test/smoke/Dockerfile` (skipped via `skip-path` in `.checkov.yaml`; see D1)

## Three Dockerfile failures: verdicts

All three failures are from framework-wide checks applied to every Dockerfile in the scan.

| Check | File | Line(s) | Verdict | Decision |
|---|---|---|---|---|
| CKV_DOCKER_7 | `app/Dockerfile` | 22 | Real, blocks gating rule 5 | Gate (D3) |
| CKV_DOCKER_2 | `app/Dockerfile` | 1–41 | Real but not gating | Report-only (D3) |
| CKV_DOCKER_2 | `app/infrastructure/Dockerfile` | 1–24 | Real but never gating | Report-only (D2) |

### CKV_DOCKER_7 at app/Dockerfile:22 — untagged distroless base

Line 22 is `FROM gcr.io/distroless/nodejs24-debian13` (implicit `latest`). **Verdict: real.**
The base lacks an explicit tag or digest, so rebuilds on different days may pull a different version,
breaking reproducibility and scan consistency. Pin by digest (also passes CKV_DOCKER_7), so the image
is completely reproducible.
**Gating decision (D3):** blocks the build. **Phase 8 candidate:** pin by digest.

### CKV_DOCKER_2 at app/Dockerfile:1–41 — no HEALTHCHECK

**Verdict: real but report-only.** The Dockerfile has no `HEALTHCHECK` instruction. Missing
HEALTHCHECK is an operability gap, not something an attacker can use. Orchestrators like Kubernetes
use their own health checks instead (ignoring Dockerfile HEALTHCHECK), and distroless images have no
shell or curl, so implementing a check would need an exec-form script. A developer would rightly push
back on a red build for this.
**Gating decision (D3):** report only, never blocks.

### CKV_DOCKER_2 at app/infrastructure/Dockerfile:1–24 — no HEALTHCHECK

**Verdict: real but challenge material, never gating.** Same check as the above, on the infrastructure
Dockerfile. This file is part of the "misplaced IaC files" challenge (like `app/terraform/`) and is
never built or deployed in this pipeline.
**Gating decision (D2):** reported but never gates (same rule as Terraform in Semgrep findings).

## GitHub Actions: 108 passed, 0 failed (local run; CI will show more)

Every check passed on the local run (before the checkov job was added to CI). No violations of
CKV_GHA_2 (shell injection), CKV2_GHA_1 (permissions: write-all), or CKV_GHA_1
(ACTIONS_ALLOW_UNSECURE_COMMANDS). The CI run will add more resources (the checkov job itself),
so results may differ. Phase 7 notes: `resource_count` is 0 even with 108 checks run, so it can't
be a coverage signal; the CI job's coverage step must verify scanned frameworks another way.

**Lesson:** 108 passed checks ≠ hardened workflow. Checkov catches only part of phase 9's hardening
needs (see plan, D4). Checkov has no check for action pinning (tag or SHA). Phase 9 will add zizmor
(`unpinned-uses`) to gate SHA-pinned actions (see gating rule 5's note on "Unpinned actions").

## What Checkov cannot see

From the researcher report:

- **Base image pinned by digest** (e.g., `@sha256:cafebabe…`). Checkov checks only for a tag or
  implicit `latest`. Digest pinning is better and currently undetectable.
- **Pinned actions** (tag or SHA, e.g., `@v7` or `@abc123def456…`). Checkov has no action-pinning
  check. Phase 9 will add zizmor for this (see gating rule 5).
- **`persist-credentials: false`** on checkouts, **`pull_request_target`** trigger (for PRs that
  run untrusted code), **missing job-level `permissions`**, and general **`${{ github.event.* }}`
  injection into `run:`** beyond the 17 fixed patterns in CKV_GHA_2.

Checkov's GitHub Actions framework catches only the high-level gates: permissions: write-all,
the known script-injection patterns, and deprecated commands. Broader hardening (phase 9,
`ci-workflows.md`) needs zizmor.

## Output-write failure (quiet failure mode)

**Lesson from step 2:** when Checkov can't write its output (unwritable directory, `-o` format count
mismatch, or directory given as a per-format file path), it exits 0 and writes no files. The only
sign is an `[ERROR]` line in stderr. The CI job must:
- Create the output directory before running the scan.
- Use `-o cli -o json -o sarif --output-file-path console,/out/results_json.json,/out/results_sarif.sarif`
  (one **file** path per format, in order; a single path for all formats is treated as a directory).
- Check for `[ERROR]` lines in the log and fail if found.
- Verify each output file exists.

## Framework-wide checks (`USER` and `HEALTHCHECK` limitations)

Both CKV_DOCKER_3 (no `USER`) and CKV_DOCKER_8 (last `USER` is root) operate at the file level,
not per-stage. A `USER` instruction anywhere in the Dockerfile satisfies CKV_DOCKER_3, even if
it's in an early build stage and overridden later. CKV_DOCKER_8 checks the last `USER` seen,
which is the final container's user. Limitation: `USER 0` (numeric root) isn't caught, only
`USER root` (by name).

## Severity field: always null

Without a Checkov account, the `severity` field is null on every check. The SARIF report marks
every failed check as level `error`. Triage must not rely on severity to filter findings.

## Gating-rule 5 check list

See `gating-policy.md`, rule 5. Gated checks are applied to `app/Dockerfile` and `.github/workflows/`
only (not `app/infrastructure/` or tests). See rule 5 for the reasoning behind each check ID.

| Check | Verdict (on this commit) |
|---|---|
| CKV_DOCKER_3 (no `USER`) | Not failing |
| CKV_DOCKER_8 (last `USER` is root) | Not failing |
| CKV_DOCKER_1 (port 22 exposed) | Not failing |
| CKV_DOCKER_7 (base without tag) | Failing (`app/Dockerfile:22`); blocks |
| CKV_GHA_2 (shell injection) | Not failing |
| CKV2_GHA_1 (permissions: write-all) | Not failing |
| CKV_GHA_1 (ACTIONS_ALLOW_UNSECURE_COMMANDS) | Not failing |
| CKV_DOCKER_2 (no HEALTHCHECK) | Failing but report-only |

## Configuration decisions

- **D1: skip-path `app/test/`** — `app/test/smoke/Dockerfile` is upstream's smoke-test container
  (Alpine + curl) used only by upstream's `docker-compose.test.yml`; this pipeline never builds or
  runs it. Same rule as Semgrep (`.semgrepignore`) and gating rule 4: tests aren't scanned for gating.
  Configured in `.checkov.yaml`: `skip-path: [app/test/]`.

- **D2: `app/infrastructure/Dockerfile` stays scanned, never gates** — Challenge material
  (the "misplaced IaC files" challenge), like `app/terraform/` in Semgrep. Nothing builds it.
  Keeping it visible matches the Terraform decision in phase 4. Scanned, but gating checks applied
  only to `/app/Dockerfile` and `/.github/workflows/`.

- **D3: rule 5 check list** — See `gating-policy.md`, rule 5, for the seven gated checks and reasons.
  Phase 7 implements filtering by check_id in `triage/policy.py`. `.checkov.yaml` is the single
  source of truth for scan settings (frameworks, skip-paths, soft-fail); the CI job repeats
  `--soft-fail` on the command line to guarantee that scan jobs never fail on findings, independent
  of the config file.

- **D4: unpinned actions not gatable by Checkov** — See gating rule 5 note. No Checkov check exists.
  Phase 9 will add zizmor.

- **D5: Triage fingerprinting** — Checkov findings have no fingerprint field and no unique ID per
  instance (just the check_id). Proposed: triage fingerprints as `check_id + file_path + file_line_range[0]`
  (the start line only; a multi-line check is keyed on where it begins). Decided in phase 7.

## Notes for phase 7 (triage integration)

- Parse JSON, not SARIF. The JSON carries check_type (framework), making it easy to separate
  Dockerfile from GitHub Actions checks.
- Every check has `severity: null` without a Checkov account. Don't filter on severity.
- Fingerprint as `check_id + file_path + file_line_range[0]` (scope TBD in phase 7; see D5).
- Scope gated checks to:
  - **Dockerfile checks** on `/app/Dockerfile` only (not `/app/infrastructure/Dockerfile`).
  - **GHA checks** on any file under `/.github/workflows/` (matching rule 5).
  - See `gating-policy.md` rule 5 for which checks gate.
- Coverage check (CI step): verify both frameworks are in the results, parsing_errors == 0 for each,
  at least `/app/Dockerfile`, `/app/infrastructure/Dockerfile`, and `/.github/workflows/security.yml`
  are listed in passed/failed file_path unions, and no Checkov-format errors (anchored log-line
  pattern matching `[ERROR]` or `[CRITI]`) appear in `checkov-stderr.log` or `console.log`.

## Fixed in phase 8

### F3: pin both base images by tag and digest (2026-10-24)

**Finding.** CKV_DOCKER_7 at `app/Dockerfile:22`: `FROM gcr.io/distroless/nodejs24-debian13`, no tag,
so implicitly `latest`. Gating rule 5. The installer stage (`FROM node:24`) passed the check but
was just as mutable: `node:24` is a moving tag.

**Why it mattered.** With floating bases, two builds of the same commit can ship different OS
packages and a different Node patch, so a scan describes one build, not the commit. A moved or
compromised tag would reach the image without any change in the repo.

**Fix.** Both stages pinned by tag and index digest (multi-arch; digests read with
`docker buildx imagetools inspect` on 2026-10-24, matching the researcher's registry values):

- `node:24.22.1-trixie@sha256:016f604a11c4c725f0a4c62e29ff11adab153d297bf97046c9bf2ddb9f1011d3`:
  Debian 13 like the runtime (plan D7; `node:24` was bookworm), Node 24.22.1 like distroless.
- `gcr.io/distroless/nodejs24-debian13:nonroot@sha256:cb606325b7ec4af55462cb0b424a53b452a5b4a894ffe841fcf1048d216fb9f8`:
  the `nonroot` variant defaults to UID 65532, the same user as the Dockerfile's `USER 65532`, so
  deleting that line later would not silently fall back to root (defence in depth).

The tag is kept next to the digest for readers; Docker resolves the digest. CKV_DOCKER_7 passes on
`image:tag@sha256:…` (Checkov 3.3.22 source: it only fails without a `:` or on a trailing
`:latest`; a bare `image@sha256:…` passes too, because of the `:` in `sha256:`). Checkov still has
no digest-pinning check, so a later `FROM image:24` would pass. Dependabot (phase 9) keeps the
digests current.

**Proof.** Checkov 3.3.22 with `.checkov.yaml` (`reports/phase8-f3/checkov/`): dockerfile 308
passed / 2 failed (was 3 failed), CKV_DOCKER_7 passes at `/app/Dockerfile:21`; the 2 left are
CKV_DOCKER_2 (no HEALTHCHECK, report-only by policy) on `app/Dockerfile` and
`app/infrastructure/Dockerfile`. github_actions 252 / 0. Trivy 0.75.0 image scan
(`reports/phase8-f3/`): Debian 13.7, 140 rows, identical to the F2c image scan. Build OK on the Debian 13
installer (sqlite3's native module included); smoke test HTTP 200 on 127.0.0.1:3001, no errors in
the logs; container user 65532 (`docker exec … id` fails: distroless has no `id`). Pinning froze
what we already had; it didn't change it. That's the point: the next change now has to be a
commit.

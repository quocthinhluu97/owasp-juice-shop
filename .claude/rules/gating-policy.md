# Gating policy

The triage script (see `triage-script.md`) is the only thing that decides whether the build passes.

## Gating rule (fail the build if any of these are true)

The rule should be one you could defend to a developer. Start here and change it only with a written reason:

1. Any secret from Gitleaks that isn't waived. A leaked credential is always actionable: rotate it.
2. Any CVE in **CISA KEV**, at any severity, in any scope: the final image, production dependencies, or build tooling. Reason (D19, phase 7): a KEV CVE is being exploited now. Build tools run on the CI runner, which holds the job's token, so a KEV CVE in build tooling is a supply-chain risk even though it never ships. It almost never fires (0 KEV hits in the phase 3-6 reports), so it costs nothing day to day.
3. **Critical/High CVE with a fix available**, in production dependencies or the final image. If there's no fix, it's reported but doesn't block, because the developer can't act on it.
   - **Build-tool exception (D7, phase 7):** a package in the *frontend* lockfile whose top parents (walking `DependsOn` up to direct packages) are all build tooling is labelled "build stage only", reported, and not gated. Reason: the build tools run in the build stage and never ship in the final image. Any top parent outside the list gates, and so does an incomplete chain (a `?` marker in the walk), because an incomplete chain must not let a finding escape. The root lockfile and the image gate as written. The exception does not apply to rule 2 (KEV), which gates in every scope (D19). The list is `BUILD_TOOL_PARENTS` in `triage/policy.py` (source of truth): `@angular/build`, `@angular/cli`, `@angular/compiler-cli`, `@cyclonedx/cyclonedx-esbuild`, `sass`, `typescript`, `vitest`, `jsdom`.
4. Semgrep findings at `ERROR`, `HIGH` or `CRITICAL` severity in first-party code (not `node_modules`, not tests, not frontend build output). Semgrep documents `ERROR` as the legacy alias of `HIGH`, and `CRITICAL` has no legacy name, so the rule gates all three (D4, phase 7): a `CRITICAL` finding must not slip through. Also not gating, each for a written reason (phase 4, `docs/findings/semgrep.md`):
   - `app/terraform/`, `app/infrastructure/`: challenge material ("misplaced IaC files"); nothing deploys it. Reported, never blocks.
   - `.npmrc` files: package-manager config, not code. Reported, never blocks.
   - `generic.secrets.*` rules: secrets are rule 1's job (Gitleaks). Triage merges them with a Gitleaks finding on the same file + line; without one they're reported, never blocking.
   - `app/data/static/codefixes/` is excluded in `.semgrepignore` (coding-challenge answer options, never executed), so it never reaches triage.
5. **Checkov failures** from a short, named list of high-impact checks in `app/Dockerfile` and any file under `.github/workflows/`, scoped and gated in code (phase 7, `triage/policy.py`):
   - **CKV_DOCKER_3** (no `USER` in Dockerfile): Container running as root turns any app RCE into root in the container and makes escapes easier. Limitation: file-wide, so a `USER` in any stage satisfies it; CKV_DOCKER_8 partly covers the final state.
   - **CKV_DOCKER_8** (last `USER` is root): Explicit `USER root` as the last `USER` undoes a non-root user. Limitation: `USER 0` isn't caught.
   - **CKV_DOCKER_1** (port 22 exposed): SSH port in an app container is a remote-login path that should never ship; never a false positive in practice.
   - **CKV_DOCKER_7** (base image without a tag or `latest`): Untagged base (implicit `latest`) means the shipped image isn't reproducible and scan results don't describe what runs. Limitation: any tag passes, including mutable ones like `node:24`; digest pinning has no Checkov check.
   - **CKV_GHA_2** (shell injection in `run:`): Script injection in `run:` gives an attacker code execution on the runner with the job's token. Limitation: 17 fixed patterns; zizmor in phase 9 broadens it.
   - **CKV2_GHA_1** (top-level `permissions: write-all`): `write-all` token permissions widen the blast radius of any compromised step.
   - **CKV_GHA_1** (`ACTIONS_ALLOW_UNSECURE_COMMANDS` set to true): Re-enables the deprecated `set-env`/`add-path` commands behind CVE-2020-15228. (ID confirmed in the phase 5 step 2 run.)

   Also not gating, each for a written reason:
   - **CKV_DOCKER_2** (no HEALTHCHECK): **report only**, not gating. Missing HEALTHCHECK is an operability gap, not something an attacker can use; orchestrators like Kubernetes ignore it; distroless has no shell/curl to run one. Developer would rightly push back on a red build for it.
   - **`app/infrastructure/Dockerfile`** (all checks): **reported but never gating** (challenge material, like `app/terraform/` in rule 4; nothing builds it).
   - `app/test/` is excluded via `skip-path` in `.checkov.yaml` (upstream smoke-test container, never built), so it never reaches triage.
   - **Unpinned actions** (any `uses:` not pinned to a full commit SHA, including tags like `@v7`): Not detectable by Checkov (no check exists). Enforced from phase 9 by zizmor (`unpinned-uses`), added to the gate then.
6. ZAP rules set to `FAIL` in `.zap/rules.tsv` (phase 6). Triage reads the levels from that file and matches on `pluginid`; the JSON report doesn't carry them:
   - **10038** (CSP header not set): Without a CSP, any XSS runs arbitrary script, and Juice Shop has several. High confidence; the fix is one header.
   - **10028** (off-site redirect): An open redirect on our own origin is a phishing and token-theft tool. The fix is an exact-match allowlist.
   - **10115** (script served from a malicious domain, polyfill.io): A known supply-chain compromise; never a false positive.

   Also not gating, each for a written reason (the 4th column of `rules.tsv`):
   - **10020 / 10021** (anti-clickjacking, nosniff): fired only on `socket.io` polling responses, which carry the headers since phase 8 (F5/D17), so they no longer fire; helmet covers the HTML pages. They stay WARN: FAIL would block on a false positive.
   - **10110** (dangerous JS functions): low confidence, fires on any use of the API; gating code is rule 4's job (Semgrep).
   - **10003** (vulnerable JS library): dependency CVEs are rules 2–3's job (Trivy).
   - IGNORE-level rules and plugin IDs not listed in `rules.tsv` (e.g. 120000 from the client add-on) are reported, never gating.

Everything else goes into the report but doesn't block. The report must say **why** each blocking finding blocks, by naming the rule number above. A developer who sees a red build should know exactly what to do next.

## Waivers

`triage/waivers.yaml` entries match on fingerprint (or CVE+package). Each one needs `reason`, `owner` and `expires` (ISO date). An expired waiver stops applying, so the finding blocks again. The script prints a warning for waivers that expire within 14 days.

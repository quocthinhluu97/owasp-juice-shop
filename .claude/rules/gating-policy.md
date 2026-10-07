# Gating policy

The triage script (see `triage-script.md`) is the only thing that decides whether the build passes.

## Gating rule (fail the build if any of these are true)

The rule should be one you could defend to a developer. Start here and change it only with a written reason:

1. Any secret from Gitleaks that isn't waived. A leaked credential is always actionable: rotate it.
2. Any CVE in **CISA KEV**, at any severity, in a package present in the final image or production dependencies.
3. **Critical/High CVE with a fix available**, in production dependencies or the final image. If there's no fix, it's reported but doesn't block, because the developer can't act on it.
4. Semgrep findings at `ERROR` severity in first-party code (not `node_modules`, not tests, not frontend build output). Also not gating, each for a written reason (phase 4, `docs/findings/semgrep.md`):
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
6. ZAP rules set to `FAIL` in `rules.tsv`.

Everything else goes into the report but doesn't block. The report must say **why** each blocking finding blocks, by naming the rule number above. A developer who sees a red build should know exactly what to do next.

## Waivers

`triage/waivers.yaml` entries match on fingerprint (or CVE+package). Each one needs `reason`, `owner` and `expires` (ISO date). An expired waiver stops applying, so the finding blocks again. The script prints a warning for waivers that expire within 14 days.

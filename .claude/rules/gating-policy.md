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
5. Checkov failures from a short, named list of high-impact checks (e.g. running as root, no `USER`, workflow script injection, unpinned actions). Keep the list in code, with a reason for each check.
6. ZAP rules set to `FAIL` in `rules.tsv`.

Everything else goes into the report but doesn't block. The report must say **why** each blocking finding blocks, by naming the rule number above. A developer who sees a red build should know exactly what to do next.

## Waivers

`triage/waivers.yaml` entries match on fingerprint (or CVE+package). Each one needs `reason`, `owner` and `expires` (ISO date). An expired waiver stops applying, so the finding blocks again. The script prints a warning for waivers that expire within 14 days.

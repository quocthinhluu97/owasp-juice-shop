# Phases

1. **App + Dockerfile + minimal workflow.** Build the image in CI and do nothing else.
2. **Gitleaks.** Scans the whole history of the commit being built (`--log-opts="--full-history --diff-filter=tuxdb HEAD"`, not `--all` refs). Output: JSON with each secret replaced by its sha256 in CI. SARIF has no secret field, and `--redact` would give every finding the same hash, which breaks the secret fingerprint in `triage-script.md`.
3. **Trivy.** Scans both the built image (`trivy image`) and the repo (`trivy fs`, for lockfile CVEs). Output: JSON, because it carries `FixedVersion`, `PkgPath` and the dependency type that triage needs. Trivy's secret and misconfig scanners overlap with Gitleaks and Checkov. Turn them off or expect duplicates.
4. **Semgrep.** Start with `p/default` plus `p/javascript` / `p/typescript`. Output: JSON for triage (SARIF results carry no severity, and without a login `extra.fingerprint` is redacted), plus SARIF from the same run for code scanning.
5. **Checkov.** Frameworks: `dockerfile`, `github_actions` (add `kubernetes`/`terraform` if those get added later). Output: JSON for triage, SARIF from the same run.
6. **ZAP baseline.** Passive scan against the running container in CI. Output: JSON (`-J`) for triage. The JSON carries no WARN/FAIL level, so triage reads `.zap/rules.tsv` itself and matches on `pluginid` (D6). `rules.tsv` sets each rule to IGNORE/WARN/FAIL, with a reason for each. Runs the Client Spider (`-j`) on a `--internal` Docker network (no internet egress, no published port), with the pscanrulesBeta add-on pinned by hash and `-z "-silent"` (D3, D12). The CI job fails only if the scan didn't really run (coverage check); findings never fail it.
7. **Triage script** gates the build (see `gating-policy.md` and `triage-script.md`).
8. **Fix a few findings** (see `fixing-findings.md`).
9. **Lock down the pipeline** (see `ci-workflows.md`).

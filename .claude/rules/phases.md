# Phases

1. **App + Dockerfile + minimal workflow.** Build the image in CI and do nothing else.
2. **Gitleaks.** Scans the whole git history, not just HEAD. Output: SARIF.
3. **Trivy.** Scans both the built image (`trivy image`) and the repo (`trivy fs`, for lockfile CVEs). Output: JSON, because it carries `FixedVersion`, `PkgPath` and the dependency type that triage needs. Trivy's secret and misconfig scanners overlap with Gitleaks and Checkov. Turn them off or expect duplicates.
4. **Semgrep.** Start with `p/default` plus `p/javascript` / `p/typescript`. Output: SARIF.
5. **Checkov.** Frameworks: `dockerfile`, `github_actions` (add `kubernetes`/`terraform` if those get added later). Output: SARIF or JSON.
6. **ZAP baseline.** Passive scan against the running container in CI. Output: JSON (`-J`). It uses a `rules.tsv` to set each rule to IGNORE/WARN/FAIL, with a reason for each.
7. **Triage script** gates the build (see `gating-policy.md` and `triage-script.md`).
8. **Fix a few findings** (see `fixing-findings.md`).
9. **Lock down the pipeline** (see `ci-workflows.md`).

---
paths:
  - ".github/**"
---

# CI workflows

- Use bash in `run:` steps.
- Pin container images by digest. Don't use `latest` in the workflow.
- Most scanners exit non-zero when they find something. Let the scan steps finish (`continue-on-error` or `--exit-code 0`) so that the triage step makes the pass/fail decision, and nothing else.

## Pipeline hardening (final phase)

- **Pin every action to a full 40-character commit SHA**, with the version in a comment: `uses: actions/checkout@<sha> # v4.x.y`. Pin container images by digest. Dependabot (`package-ecosystem: github-actions` and `docker`) handles updates.
- **Least-privilege `GITHUB_TOKEN`:** set `permissions: {}` at the workflow level and grant each job only what it needs (`contents: read`; add `security-events: write` only on the job that uploads SARIF).
- `actions/checkout` with `persist-credentials: false`.
- Use the `pull_request` trigger, never `pull_request_target`, for anything that runs PR code. Never interpolate `${{ github.event.* }}` directly into `run:`. Pass it through `env:` instead.
- **OIDC, not cloud keys:** the deploy job requests `id-token: write` and assumes a cloud role whose trust policy is scoped to this repo + branch/environment. No long-lived cloud credentials in repository secrets. Use a protected GitHub Environment for deploy.
- Set job `timeout-minutes` and a `concurrency` group.
- Checkov's `github_actions` framework and `zizmor`/`actionlint` (optional) should pass on the workflows themselves.

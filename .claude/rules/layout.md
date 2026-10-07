# Layout (target)

```
.claude/
  CLAUDE.md               project overview
  rules/                  topic rules (this directory)
  agents/                 subagents (researcher.md: read-only research; code-reviewer.md: review, no edits;
                          implementer.md: code from a plan; plan-writer.md: persists plans)
  plans/                  persisted plans (roadmap.md: all phases)
app/                      Juice Shop source (vendored at a pinned tag) + Dockerfile
.github/workflows/
  security.yml            build + scan jobs (gitleaks, trivy, semgrep, checkov run in parallel) → triage gate (phase 7)
  deploy.yml              (optional) OIDC-authenticated deploy, final phase only
.github/dependabot.yml    keeps pinned action SHAs and base images up to date
triage/
  triage.py               CLI entry point
  parsers/                one module per scanner → common Finding model
  policy.py               the gating rule
  enrich.py               CISA KEV / EPSS lookup, reachability hints
  waivers.yaml            accepted exceptions
  tests/                  pytest, with real scanner output trimmed into fixtures/
reports/                  raw scanner output (gitignored)
docs/findings/            one note per scanner: what it found, what was noise, what was fixed
.gitleaks.toml  .semgrepignore  .trivyignore  .checkov.yaml  .zap/rules.tsv
```

Update this file when the real layout changes.

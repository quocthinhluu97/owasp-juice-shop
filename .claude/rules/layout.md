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
  security.yml            build + scan jobs (gitleaks, trivy, semgrep, checkov, zap run in parallel) → triage job (phase 7) decides pass/fail
  deploy.yml              (optional) OIDC-authenticated deploy, final phase only
.github/dependabot.yml    keeps pinned action SHAs and base images up to date
triage/
  triage.py               CLI entry point (exit 0 pass, 1 gate failed, 2 script error)
  model.py                Finding model, explicit per-tool severity mapping
  parsers/                one module per scanner (gitleaks, trivy, semgrep, checkov, zap) + common.py
  dedupe.py               fingerprint dedupe; Semgrep secrets merged into Gitleaks
  enrich.py               CISA KEV lookup, cached in triage/.cache/ (gitignored)
  reachability.py         labels only: dependency type, image/fs presence, grep-level imports
  policy.py               the gating rule (rules 1–6)
  waivers.py              loads and applies waivers.yaml
  waivers.yaml            accepted exceptions
  report.py               step summary and reports/triage.json
  requirements.txt        pinned pytest and PyYAML
  tests/                  pytest, with real scanner output trimmed into fixtures/
reports/                  raw scanner output (gitignored)
docs/findings/            one note per scanner: what it found, what was noise, what was fixed
.gitleaks.toml  .semgrepignore  .trivyignore  .checkov.yaml  .zap/rules.tsv
```

Update this file when the real layout changes.

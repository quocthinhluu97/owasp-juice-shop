# CLAUDE.md

This is a DevSecOps learning project. OWASP Juice Shop is the target app. The project adds five security scanners to a GitHub Actions pipeline, one at a time. A Python triage script combines their output and decides whether the build fails. The last step is hardening the pipeline itself.

The goal is learning, not a green build. Reading and judging findings is the work. Suppressing them to make CI pass defeats the purpose.

## Rules

Detailed instructions live in `.claude/rules/`, one file per topic:

| File | Topic | Loaded |
|---|---|---|
| `ground-rules.md` | Non-negotiables: safety, suppression, secrets, scanner output | always |
| `working-conventions.md` | How Claude works on this repo, shell (Linux/bash) | always |
| `layout.md` | Target repo layout | always |
| `phases.md` | The nine phases and each scanner's setup | always |
| `local-scanning.md` | Running scanners locally on Linux / WSL2 | always |
| `gating-policy.md` | The rules that fail the build, and waivers | always |
| `fixing-findings.md` | How to pick, fix and document findings | always |
| `triage-script.md` | Triage implementation: model, dedupe, enrich, output, tests | `triage/**` |
| `ci-workflows.md` | GitHub Actions conventions and pipeline hardening | `.github/**` |

Keep this table in sync when rule files are added, renamed or rescoped.

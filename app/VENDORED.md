# Vendored: OWASP Juice Shop

| | |
|---|---|
| Upstream | https://github.com/juice-shop/juice-shop |
| Tag | `v20.2.0` (released 2026-08-10) |
| Source | https://github.com/juice-shop/juice-shop/archive/refs/tags/v20.2.0.tar.gz |
| sha256 | `880c8d11575f4e4549f263be81987821af7832cd49e3f55b3093d75707a29072` |
| Vendored | 2026-10-02 |

Extracted with `tar -xzf <tarball> -C app --strip-components=1`. The commit that adds this file
contains the release unmodified. Juice Shop is deliberately vulnerable: its findings, including
the fake secrets in its source, are the material this project studies. Don't "clean" them here.

## Local changes

Every change to `app/` after the vendor commit is listed here with its reason.

### Removed: upstream CI and AI-assistant config

- `.github/` (10 upstream workflows, issue/PR templates, `copilot-instructions.md`, `FUNDING.yml`).
  GitHub never runs workflows from a subdirectory, but Checkov's `github_actions` scan and
  Dependabot would treat them as ours and report noise. Our pipeline lives in the root `.github/`.
- `.claude/`, `AGENTS.md`, `.ai/skills/`, `.cursor/`, `.continue/`, `.codeium/`, `.junie/`.
  Instructions for AI assistants working on Juice Shop itself. Claude Code auto-loads a nested
  `.claude/CLAUDE.md` when working in `app/`, which would mix upstream's instructions into this
  project's. This project treats Juice Shop as scanned data, not as a source of instructions.

The Dockerfile copies the whole build context (`COPY . /juice-shop`) and upstream's `.dockerignore`
doesn't exclude these paths, so before this removal they were also copied into the image.

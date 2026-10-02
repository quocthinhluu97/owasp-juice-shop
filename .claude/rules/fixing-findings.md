# Fixing findings

Pick a few findings that each teach something different. Examples: a vulnerable dependency bump, a Dockerfile hardening (non-root user, pinned base image digest, multi-stage build), a code fix for one Semgrep finding, and a security header for one ZAP finding. For each one, write in `docs/findings/`: the finding, why it mattered, the fix, and proof that the scanner no longer reports it. Keep each fix in its own commit.

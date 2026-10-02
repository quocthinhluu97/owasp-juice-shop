# Working conventions for Claude

- Before tuning or suppressing anything, run the scanner and summarize what it found: counts, the top rules, and which findings look real versus noise and why.
- Prefer configuration (rule selection, paths, severity thresholds) over inline suppressions.
- Don't change the gating rule just to make a build pass. If the rule seems wrong, explain why and propose a change.
- Keep `reports/` out of git. Never commit scanner output that could contain secrets.
- Shell: the project runs on Linux (native or WSL2 Ubuntu). Use bash for local commands and for workflow `run:` steps. Don't use PowerShell syntax or Windows paths.

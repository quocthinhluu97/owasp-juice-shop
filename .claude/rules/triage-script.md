---
paths:
  - "triage/**"
---

# Triage script

Use Python 3.12+ and the standard library where possible. Allowed extra dependencies: `pyyaml`, plus `requests` only if `urllib` gets painful. Use type hints and dataclasses. Tests use `pytest`.

**Pipeline:** parse → normalize → dedupe → enrich → apply waivers → gate → report. The gating rule and waiver format are in `gating-policy.md`.

- **Normalize** every finding to one `Finding` model with these fields: `tool`, `rule_id`, `category` (secret | vuln | code | iac | dast), `severity` (critical/high/medium/low/info, mapped explicitly per tool and never guessed), `location` (file+line, or package+version, or URL+param), `cve`/`cwe` when present, `fixed_version`, and `fingerprint`.
- **Dedupe** on the fingerprint, and keep a list of every tool that reported the finding:
  - vuln: `cve + package + installed_version` (the same CVE from `trivy image` and `trivy fs` counts once)
  - secret: `rule + file + sha256(secret)`. Never store or print the raw secret.
  - code/iac: `cwe or rule + file + line` (allow a small line tolerance if tools disagree)
  - dast: `alert_id + url_path + param`
- **Enrich:** CISA KEV catalog (JSON feed, cached to a file with a timestamp, and refreshed at most daily) and EPSS if useful. Tests must never hit the network. They use a fixture copy of the feed.
- **Reachability hints** (keep them simple and honest): whether a package is a production or dev dependency, whether it appears only in the build stage and not the final image, and whether first-party code imports or calls the vulnerable module (grep-level evidence is acceptable if it is labelled as such).

## Output

- A human summary to stdout and `$GITHUB_STEP_SUMMARY`: counts by tool and category before and after dedupe, then the blocking findings first.
- `reports/triage.json` (machine-readable) and, optionally, a combined SARIF for upload to code scanning.
- Exit code 0 = pass, 1 = gate failed, 2 = the script itself errored (bad input, parse failure). Never exit 0 on a parse error.

## Tests

- Each parser has a test against a **real** output file from that scanner, trimmed down. Commit these to `triage/tests/fixtures/`.
- Test dedupe across tools, waiver expiry, the KEV rule and each gating rule, including a case that passes and a case that fails.
- Run with `python3 -m pytest triage/tests`.

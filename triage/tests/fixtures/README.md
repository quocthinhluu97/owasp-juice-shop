# Triage test fixtures

Trimmed copies of real scanner output, used by `triage/tests/`. Each fixture keeps the real JSON structure (top-level keys, metadata, field names) and only the entries the tests need. Nothing here is hand-written except the one synthetic KEV entry, which is marked as fake.

## Source

| Item | Value |
|---|---|
| Source | CI artifacts of `main` run **38422003321**, downloaded by the user into `reports/ci/` (the run's head commit was not checked from here; `gh run view 38422003321` shows it) |
| Gitleaks | 8.30.1 (pinned in `security.yml`; the report has no version field). `Secret` is `sha256:<hex>`, `Match` is `REDACTED` (CI hashes it) |
| Trivy | 0.75.0 (`Trivy.Version` in both reports). Image `ArtifactName` `/in/juice-shop.tar` (Debian 13.7); fs `ArtifactName` `/src/app`, created 2026-10-13 |
| Semgrep | 1.179.0 (`version`), `p/default` plus JavaScript/TypeScript rules, OSS engine |
| Checkov | 3.3.22 (`summary.checkov_version`) |
| ZAP | 2.17.0 (`@version`), pscanrulesBeta v50, baseline with Client Spider, target `http://juice:3000` |
| KEV | `reports/kev.json`, catalogVersion `2026.10.02`, 1733 entries (local download, not a CI artifact) |

No CVE in the CI Trivy reports is in KEV catalog 2026.10.02 (checked against `reports/kev.json`: zero intersections). The KEV fixture therefore carries real entries for the schema, and one synthetic entry for a KEV match (see below).

## What was kept

Trimming commands are in the `trim.py` block below. Run from the repo root after downloading the artifacts into `reports/ci/`. The script writes the fixtures listed in the table.

| Fixture | Entries kept | Why |
|---|---|---|
| `gitleaks.json` | 6 of 8 findings | `users.yml:151` generic-api-key (pairs with Semgrep `generic.secrets` at the same line); `users.yml:88` and `login.ts:64` share one sha256 but live in different files (dedupe must count them separately); `ctf.key` (`key-files`, StartLine 0); `lib/insecurity.ts` private-key (first-party); `terraform/networking.tf` private-key (rule 1 applies to any path). Dropped: `encryptionkeys/premium.key` and `infrastructure/terraform/networking.tf` (same shape as kept ones). |
| `trivy-image.json` | 2 Results, 5 vulns (`os-pkgs` 1, `Node.js` 4) | `CVE-2026-19481` `@fastify/busboy` (also in fs, fixed HIGH: image+fs dedupe); `CVE-2026-8674` libc6 (image-only Debian, `affected`, no fix); `GHSA-rvg8-pwq2-xj7q` base64url (non-CVE ID, also in fs, fixed MEDIUM); `GHSA-5mrr-rgp6-x4gr` marsdb (non-CVE, also in fs, `affected` CRITICAL, no fix); `CVE-2026-101894` decompress (`affected` CRITICAL, no fix, also in fs). The Debian rows are all `affected`: this image has no fixed Debian package in the run. |
| `trivy-fs.json` | 2 Results, 7 vulns (`package-lock.json` 4, `frontend/package-lock.json` 3) | Root `package-lock.json`: `CVE-2026-19481`, `GHSA-rvg8`, `GHSA-5mrr`, `CVE-2026-101894` (the dups of the image rows, plus `decompress`). Frontend `frontend/package-lock.json`: `CVE-2026-75899` `fast-uri` (multi-value `FixedVersion` `2.4.5, 3.1.6, 4.1.3`), and `CVE-2026-84961` and `CVE-2026-18540` for `undici@7.29.0`, a transitive dependency of `jsdom@29.1.1` (build tooling, D7 case). `Packages[]` keeps the packages named by kept vulns plus their ancestors up to a direct package (the `ancestors()` closure in the trim script), so the top-parent walk resolves: `undici` → `jsdom` (direct); `fast-uri` → `ajv` → `@angular-devkit/core` → `@angular/cli` / `@angular/build` / `@cyclonedx/cyclonedx-esbuild` (direct). No dead end is left in the kept graph. |
| `semgrep.json` | 10 of 37 results | `app/data/static/users.yml:151` `generic.secrets` ERROR (merge case); `app/routes/login.ts:34` and `app/routes/currentUser.ts:31` ERROR first-party; `app/frontend/src/.../helpers.ts:49` and `app/routes/redirect.ts:18` WARNING; `app/server.ts:157` INFO (maps to low); `app/.npmrc` and `app/frontend/.npmrc` MEDIUM (rule 4 exclusion); `app/infrastructure/terraform/networking.tf:18` and `app/terraform/networking.tf:18` WARNING (non-gating paths). `errors[]` kept to the first entry; `paths.scanned` filtered to the kept files. |
| `checkov/results_json.json` | 7 check results across 2 frameworks | Array shape with both `dockerfile` and `github_actions` objects (parser must accept list, single object and summary-only object). Failed: `CKV_DOCKER_2` `/app/Dockerfile`, `CKV_DOCKER_7` `/app/Dockerfile` (rule 5 gated), `CKV_DOCKER_2` `/app/infrastructure/Dockerfile` (report only). Passed: `CKV_DOCKER_3` and `CKV_DOCKER_8` on `/app/Dockerfile`; `CKV_GHA_1` and `CKV2_GHA_1` on `/.github/workflows/security.yml`. `summary` is kept as the full run reported it (dockerfile failed 3 matches; passed counts are from the full run, not the trimmed list). |
| `zap/zap.json` | 6 of 15 alerts on `http://juice:3000` | `10028` Off-site Redirect (FAIL, High); `10038-1` CSP not set (FAIL, Medium); `10110` Dangerous JS Functions (WARN); `10020-1` anti-clickjacking on socket.io polling URLs (WARN; `sid` in the query, which the fingerprint ignores: D20 keys on pluginid + site); `10049-3` Storable and Cacheable (IGNORE); `3-1` Session ID in URL Rewrite (IGNORE, `sid` in the query). `insights[]`, `created`, `sequences` kept unchanged. Plugin 120000 (client add-on) is not in this run's report, so it is not in the fixture. `count` fields are from the full run. |
| `zap/zap-console.txt` | header, summary line, and blocks for the plugins above | Console text is not parsed by triage; kept so the rule-level levels can be checked by eye. |
| `kev.json` | 3 real entries + 1 synthetic | Real: `CVE-2026-102490`, `CVE-2026-102489` (Zammad chain, `Unknown`), `CVE-2026-59310` (`Known` ransomware use). Synthetic: `CVE-2099-0001`, marked `FAKE` in vendor, product and name, for the KEV-hit test. `count` is set to the number of kept entries; `catalogVersion` and `dateReleased` are the real ones. |

Not in fixtures: `gitleaks.sarif`, `semgrep.sarif`, `checkov` SARIF and console logs, the ZAP HTML report, and `rules.tsv`. Triage does not read them, and the parser tests read the real `.zap/rules.tsv` from the repo.

## Secret checks

- `gitleaks.json`: every `Secret` starts with `sha256:` and every `Match` is `REDACTED`. Checked with a Python one-liner in the step 2 run.
- All fixtures, grep (case-insensitive where it matters):
  - `-----BEGIN` (PEM): no hits.
  - AWS access key ids (`AKIA`/`ASIA` + 16 chars): no hits.
  - GitHub, Slack and Stripe token shapes (`ghp_`, `gh[pousr]_`, `xox*-`, `sk_live_`/`sk_test_`): no hits.
  - JWT shape (`eyJ….….…`): no hits.
  - `password|secret|token|api_key` assigned a quoted value: no hits outside the `sha256:` hashes.
  - Hex strings of 40+ chars: only git commit ids inside `Link`/`references` URLs, which are public.
  - `Private Key`: only the rule description text in `gitleaks.json`.
- Juice Shop's challenge material is not in these fixtures: the Semgrep `lines` field is `requires login`, and the Checkov code blocks are Dockerfile lines only. Nothing to report beyond that.
- No `.gitleaks.toml` allowlist covers these fixtures. Gitleaks v8.30.1 (`dir` mode, repo config without any fixture allowlist) found no leaks here on 2026-10-18. A path allowlist would make Gitleaks skip the files entirely (0 bytes scanned), so a real secret pasted in later would go unseen.

## Synthetic data

`CVE-2099-0001` in `kev.json` is the only invented record. It exists so the KEV-hit path can be tested without a real CVE in a real report. Its vendor, product and name say `FAKE`.

## trim.py

Reproduces every fixture from `reports/ci/` and `reports/kev.json`. Run from the repo root: `python3 -I` with this block saved as a file, or extracted from this README.

```python
# trim.py: rebuild triage/tests/fixtures/ from reports/ci/ (CI artifacts of run 38422003321) and reports/kev.json.
import json
import pathlib
import re

CI = pathlib.Path("reports/ci")
OUT = pathlib.Path("triage/tests/fixtures")
OUT.mkdir(parents=True, exist_ok=True)


def load(path):
    return json.loads(pathlib.Path(path).read_text(encoding="utf-8"))


def save(path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


# Gitleaks: Fingerprint is commit:file:rule:line. Match on file:rule:line (no commit).
GITLEAKS_KEEP = {
    "app/data/static/users.yml:generic-api-key:151",
    "app/data/static/users.yml:generic-api-key:88",
    "app/routes/login.ts:generic-api-key:64",
    "app/ctf.key:key-files:0",
    "app/lib/insecurity.ts:private-key:21",
    "app/terraform/networking.tf:private-key:171",
}
gitleaks = load(CI / "gitleaks-report/gitleaks.json")
save(OUT / "gitleaks.json", [e for e in gitleaks if e["Fingerprint"].split(":", 1)[1] in GITLEAKS_KEEP])

# Trivy: keep the listed (VulnerabilityID, PkgName, InstalledVersion) and the Packages[] needed to join them.
TRIVY_KEEP = {
    ("CVE-2026-19481", "@fastify/busboy", "2.1.1"),
    ("CVE-2026-8674", "libc6", "2.41-12+deb13u4"),
    ("GHSA-rvg8-pwq2-xj7q", "base64url", "0.0.6"),
    ("GHSA-5mrr-rgp6-x4gr", "marsdb", "0.6.11"),
    ("CVE-2026-101894", "decompress", "4.2.1"),
    ("CVE-2026-75899", "fast-uri", "3.1.5"),
    ("CVE-2026-84961", "undici", "7.29.0"),
    ("CVE-2026-18540", "undici", "7.29.0"),
}


def ancestors(packages, ids):
    # Keep each id plus its DependsOn ancestors, stopping at direct packages, so the walk up resolves.
    by_id = {p["ID"]: p for p in packages}
    keep, frontier = set(ids), list(ids)
    while frontier:
        current = frontier.pop()
        if by_id.get(current, {}).get("Relationship") == "direct":
            continue
        for p in packages:
            if current in (p.get("DependsOn") or []) and p["ID"] not in keep:
                keep.add(p["ID"])
                frontier.append(p["ID"])
    return keep


def trim_trivy(src, dst):
    doc = load(src)
    results = []
    for r in doc["Results"]:
        vulns = [v for v in r.get("Vulnerabilities") or []
                 if (v["VulnerabilityID"], v["PkgName"], v["InstalledVersion"]) in TRIVY_KEEP]
        if not vulns:
            continue
        pkg_ids = ancestors(r.get("Packages") or [], {v["PkgID"] for v in vulns})
        packages = [p for p in r.get("Packages") or [] if p["ID"] in pkg_ids]
        results.append({**r, "Packages": packages, "Vulnerabilities": vulns})
    doc["Results"] = results
    save(dst, doc)


trim_trivy(CI / "trivy-reports/trivy-image.json", OUT / "trivy-image.json")
trim_trivy(CI / "trivy-reports/trivy-fs.json", OUT / "trivy-fs.json")

# Semgrep: (path, start line) of the kept results.
SEMGREP_KEEP = {
    ("app/.npmrc", 1),
    ("app/frontend/.npmrc", 1),
    ("app/data/static/users.yml", 151),
    ("app/frontend/src/hacking-instructor/helpers/helpers.ts", 49),
    ("app/infrastructure/terraform/networking.tf", 18),
    ("app/routes/currentUser.ts", 31),
    ("app/routes/login.ts", 34),
    ("app/routes/redirect.ts", 18),
    ("app/server.ts", 157),
    ("app/terraform/networking.tf", 18),
}
semgrep = load(CI / "semgrep-reports/semgrep.json")
semgrep["results"] = [r for r in semgrep["results"] if (r["path"], r["start"]["line"]) in SEMGREP_KEEP]
semgrep["errors"] = semgrep["errors"][:1]
kept_paths = {r["path"] for r in semgrep["results"]}
semgrep["paths"]["scanned"] = [p for p in semgrep["paths"]["scanned"] if p in kept_paths]
save(OUT / "semgrep.json", semgrep)

# Checkov: keep the array shape. Key = (check_id, file_path, first line of file_line_range).
CHECKOV_KEEP = {
    ("CKV_DOCKER_2", "/app/Dockerfile", 1),
    ("CKV_DOCKER_7", "/app/Dockerfile", 22),
    ("CKV_DOCKER_2", "/app/infrastructure/Dockerfile", 1),
    ("CKV_DOCKER_3", "/app/Dockerfile", 39),
    ("CKV_DOCKER_8", "/app/Dockerfile", 39),
    ("CKV_GHA_1", "/.github/workflows/security.yml", 23),
    ("CKV2_GHA_1", "/.github/workflows/security.yml", 19),
}
checkov = load(CI / "checkov-reports/results_json.json")
for obj in checkov:
    results = obj["results"]
    for section in ("failed_checks", "passed_checks"):
        results[section] = [c for c in results[section]
                            if (c["check_id"], c["file_path"], c["file_line_range"][0]) in CHECKOV_KEEP]
    results["skipped_checks"] = []
    results["parsing_errors"] = []
save(OUT / "checkov/results_json.json", checkov)

# ZAP: keep the alerts by alertRef (pluginid plus suffix). The console keeps the same plugins.
ZAP_KEEP_REFS = {"10028", "10038-1", "10110", "10020-1", "10049-3", "3-1"}
ZAP_PLUGINS = {"10028", "10038", "10110", "10020", "10049", "3"}
zap = load(CI / "zap-report/zap.json")
for site in zap["site"]:
    site["alerts"] = [a for a in site["alerts"] if a["alertRef"] in ZAP_KEEP_REFS]
save(OUT / "zap/zap.json", zap)

lines = (CI / "zap-report/zap-console.txt").read_text(encoding="utf-8").splitlines()
out, inside = [], False
for i, line in enumerate(lines):
    m = re.match(r"^[A-Z-]+: .*\[(\d+)\]", line)
    if m:
        inside = m.group(1) in ZAP_PLUGINS
    elif not line.startswith("\t"):
        inside = False
    if i < 2 or i == len(lines) - 1 or (inside and line):
        out.append(line)
(OUT / "zap").mkdir(parents=True, exist_ok=True)
(OUT / "zap/zap-console.txt").write_text("\n".join(out) + "\n", encoding="utf-8")

# KEV: real entries plus one synthetic entry (CVE-2099-0001, marked FAKE).
KEV_KEEP = {"CVE-2026-102490", "CVE-2026-102489", "CVE-2026-59310"}
kev = load("reports/kev.json")
entries = [v for v in kev["vulnerabilities"] if v["cveID"] in KEV_KEEP]
fake = {**entries[0], "cveID": "CVE-2099-0001", "vendorProject": "FAKE (test fixture)",
        "product": "Fake product", "vulnerabilityName": "FAKE test-only entry, not a real vulnerability",
        "shortDescription": "Synthetic entry for triage tests. Not a CISA KEV listing.",
        "knownRansomwareCampaignUse": "Unknown", "notes": ""}
save(OUT / "kev.json", {"title": kev["title"], "catalogVersion": kev["catalogVersion"],
                        "dateReleased": kev["dateReleased"], "count": len(entries) + 1,
                        "vulnerabilities": entries + [fake]})
```

## Checks run

- Rebuilding from the README `trim.py` block reproduces every fixture byte for byte.
- Gitleaks scan of the repo: not run locally (no gitleaks binary or Docker in the sandbox). Run it in CI or with the pinned image before merging.

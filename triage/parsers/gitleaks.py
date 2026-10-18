"""Gitleaks JSON from the CI job (Secret is already sha256:<hex>, Match is REDACTED) -> Finding (secret)."""

from __future__ import annotations

from pathlib import Path

from triage.model import Finding, ParseError, map_severity
from triage.parsers.common import load_json, require_keys

REQUIRED = ("RuleID", "File", "StartLine", "Match", "Secret")


def parse_gitleaks(path: Path) -> list[Finding]:
    doc = load_json(path)
    if not isinstance(doc, list):
        raise ParseError(f"{path}: expected a JSON list of findings")
    findings: list[Finding] = []
    for i, entry in enumerate(doc):
        where = f"{path}[{i}]"
        require_keys(entry, REQUIRED, where)
        # Refuse anything that is not the CI-hashed form. Never store or print a raw secret.
        if entry["Match"] != "REDACTED":
            raise ParseError(f"{where}: Match is not REDACTED; this is not the CI report")
        secret = entry["Secret"]
        if not isinstance(secret, str) or not secret.startswith("sha256:"):
            raise ParseError(f"{where}: Secret is not a sha256 hash; refusing to read it")
        rule, file, line = entry["RuleID"], entry["File"], entry["StartLine"]
        findings.append(Finding(
            tool="gitleaks",
            rule_id=rule,
            category="secret",
            severity=map_severity("gitleaks", None),
            location=f"{file}:{line}",
            # D5: rule + file + sha256(secret). No commit: the same secret in two commits counts once.
            fingerprint=f"secret:{rule}:{file}:{secret}",
            tools=["gitleaks"],
            sources=["gitleaks"],
        ))
    return findings

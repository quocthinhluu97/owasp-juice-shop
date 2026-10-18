"""Semgrep JSON (semgrep.json, not SARIF) -> Finding (code, or secret for generic.secrets.*)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from triage.model import Finding, ParseError, map_severity
from triage.parsers.common import load_json, require_keys


def parse_semgrep(path: Path) -> list[Finding]:
    doc = load_json(path)
    require_keys(doc, ("results",), str(path))
    if not isinstance(doc["results"], list):
        raise ParseError(f"{path}: results is not a list")
    return [_finding(r, path) for r in doc["results"]]


def _finding(r: dict[str, Any], path: Path) -> Finding:
    where = f"{path}: result"
    require_keys(r, ("check_id", "path", "start", "extra"), where)
    require_keys(r["start"], ("line",), where)
    require_keys(r["extra"], ("severity",), where)
    rule, file, line = r["check_id"], r["path"], r["start"]["line"]
    cwes = (r["extra"].get("metadata") or {}).get("cwe") or []
    # metadata.cwe is a list of "CWE-798: Use of Hard-coded Credentials" strings.
    cwe = cwes[0].split(":", 1)[0].strip() if cwes else None
    # D6: generic.secrets.* is a secret. It merges into the Gitleaks finding at the same file and line (dedupe.py).
    category = "secret" if rule.startswith("generic.secrets.") else "code"
    return Finding(
        tool="semgrep",
        rule_id=rule,
        category=category,
        severity=map_severity("semgrep", r["extra"]["severity"]),
        location=f"{file}:{line}",
        cwe=cwe,
        # D5: tool:rule_id + path + start line.
        fingerprint=f"code:semgrep:{rule}:{file}:{line}",
        tools=["semgrep"],
        sources=["semgrep"],
    )

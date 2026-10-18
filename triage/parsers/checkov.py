"""Checkov JSON (checkov/results_json.json) -> Finding (iac), failed checks only.

Checkov writes a list of per-framework objects, but a single object when only one framework has
results, and a summary-only object when none do (D13). All three shapes are accepted.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from triage.model import Finding, ParseError, map_severity
from triage.parsers.common import load_json, require_keys


def parse_checkov(path: Path) -> list[Finding]:
    doc = load_json(path)
    if isinstance(doc, list):
        if not doc:
            raise ParseError(f"{path}: empty list; Checkov always writes at least one framework object")
        objects = doc
    elif isinstance(doc, dict):
        objects = [doc]
    else:
        raise ParseError(f"{path}: expected a JSON object or list")

    findings: list[Finding] = []
    for obj in objects:
        if not isinstance(obj, dict):
            raise ParseError(f"{path}: framework entry is not an object")
        if "results" not in obj:
            # Summary-only object: a framework that ran and found nothing to report.
            require_keys(obj, ("summary",), f"{path}: framework entry")
            continue
        require_keys(obj["results"], ("failed_checks",), f"{path}: results")
        if not isinstance(obj["results"]["failed_checks"], list):
            raise ParseError(f"{path}: failed_checks is not a list")
        findings.extend(_finding(c, path) for c in obj["results"]["failed_checks"])
    return findings


def _finding(c: dict[str, Any], path: Path) -> Finding:
    where = f"{path}: failed check"
    require_keys(c, ("check_id", "file_path", "file_line_range"), where)
    if not isinstance(c["file_line_range"], list) or not c["file_line_range"]:
        raise ParseError(f"{where}: file_line_range is empty")
    check, file, line = c["check_id"], c["file_path"], c["file_line_range"][0]
    return Finding(
        tool="checkov",
        rule_id=check,
        category="iac",
        # severity is always null in Checkov's JSON, so D3 maps it to info. Rule 5 gates by check ID.
        severity=map_severity("checkov", c.get("severity")),
        location=f"{file}:{line}",
        # D5: check_id + file_path + first line of file_line_range. file_path keeps Checkov's leading "/".
        fingerprint=f"iac:{check}:{file}:{line}",
        tools=["checkov"],
        sources=["checkov"],
    )

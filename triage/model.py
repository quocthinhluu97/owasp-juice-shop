"""Common Finding model and the explicit per-tool severity mapping (phase-7-triage.md D3)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

Category = Literal["secret", "vuln", "code", "iac", "dast"]
Severity = Literal["critical", "high", "medium", "low", "info"]

CATEGORIES: frozenset[str] = frozenset({"secret", "vuln", "code", "iac", "dast"})
SEVERITIES: frozenset[str] = frozenset({"critical", "high", "medium", "low", "info"})


class UnknownSeverityError(ValueError):
    """A tool reported a severity value that has no explicit mapping. The CLI turns this into exit 2."""


class ParseError(ValueError):
    """A report is missing, unparseable, or lacks a required key. The CLI turns this into exit 2."""


@dataclass
class Finding:
    """One normalized finding. Fingerprint rules are in triage-script.md and D5."""

    tool: str
    rule_id: str
    category: Category
    severity: Severity
    location: str
    fingerprint: str
    cve: str | None = None
    cwe: str | None = None
    # Trivy: fix versions when Status is fixed (split on ",", stripped). Empty list = no fix (D8).
    fixed_version: list[str] = field(default_factory=list)
    # Trivy fs only: "direct" / "indirect" from the lockfile join, the name@version IDs of the
    # packages that list this one in DependsOn (immediate parents), and the direct ancestors reached
    # by walking DependsOn up (a direct package is its own top parent). A "?name@version" entry marks a
    # dead end in the walk (the chain is incomplete, not resolved). None / [] when unknown.
    relationship: str | None = None
    parents: list[str] = field(default_factory=list)
    top_parents: list[str] = field(default_factory=list)
    # Vulns only, set by enrich.py: CVE in CISA KEV ("in_kev"), not in it ("not_in_kev"), or an ID KEV
    # does not list (GHSA-/NSWG-, reported as "not checkable", never as "not in KEV"). None for other categories.
    kev: str | None = None
    # ZAP only (D20): the alert's instances as "path [param=x]", deduped and sorted. For the report only;
    # never part of the fingerprint, because ZAP caps and reselects instances between runs.
    instances: list[str] = field(default_factory=list)
    # ZAP only: the alert names folded into this finding. One pluginid can carry variants with different
    # names (e.g. 90004-2 / 90004-3); every distinct name is kept, none is dropped by the merge.
    names: list[str] = field(default_factory=list)
    # Reachability labels (reachability.py). Never gating by themselves.
    hints: list[str] = field(default_factory=list)
    # Every tool that reported this finding, and where (e.g. trivy-fs:app/package-lock.json).
    # Filled in by dedupe; a fresh finding has one entry each.
    tools: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.category not in CATEGORIES:
            raise ValueError(f"unknown category: {self.category!r}")
        if self.severity not in SEVERITIES:
            raise ValueError(f"unknown severity: {self.severity!r}")


# Explicit maps. Keys are the exact raw values the tool writes; no case folding, no guessing.
_TRIVY: dict[str | None, Severity] = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "UNKNOWN": "info",
}
_SEMGREP: dict[str | None, Severity] = {
    "CRITICAL": "critical",
    "ERROR": "high",  # legacy alias of HIGH
    "HIGH": "high",
    "WARNING": "medium",  # legacy alias of MEDIUM
    "MEDIUM": "medium",
    "INFO": "low",  # legacy alias of LOW
    "LOW": "low",
}
_CHECKOV: dict[str | None, Severity] = {
    None: "info",  # Checkov gives no severity; rule 5 gates by check ID, not severity
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "INFO": "info",
}
# ZAP riskcode is a string in the JSON ("0".."3").
_ZAP: dict[str | None, Severity] = {
    "3": "high",
    "2": "medium",
    "1": "low",
    "0": "info",
}


def map_severity(tool: str, raw: str | None) -> Severity:
    """Map a tool's raw severity value to the common scale. Unknown tool or value raises UnknownSeverityError."""
    if tool == "gitleaks":
        # Gitleaks has no severity field. Every secret is high; rule 1 gates it regardless.
        return "high"
    tables = {"trivy": _TRIVY, "semgrep": _SEMGREP, "checkov": _CHECKOV, "zap": _ZAP}
    table = tables.get(tool)
    if table is None:
        raise UnknownSeverityError(f"no severity mapping for tool {tool!r}")
    if raw not in table:
        raise UnknownSeverityError(f"{tool}: unmapped severity value {raw!r}")
    return table[raw]

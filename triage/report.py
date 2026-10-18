"""Output (D16): the summary for stdout and $GITHUB_STEP_SUMMARY, and reports/triage.json.

Blocking findings come first, each with its rule, why and next step. Waived, expired and warnings follow.
The summary is capped well under the 1 MiB step-summary limit; triage.json always has every finding.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from triage.model import Finding
from triage.policy import Verdict
from triage.waivers import Waiver

SUMMARY_ROW_CAP = 200  # rows shown per section; the rest are in triage.json
SUMMARY_BYTE_LIMIT = 900_000  # GitHub's limit is 1 MiB per step; stay well under it
CELL_CHARS = 300  # longest text in a table cell


@dataclass
class Result:
    generated_at: datetime
    exit_code: int
    before: dict[tuple[str, str], int]  # (tool, category) -> count before dedupe
    after: dict[tuple[str, str], int]  # (tool, category) -> count after dedupe
    verdicts: list[tuple[Finding, Verdict]]  # every active finding with its verdict
    waived: list[tuple[Finding, Waiver]]
    expired: list[Waiver]
    warnings: list[str] = field(default_factory=list)
    kev_source: str = ""
    kev_version: str = ""

    @property
    def blocking(self) -> list[tuple[Finding, Verdict]]:
        return [(f, v) for f, v in self.verdicts if v.blocking]

    @property
    def not_gating(self) -> list[tuple[Finding, Verdict]]:
        return [(f, v) for f, v in self.verdicts if not v.blocking]


def counts(findings: list[Finding]) -> dict[tuple[str, str], int]:
    out: dict[tuple[str, str], int] = {}
    for f in findings:
        key = (f.tool, f.category)
        out[key] = out.get(key, 0) + 1
    return dict(sorted(out.items()))


def _cell(text: Any) -> str:
    s = str(text).replace("\r", " ").replace("\n", " ").replace("|", "\\|")
    return s if len(s) <= CELL_CHARS else s[: CELL_CHARS - 3] + "..."


def _finding_id(f: Finding) -> str:
    return f.cve or f.rule_id


SUMMARY_INSTANCE_CAP = 5  # ZAP rows show this many instances; triage.json has them all


def _location_cell(f: Finding) -> str:
    """A ZAP row shows its site and a capped list of instances (D20). Other rows show the location."""
    if f.category != "dast":
        return f.location
    variants = f"variants: {' | '.join(f.names)}; " if len(f.names) > 1 else ""
    if not f.instances:
        return f"{variants}{f.location}"
    shown = ", ".join(f.instances[:SUMMARY_INSTANCE_CAP])
    more = f" (+{len(f.instances) - SUMMARY_INSTANCE_CAP} more)" if len(f.instances) > SUMMARY_INSTANCE_CAP else ""
    return f"{variants}{f.location}: {shown}{more}"


def render_markdown(result: Result) -> str:
    """The summary used on stdout and in $GITHUB_STEP_SUMMARY. Capped by row count and by bytes."""
    lines: list[str] = []
    status = "FAILED" if result.blocking else "PASSED"
    lines.append("## Triage")
    lines.append("")
    lines.append(f"**Gate {status}**: {len(result.blocking)} blocking finding(s). Exit code {result.exit_code}.")
    lines.append(f"Every finding is in `reports/triage.json`. KEV: {result.kev_source or 'not loaded'}"
                 f"{' (catalog ' + result.kev_version + ')' if result.kev_version else ''}.")
    lines.append("")

    lines.append("### Counts (before and after dedupe)")
    lines.append("")
    lines.append("| tool | category | before | after |")
    lines.append("|---|---|---:|---:|")
    for key in sorted(set(result.before) | set(result.after)):
        lines.append(f"| {key[0]} | {key[1]} | {result.before.get(key, 0)} | {result.after.get(key, 0)} |")
    lines.append("")

    blocking = result.blocking
    lines.append(f"### Blocking ({len(blocking)})")
    lines.append("")
    if blocking:
        lines.append("| rule | location | id | why | next step |")
        lines.append("|---|---|---|---|---|")
        for f, v in blocking[:SUMMARY_ROW_CAP]:
            lines.append(f"| {v.rule} | {_cell(_location_cell(f))} | {_cell(_finding_id(f))} | {_cell(v.why)} | {_cell(v.next_step)} |")
        if len(blocking) > SUMMARY_ROW_CAP:
            lines.append(f"\n{len(blocking) - SUMMARY_ROW_CAP} more blocking finding(s) not shown; see reports/triage.json.")
    else:
        lines.append("None.")
    lines.append("")

    lines.append(f"### Waived ({len(result.waived)})")
    lines.append("")
    if result.waived:
        lines.append("| id | location | reason | owner | expires |")
        lines.append("|---|---|---|---|---|")
        for f, w in result.waived[:SUMMARY_ROW_CAP]:
            lines.append(f"| {_cell(_finding_id(f))} | {_cell(f.location)} | {_cell(w.reason)} | {_cell(w.owner)} | {w.expires.isoformat()} |")
        if len(result.waived) > SUMMARY_ROW_CAP:
            lines.append(f"\n{len(result.waived) - SUMMARY_ROW_CAP} more waived finding(s) not shown.")
    else:
        lines.append("None.")
    lines.append("")

    lines.append(f"### Expired waivers, not applied ({len(result.expired)})")
    lines.append("")
    for w in result.expired[:SUMMARY_ROW_CAP]:
        lines.append(f"- {_cell(w.label())}: the finding blocks again until it is renewed or removed.")
    if not result.expired:
        lines.append("None.")
    lines.append("")

    lines.append(f"### Warnings ({len(result.warnings)})")
    lines.append("")
    for w in result.warnings[:SUMMARY_ROW_CAP]:
        lines.append(f"- {_cell(w)}")
    if not result.warnings:
        lines.append("None.")
    lines.append("")

    not_gating = len(result.not_gating)
    lines.append(f"Not gating (report only): {not_gating} finding(s); see reports/triage.json for each reason.")
    text = "\n".join(lines) + "\n"
    if len(text.encode("utf-8")) > SUMMARY_BYTE_LIMIT:
        text = text.encode("utf-8")[:SUMMARY_BYTE_LIMIT].decode("utf-8", errors="ignore")
        text += "\n\n(summary truncated to stay under the step-summary limit; see reports/triage.json)\n"
    return text


def _finding_json(f: Finding, v: Verdict | None) -> dict[str, Any]:
    return {
        "tool": f.tool,
        "rule_id": f.rule_id,
        "category": f.category,
        "severity": f.severity,
        "location": f.location,
        "cve": f.cve,
        "cwe": f.cwe,
        "fixed_version": f.fixed_version,
        "relationship": f.relationship,
        "parents": f.parents,
        "instances": f.instances,
        "names": f.names,
        "top_parents": f.top_parents,
        "kev": f.kev,
        "hints": f.hints,
        "tools": f.tools,
        "sources": f.sources,
        "fingerprint": f.fingerprint,
        "verdict": None if v is None else {
            "blocking": v.blocking, "rule": v.rule, "why": v.why, "next_step": v.next_step,
        },
    }


def _waiver_json(w: Waiver) -> dict[str, Any]:
    return {"index": w.index, "fingerprint": w.fingerprint, "cve": w.cve, "package": w.package,
            "reason": w.reason, "owner": w.owner, "expires": w.expires.isoformat()}


def to_json(result: Result) -> dict[str, Any]:
    return {
        "generated_at": result.generated_at.isoformat(),
        "exit_code": result.exit_code,
        "gate": "fail" if result.blocking else "pass",
        "blocking": len(result.blocking),
        "counts": {
            "before": [{"tool": k[0], "category": k[1], "count": n} for k, n in result.before.items()],
            "after": [{"tool": k[0], "category": k[1], "count": n} for k, n in result.after.items()],
        },
        "kev": {"catalog_version": result.kev_version, "source": result.kev_source},
        "findings": [_finding_json(f, v) for f, v in result.verdicts],
        "waived": [{"finding": _finding_json(f, None), "waiver": _waiver_json(w)} for f, w in result.waived],
        "expired": [_waiver_json(w) for w in result.expired],
        "warnings": result.warnings,
    }


def write_json(result: Result, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(to_json(result), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def append_step_summary(text: str, env_path: str) -> None:
    with open(env_path, "a", encoding="utf-8") as fh:
        fh.write(text)

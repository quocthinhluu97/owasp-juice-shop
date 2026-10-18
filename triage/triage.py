#!/usr/bin/env python3
"""Triage CLI (D2, D16): parse the scanner reports, dedupe, enrich, apply waivers, gate, report.

Exit codes: 0 pass, 1 gate failed (a blocking finding), 2 the script could not do its job
(missing or unparseable report, bad waiver or rules file, no usable KEV feed, any other error).
"""

import sys
from pathlib import Path

# Run as `python3 triage/triage.py`: sys.path[0] is then triage/, where this file would shadow the
# triage package. Put the repo root first instead. Not done on import (tests import this module).
if __name__ == "__main__":
    sys.path[0] = str(Path(__file__).resolve().parents[1])

import argparse  # noqa: E402
import os  # noqa: E402
from datetime import datetime, timezone  # noqa: E402

from triage.dedupe import dedupe  # noqa: E402
from triage.enrich import annotate_kev, get_kev  # noqa: E402
from triage.model import Finding, ParseError, UnknownSeverityError  # noqa: E402
from triage.parsers.checkov import parse_checkov  # noqa: E402
from triage.parsers.gitleaks import parse_gitleaks  # noqa: E402
from triage.parsers.semgrep import parse_semgrep  # noqa: E402
from triage.parsers.trivy import parse_trivy  # noqa: E402
from triage.parsers.zap import parse_rules, parse_zap  # noqa: E402
from triage.policy import evaluate  # noqa: E402
from triage.reachability import add_hints  # noqa: E402
from triage.report import Result, append_step_summary, counts, render_markdown, write_json  # noqa: E402
from triage.waivers import apply_waivers, load_waivers  # noqa: E402

EXIT_PASS, EXIT_GATE, EXIT_ERROR = 0, 1, 2


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="triage", description="Gate the build on the scanner reports (phase 7).")
    p.add_argument("reports_dir", type=Path, help="directory with gitleaks.json, trivy-*.json, semgrep.json, checkov/, zap/")
    p.add_argument("--waivers", type=Path, default=Path("triage/waivers.yaml"), help="waiver file (default: %(default)s)")
    p.add_argument("--zap-rules", type=Path, default=Path(".zap/rules.tsv"), help="ZAP levels (default: %(default)s)")
    p.add_argument("--app", type=Path, default=Path("app"), help="app directory for reachability hints (default: %(default)s)")
    p.add_argument("--kev-file", type=Path, default=None, help="use this KEV catalog as-is (tests, local runs)")
    p.add_argument("--offline", action="store_true", help="do not download KEV; use the cache if it is usable")
    p.add_argument("--cache-dir", type=Path, default=Path("triage/.cache"), help="KEV cache (default: %(default)s)")
    return p


def report_paths(reports: Path) -> dict[str, Path]:
    return {
        "gitleaks": reports / "gitleaks.json",
        "trivy-image": reports / "trivy-image.json",
        "trivy-fs": reports / "trivy-fs.json",
        "semgrep": reports / "semgrep.json",
        "checkov": reports / "checkov" / "results_json.json",
        "zap": reports / "zap" / "zap.json",
    }


def parse_all(reports: Path) -> list[Finding]:
    paths = report_paths(reports)
    missing = [str(p) for p in paths.values() if not p.is_file()]
    if missing:
        raise ParseError("missing report file(s), the scan job may not have produced them: " + ", ".join(missing))
    findings: list[Finding] = []
    findings += parse_gitleaks(paths["gitleaks"])
    findings += parse_trivy(paths["trivy-image"], "image")
    findings += parse_trivy(paths["trivy-fs"], "fs")
    findings += parse_semgrep(paths["semgrep"])
    findings += parse_checkov(paths["checkov"])
    findings += parse_zap(paths["zap"])
    return findings


def run(args: argparse.Namespace, now: datetime) -> Result:
    raw = parse_all(args.reports_dir)
    before = counts(raw)
    findings = dedupe(raw)
    zap_rules = parse_rules(args.zap_rules)
    kev = get_kev(args.cache_dir, now, offline=args.offline, kev_file=args.kev_file)
    annotate_kev(findings, kev)
    add_hints(findings, args.app)
    today = now.date()
    waivers = load_waivers(args.waivers, today)
    waiver_result = apply_waivers(findings, waivers, today)
    verdicts = evaluate(waiver_result.active, zap_rules)
    blocking = any(v.blocking for _, v in verdicts)
    return Result(
        generated_at=now,
        exit_code=EXIT_GATE if blocking else EXIT_PASS,
        before=before,
        after=counts(findings),
        verdicts=verdicts,
        waived=waiver_result.waived,
        expired=waiver_result.expired,
        warnings=kev.warnings + waiver_result.warnings,
        kev_source=kev.source,
        kev_version=kev.catalog_version,
    )


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    now = datetime.now(timezone.utc)
    try:
        result = run(args, now)
        write_json(result, args.reports_dir / "triage.json")
        text = render_markdown(result)
    except (ParseError, UnknownSeverityError) as exc:
        msg = f"triage: error: {exc}"
        print(msg, file=sys.stderr)
        if summary_path:
            append_step_summary(f"## Triage: error (exit {EXIT_ERROR})\n\n{exc}\n", summary_path)
        return EXIT_ERROR
    except Exception as exc:  # any other failure is a script error: exit 2, never a silent pass
        msg = f"triage: error: unexpected {type(exc).__name__}: {exc}"
        print(msg, file=sys.stderr)
        if summary_path:
            append_step_summary(f"## Triage: error (exit {EXIT_ERROR})\n\n{type(exc).__name__}: {exc}\n", summary_path)
        return EXIT_ERROR
    print(text, end="")
    if summary_path:
        append_step_summary(text, summary_path)
    return result.exit_code


if __name__ == "__main__":
    sys.exit(main())

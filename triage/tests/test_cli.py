"""CLI and report (D2, D16): exit codes 0/1/2, step summary, size cap, and an end-to-end run on the fixtures."""

import copy
import json
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

from triage import report
from triage.model import Finding
from triage.policy import Verdict
from triage.triage import main
from triage.waivers import Waiver

REPO = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).parent / "fixtures"
ZAP_RULES = REPO / ".zap" / "rules.tsv"


def _reports(tmp_path: Path) -> Path:
    """A reports/ tree with the fixture reports in the layout D2 expects."""
    reports = tmp_path / "reports"
    (reports / "checkov").mkdir(parents=True)
    (reports / "zap").mkdir(parents=True)
    for name in ("gitleaks.json", "trivy-image.json", "trivy-fs.json", "semgrep.json"):
        shutil.copy(FIXTURES / name, reports / name)
    shutil.copy(FIXTURES / "checkov" / "results_json.json", reports / "checkov" / "results_json.json")
    shutil.copy(FIXTURES / "zap" / "zap.json", reports / "zap" / "zap.json")
    return reports


def _args(tmp_path: Path, reports: Path, *extra: str) -> list[str]:
    app = tmp_path / "app"
    app.mkdir(exist_ok=True)
    waivers = tmp_path / "waivers.yaml"
    if not waivers.exists():
        waivers.write_text("waivers: []\n", encoding="utf-8")
    return [
        str(reports),
        "--waivers", str(waivers),
        "--zap-rules", str(ZAP_RULES),
        "--app", str(app),
        "--kev-file", str(FIXTURES / "kev.json"),
        "--offline",
        "--cache-dir", str(tmp_path / "cache"),
        *extra,
    ]


def _write_json(path: Path, doc) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc), encoding="utf-8")


def _clean_reports(tmp_path: Path) -> Path:
    reports = tmp_path / "reports"
    _write_json(reports / "gitleaks.json", [])
    _write_json(reports / "trivy-image.json", {"ArtifactType": "container_image", "Results": []})
    _write_json(reports / "trivy-fs.json", {"ArtifactType": "filesystem", "Results": []})
    _write_json(reports / "semgrep.json", {"results": [], "errors": []})
    _write_json(reports / "checkov" / "results_json.json",
                [{"check_type": "dockerfile", "results": {"failed_checks": [], "passed_checks": []}}])
    _write_json(reports / "zap" / "zap.json", {"site": []})
    return reports


# exit 1 and the end-to-end run on the fixtures

def test_end_to_end_on_fixtures_exits_1_and_writes_everything(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    reports = _reports(tmp_path)
    code = main(_args(tmp_path, reports))
    out = capsys.readouterr().out
    assert code == 1
    assert "**Gate FAILED**: 12 blocking finding(s)" in out
    assert "| rule 1 | app/ctf.key:0 |" in out
    assert "| rule 3 | @fastify/busboy@2.1.1 |" in out
    assert "| rule 6 | http://juice:3000: /redirect [param=to] |" in out
    doc = json.loads((reports / "triage.json").read_text(encoding="utf-8"))
    assert doc["gate"] == "fail" and doc["blocking"] == 12 and doc["exit_code"] == 1
    assert len(doc["findings"]) == 32  # after dedupe: 6 + 8 + 9 + 3 + 6


def test_end_to_end_counts_before_and_after_dedupe(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    reports = _reports(tmp_path)
    main(_args(tmp_path, reports))
    doc = json.loads((reports / "triage.json").read_text(encoding="utf-8"))
    before = {(c["tool"], c["category"]): c["count"] for c in doc["counts"]["before"]}
    after = {(c["tool"], c["category"]): c["count"] for c in doc["counts"]["after"]}
    assert before[("trivy", "vuln")] == 12 and after[("trivy", "vuln")] == 8
    assert before[("zap", "dast")] == 6 and after[("zap", "dast")] == 6  # one per alert (D20)
    assert before[("semgrep", "secret")] == 1 and ("semgrep", "secret") not in after


def test_every_finding_has_a_verdict_with_rule_why_and_next_step(tmp_path, monkeypatch):
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    reports = _reports(tmp_path)
    main(_args(tmp_path, reports))
    doc = json.loads((reports / "triage.json").read_text(encoding="utf-8"))
    for f in doc["findings"]:
        assert f["verdict"]["why"] and f["verdict"]["next_step"]


def test_step_summary_is_written_when_env_is_set(tmp_path, capsys, monkeypatch):
    summary = tmp_path / "step-summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    main(_args(tmp_path, _reports(tmp_path)))
    text = summary.read_text(encoding="utf-8")
    assert text.startswith("## Triage")
    assert "### Blocking (12)" in text and "### Counts" in text


def test_clean_reports_exit_0(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    reports = _clean_reports(tmp_path)
    code = main(_args(tmp_path, reports))
    out = capsys.readouterr().out
    assert code == 0
    assert "**Gate PASSED**: 0 blocking" in out
    assert json.loads((reports / "triage.json").read_text(encoding="utf-8"))["gate"] == "pass"


# exit 2

def test_missing_report_file_exits_2_and_names_it(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    reports = _reports(tmp_path)
    (reports / "trivy-fs.json").unlink()
    code = main(_args(tmp_path, reports))
    err = capsys.readouterr().err
    assert code == 2
    assert "missing report file" in err and "trivy-fs.json" in err


def test_missing_checkov_report_exits_2(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    reports = _reports(tmp_path)
    (reports / "checkov" / "results_json.json").unlink()
    assert main(_args(tmp_path, reports)) == 2


def test_malformed_report_exits_2(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    reports = _reports(tmp_path)
    (reports / "semgrep.json").write_text("{not json", encoding="utf-8")
    code = main(_args(tmp_path, reports))
    assert code == 2
    assert "not valid JSON" in capsys.readouterr().err


def test_unknown_severity_exits_2(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    reports = _reports(tmp_path)
    doc = json.loads((reports / "trivy-image.json").read_text(encoding="utf-8"))
    doc["Results"][0]["Vulnerabilities"][0]["Severity"] = "BOGUS"
    _write_json(reports / "trivy-image.json", doc)
    code = main(_args(tmp_path, reports))
    assert code == 2
    assert "BOGUS" in capsys.readouterr().err


def test_bad_waiver_file_exits_2(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    reports = _clean_reports(tmp_path)
    (tmp_path / "waivers.yaml").write_text("waivers:\n  - reason: x\n", encoding="utf-8")
    assert main(_args(tmp_path, reports)) == 2


def test_no_usable_kev_feed_exits_2(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    reports = _clean_reports(tmp_path)
    args = _args(tmp_path, reports)
    args.remove("--kev-file")
    args.remove(str(FIXTURES / "kev.json"))
    assert main(args) == 2  # --offline with no cache: rule 2 cannot be evaluated


def test_raw_secret_in_gitleaks_report_exits_2_and_is_not_printed(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    reports = _clean_reports(tmp_path)
    raw = "FAKE-raw-secret-0000"
    _write_json(reports / "gitleaks.json", [{
        "RuleID": "generic-api-key", "File": "app/x.ts", "StartLine": 1, "Match": raw, "Secret": raw,
        "Fingerprint": "c:app/x.ts:generic-api-key:1",
    }])
    code = main(_args(tmp_path, reports))
    captured = capsys.readouterr()
    assert code == 2
    assert raw not in captured.out and raw not in captured.err
    assert not (reports / "triage.json").exists()  # nothing is written on a script error


def test_error_writes_a_step_summary_too(tmp_path, capsys, monkeypatch):
    summary = tmp_path / "step-summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    reports = _reports(tmp_path)
    (reports / "gitleaks.json").unlink()
    assert main(_args(tmp_path, reports)) == 2
    assert "## Triage: error (exit 2)" in summary.read_text(encoding="utf-8")


def test_script_runs_as_a_file_from_the_repo_root(tmp_path):
    # `python3 triage/triage.py` puts triage/ first on sys.path; the script must still import the package.
    completed = subprocess.run(
        [sys.executable, "triage/triage.py", str(tmp_path / "nope"), "--kev-file", str(FIXTURES / "kev.json"),
         "--offline", "--cache-dir", str(tmp_path / "cache")],
        cwd=REPO, capture_output=True, text=True,
    )
    assert completed.returncode == 2
    assert "missing report file" in completed.stderr


# size cap and rendering

def _big_result(n: int) -> report.Result:
    now = datetime(2026, 10, 18, tzinfo=timezone.utc)
    long_why = "x" * 900
    verdicts = []
    for i in range(n):
        f = Finding(tool="gitleaks", rule_id="generic-api-key", category="secret", severity="high",
                    location=f"app/file{i}.ts:{i}", fingerprint=f"secret:{i}", tools=["gitleaks"],
                    sources=["gitleaks"])
        verdicts.append((f, Verdict(True, "rule 1", long_why, "rotate")))
    return report.Result(generated_at=now, exit_code=1, before={("gitleaks", "secret"): n},
                         after={("gitleaks", "secret"): n}, verdicts=verdicts, waived=[], expired=[])


def test_summary_is_capped_by_rows_and_bytes():
    text = report.render_markdown(_big_result(5000))
    assert len(text.encode("utf-8")) <= report.SUMMARY_BYTE_LIMIT + 200
    assert "more blocking finding(s) not shown" in text
    assert "### Blocking (5000)" in text


def test_summary_stays_under_one_mib_even_with_long_cells():
    text = report.render_markdown(_big_result(2000))
    assert len(text.encode("utf-8")) < 1024 * 1024


def test_table_cell_pipes_and_newlines_are_escaped():
    assert "\\|" in report._cell("a | b") and "\n" not in report._cell("a\nb")


def test_repo_waivers_file_parses():
    # The repo's waivers.yaml is the owner's file and changes over time: only check that it parses.
    from triage.waivers import load_waivers

    load_waivers(REPO / "triage" / "waivers.yaml", datetime.now(timezone.utc).date())


def test_zap_row_shows_capped_instances_in_summary():
    f = Finding(tool="zap", rule_id="10038", category="dast", severity="medium", location="http://juice:3000",
                fingerprint="dast:10038:http://juice:3000",
                instances=[f"/p{i}" for i in range(8)], tools=["zap"], sources=["zap"])
    cell = report._location_cell(f)
    assert cell.startswith("http://juice:3000: /p0, /p1, /p2, /p3, /p4 (+3 more)")

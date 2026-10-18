"""Semgrep parser against the trimmed semgrep.json. Counts come from the raw results list."""

import copy
import json
from pathlib import Path

import pytest

from triage.model import ParseError
from triage.parsers.semgrep import parse_semgrep

FIXTURE = Path(__file__).parent / "fixtures" / "semgrep.json"


def _raw():
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def _by_location(findings):
    return {f.location: f for f in findings}


def test_one_finding_per_result():
    assert len(parse_semgrep(FIXTURE)) == len(_raw()["results"]) == 10


@pytest.mark.parametrize(
    ("location", "expected"),
    [
        ("app/.npmrc:1", "medium"),  # MEDIUM
        ("app/data/static/users.yml:151", "high"),  # ERROR
        ("app/frontend/src/hacking-instructor/helpers/helpers.ts:49", "medium"),  # WARNING
        ("app/routes/login.ts:34", "high"),  # ERROR
        ("app/server.ts:157", "low"),  # INFO
    ],
)
def test_severity_per_mapped_value(location, expected):
    assert _by_location(parse_semgrep(FIXTURE))[location].severity == expected


def test_generic_secret_is_category_secret_others_are_code():
    findings = parse_semgrep(FIXTURE)
    secrets = [f for f in findings if f.category == "secret"]
    assert [f.location for f in secrets] == ["app/data/static/users.yml:151"]
    assert secrets[0].rule_id.startswith("generic.secrets.")
    assert {f.category for f in findings} == {"secret", "code"}
    assert sum(f.category == "code" for f in findings) == 9


def test_cwe_is_the_id_before_the_colon():
    by = _by_location(parse_semgrep(FIXTURE))
    assert by["app/data/static/users.yml:151"].cwe == "CWE-798"
    assert by["app/.npmrc:1"].cwe == "CWE-829"


def test_fingerprint_is_tool_rule_path_line():
    f = _by_location(parse_semgrep(FIXTURE))["app/routes/login.ts:34"]
    assert f.fingerprint == f"code:semgrep:{f.rule_id}:app/routes/login.ts:34"
    assert f.tools == ["semgrep"] and f.sources == ["semgrep"]


def test_missing_severity_is_parse_error(tmp_path):
    doc = copy.deepcopy(_raw())
    del doc["results"][0]["extra"]["severity"]
    p = tmp_path / "semgrep.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    with pytest.raises(ParseError, match="severity"):
        parse_semgrep(p)


def test_missing_results_is_parse_error(tmp_path):
    p = tmp_path / "semgrep.json"
    p.write_text(json.dumps({"errors": []}), encoding="utf-8")
    with pytest.raises(ParseError, match="results"):
        parse_semgrep(p)


def test_missing_file_is_parse_error(tmp_path):
    with pytest.raises(ParseError):
        parse_semgrep(tmp_path / "missing.json")

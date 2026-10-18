"""Checkov parser: the three JSON shapes (D13), failed checks only. Counts come from raw failed_checks lists."""

import copy
import json
from pathlib import Path

import pytest

from triage.model import ParseError
from triage.parsers.checkov import parse_checkov

FIXTURE = Path(__file__).parent / "fixtures" / "checkov" / "results_json.json"
SUMMARY_ONLY = {"summary": {"passed": 0, "failed": 0, "skipped": 0, "parsing_errors": 0,
                            "resource_count": 0, "checkov_version": "3.3.22"}}


def _raw():
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def _failed_in(objects):
    return sum(len(o["results"]["failed_checks"]) for o in objects if "results" in o)


def _write(tmp_path, doc):
    p = tmp_path / "results_json.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    return p


def test_list_shape_counts_failed_checks_of_every_framework():
    doc = _raw()
    assert isinstance(doc, list) and len(doc) == 2
    assert len(parse_checkov(FIXTURE)) == _failed_in(doc) == 3


def test_failed_checks_only_passed_are_not_findings():
    ids = sorted(f.rule_id for f in parse_checkov(FIXTURE))
    assert ids == ["CKV_DOCKER_2", "CKV_DOCKER_2", "CKV_DOCKER_7"]


def test_location_and_fingerprint_use_first_line_of_range():
    by = {f.fingerprint: f for f in parse_checkov(FIXTURE)}
    assert "iac:CKV_DOCKER_7:/app/Dockerfile:22" in by
    f = by["iac:CKV_DOCKER_7:/app/Dockerfile:22"]
    assert f.location == "/app/Dockerfile:22"
    assert f.category == "iac" and f.tool == "checkov"


def test_null_severity_maps_to_info():
    assert {f.severity for f in parse_checkov(FIXTURE)} == {"info"}


def test_single_object_shape(tmp_path):
    dockerfile = _raw()[0]
    assert dockerfile["check_type"] == "dockerfile"
    findings = parse_checkov(_write(tmp_path, dockerfile))
    assert len(findings) == len(dockerfile["results"]["failed_checks"]) == 3


def test_single_object_with_no_failures_is_zero(tmp_path):
    github = _raw()[1]
    assert github["check_type"] == "github_actions"
    assert parse_checkov(_write(tmp_path, github)) == []


def test_summary_only_object_is_zero(tmp_path):
    assert parse_checkov(_write(tmp_path, SUMMARY_ONLY)) == []


def test_list_with_summary_only_entry_is_zero(tmp_path):
    assert parse_checkov(_write(tmp_path, [SUMMARY_ONLY])) == []


def test_synthetic_failed_check_in_single_object(tmp_path):
    # Synthetic check, obviously fake path, to show the parser reads failed_checks of a lone object.
    check = copy.deepcopy(_raw()[0]["results"]["failed_checks"][0])
    check["file_path"] = "/fake/Dockerfile"
    check["file_line_range"] = [7, 7]
    doc = {"check_type": "dockerfile", "results": {"failed_checks": [check], "passed_checks": []}}
    (f,) = parse_checkov(_write(tmp_path, doc))
    assert f.fingerprint == f"iac:{check['check_id']}:/fake/Dockerfile:7"


def test_empty_list_is_parse_error(tmp_path):
    with pytest.raises(ParseError, match="empty"):
        parse_checkov(_write(tmp_path, []))


def test_object_with_neither_results_nor_summary_is_parse_error(tmp_path):
    with pytest.raises(ParseError, match="summary"):
        parse_checkov(_write(tmp_path, {"check_type": "dockerfile"}))


def test_missing_failed_checks_is_parse_error(tmp_path):
    with pytest.raises(ParseError, match="failed_checks"):
        parse_checkov(_write(tmp_path, {"results": {"passed_checks": []}}))


def test_failed_check_without_file_path_is_parse_error(tmp_path):
    check = copy.deepcopy(_raw()[0]["results"]["failed_checks"][0])
    del check["file_path"]
    with pytest.raises(ParseError, match="file_path"):
        parse_checkov(_write(tmp_path, {"results": {"failed_checks": [check]}}))


def test_missing_file_is_parse_error(tmp_path):
    with pytest.raises(ParseError):
        parse_checkov(tmp_path / "missing.json")

"""Severity mapping (D3) and the Finding model. Every mapped value of every tool, plus an unknown value per tool."""

import pytest

from triage.model import Finding, UnknownSeverityError, map_severity


@pytest.mark.parametrize("raw", [None, "", "HIGH", "critical", "anything"])
def test_gitleaks_every_finding_is_high(raw):
    assert map_severity("gitleaks", raw) == "high"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("CRITICAL", "critical"),
        ("HIGH", "high"),
        ("MEDIUM", "medium"),
        ("LOW", "low"),
        ("UNKNOWN", "info"),
    ],
)
def test_trivy_mapped_values(raw, expected):
    assert map_severity("trivy", raw) == expected


def test_trivy_unknown_value_raises():
    with pytest.raises(UnknownSeverityError, match="BOGUS"):
        map_severity("trivy", "BOGUS")


def test_trivy_lowercase_is_not_guessed():
    with pytest.raises(UnknownSeverityError):
        map_severity("trivy", "high")


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("CRITICAL", "critical"),
        ("ERROR", "high"),
        ("HIGH", "high"),
        ("WARNING", "medium"),
        ("MEDIUM", "medium"),
        ("INFO", "low"),
        ("LOW", "low"),
    ],
)
def test_semgrep_mapped_values(raw, expected):
    assert map_severity("semgrep", raw) == expected


def test_semgrep_unknown_value_raises():
    with pytest.raises(UnknownSeverityError, match="FATAL"):
        map_severity("semgrep", "FATAL")


def test_semgrep_missing_value_raises():
    # Semgrep always writes extra.severity; a missing one is a broken report, not "info".
    with pytest.raises(UnknownSeverityError):
        map_severity("semgrep", None)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (None, "info"),
        ("CRITICAL", "critical"),
        ("HIGH", "high"),
        ("MEDIUM", "medium"),
        ("LOW", "low"),
        ("INFO", "info"),
    ],
)
def test_checkov_mapped_values(raw, expected):
    assert map_severity("checkov", raw) == expected


def test_checkov_unknown_value_raises():
    with pytest.raises(UnknownSeverityError, match="BOGUS"):
        map_severity("checkov", "BOGUS")


@pytest.mark.parametrize(
    ("raw", "expected"),
    [("3", "high"), ("2", "medium"), ("1", "low"), ("0", "info")],
)
def test_zap_riskcode_mapped_values(raw, expected):
    assert map_severity("zap", raw) == expected


@pytest.mark.parametrize("raw", ["4", "high", None])
def test_zap_unknown_value_raises(raw):
    with pytest.raises(UnknownSeverityError):
        map_severity("zap", raw)


def test_unknown_tool_raises():
    with pytest.raises(UnknownSeverityError, match="nessus"):
        map_severity("nessus", "HIGH")


def test_finding_defaults_and_independent_lists():
    a = Finding(tool="trivy", rule_id="CVE-2026-19481", category="vuln", severity="high",
                location="@fastify/busboy@2.1.1", fingerprint="x")
    b = Finding(tool="trivy", rule_id="CVE-2026-19481", category="vuln", severity="high",
                location="@fastify/busboy@2.1.1", fingerprint="x")
    assert a.tools == [] and a.sources == []
    a.tools.append("trivy")
    assert b.tools == []


def test_finding_rejects_unknown_category():
    with pytest.raises(ValueError, match="category"):
        Finding(tool="zap", rule_id="10038", category="web", severity="high",
                location="http://juice:3000", fingerprint="x")


def test_finding_rejects_unknown_severity():
    with pytest.raises(ValueError, match="severity"):
        Finding(tool="zap", rule_id="10038", category="dast", severity="error",
                location="http://juice:3000", fingerprint="x")

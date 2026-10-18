"""ZAP parser (one Finding per alert per site, D20) and the rules.tsv parser (D14). Counts come from raw alerts and instances."""

import copy
import json
from pathlib import Path

import pytest

from triage.model import ParseError
from triage.parsers.zap import parse_rules, parse_zap

REPO = Path(__file__).resolve().parents[2]
FIXTURE = Path(__file__).parent / "fixtures" / "zap" / "zap.json"
RULES = REPO / ".zap" / "rules.tsv"


def _raw():
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def _alerts(doc):
    return [(site, alert) for site in doc["site"] for alert in site["alerts"]]


def _write(tmp_path, doc):
    p = tmp_path / "zap.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    return p


def test_alert_name_is_kept_on_the_finding():
    by = {f.rule_id: f for f in parse_zap(FIXTURE)}
    doc = json.loads(FIXTURE.read_text(encoding="utf-8"))
    assert by["10038"].names == [next(a["name"] for _, a in _alerts(doc) if a["pluginid"] == "10038")]


def test_one_finding_per_alert_per_site():
    # jq: [.site[].alerts[]] | length  -> 6 (see fixtures/README.md)
    doc = _raw()
    assert len(parse_zap(FIXTURE)) == len(_alerts(doc)) == 6


def test_fingerprint_is_plugin_and_site():
    by = {f.rule_id: f for f in parse_zap(FIXTURE)}
    assert by["3"].fingerprint == "dast:3:http://juice:3000"
    assert by["10028"].fingerprint == "dast:10028:http://juice:3000"


def test_location_is_the_site():
    assert {f.location for f in parse_zap(FIXTURE)} == {"http://juice:3000"}


def test_instances_are_paths_with_params_deduped_and_sorted():
    by = {f.rule_id: f for f in parse_zap(FIXTURE)}
    # 10038-1 has "http://juice:3000" and "http://juice:3000/" (same path "/") plus three more paths.
    assert by["10038"].instances == ["/", "/ftp", "/ftp/coupons_2013.md.bak", "/sitemap.xml"]
    # Query strings are not in the instance list; the param is.
    assert by["3"].instances == ["/socket.io/ [param=sid]"]
    assert by["10028"].instances == ["/redirect [param=to]"]


def test_instances_are_not_in_the_fingerprint():
    # The fingerprint is exactly plugin + site; the instances never change it.
    for f in parse_zap(FIXTURE):
        assert f.fingerprint == f"dast:{f.rule_id}:{f.location}"


def test_severity_and_category():
    by_rule = {f.rule_id: f for f in parse_zap(FIXTURE)}
    assert by_rule["10028"].severity == "high"  # riskcode 3
    assert by_rule["10038"].severity == "medium"  # riskcode 2
    assert by_rule["10110"].severity == "low"  # riskcode 1
    assert by_rule["10049"].severity == "info"  # riskcode 0
    assert {f.category for f in parse_zap(FIXTURE)} == {"dast"}


def test_cwe_from_cweid():
    by_rule = {f.rule_id: f for f in parse_zap(FIXTURE)}
    assert by_rule["10028"].cwe == "CWE-601"


def test_two_alerts_same_plugin_and_site_share_a_fingerprint_with_different_instances(tmp_path):
    doc = copy.deepcopy(_raw())
    alert = copy.deepcopy(doc["site"][0]["alerts"][1])  # 10038-1
    alert["instances"] = [{"uri": "http://juice:3000/new-page", "param": ""}]
    doc["site"][0]["alerts"].append(alert)
    findings = [f for f in parse_zap(_write(tmp_path, doc)) if f.rule_id == "10038"]
    assert len(findings) == 2
    assert findings[0].fingerprint == findings[1].fingerprint
    assert findings[1].instances == ["/new-page"]


def test_different_sites_do_not_merge(tmp_path):
    doc = copy.deepcopy(_raw())
    other = copy.deepcopy(doc["site"][0])
    other["@name"] = "https://juice.example:443"
    other["alerts"] = other["alerts"][:1]
    doc["site"].append(other)
    findings = parse_zap(_write(tmp_path, doc))
    redirect = [f for f in findings if f.rule_id == "10028"]
    assert len(redirect) == 2
    assert redirect[0].fingerprint != redirect[1].fingerprint
    assert {f.location for f in redirect} == {"http://juice:3000", "https://juice.example:443"}


def test_site_name_without_scheme_is_parse_error(tmp_path):
    doc = copy.deepcopy(_raw())
    doc["site"][0]["@name"] = "juice:3000"
    with pytest.raises(ParseError, match="scheme"):
        parse_zap(_write(tmp_path, doc))


def test_unknown_riskcode_is_unknown_severity_error(tmp_path):
    from triage.model import UnknownSeverityError

    doc = copy.deepcopy(_raw())
    doc["site"][0]["alerts"][0]["riskcode"] = "4"
    with pytest.raises(UnknownSeverityError):
        parse_zap(_write(tmp_path, doc))


def test_missing_site_is_parse_error(tmp_path):
    with pytest.raises(ParseError, match="site"):
        parse_zap(_write(tmp_path, {"@version": "2.17.0"}))


def test_missing_instances_is_parse_error(tmp_path):
    doc = copy.deepcopy(_raw())
    del doc["site"][0]["alerts"][0]["instances"]
    with pytest.raises(ParseError, match="instances"):
        parse_zap(_write(tmp_path, doc))


# rules.tsv

def _data_rows(path):
    return [ln for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip() and not ln.startswith("#")]


def test_rules_tsv_count_matches_file():
    rules = parse_rules(RULES)
    assert len(rules) == len(_data_rows(RULES)) > 0


def test_rules_tsv_levels():
    rules = parse_rules(RULES)
    fail = {pid for pid, level in rules.items() if level == "FAIL"}
    assert fail == {"10028", "10038", "10115"}  # gating-policy.md rule 6
    assert rules["10020"] == "WARN"
    assert rules["120000"] == "IGNORE"
    assert "99999" not in rules  # unlisted plugin ids are not in the map (report only)


def _rules_file(tmp_path, text):
    p = tmp_path / "rules.tsv"
    p.write_text(text, encoding="utf-8")
    return p


def test_rules_tsv_bad_level_is_parse_error(tmp_path):
    p = _rules_file(tmp_path, "10001\tBLOCK\t(Fake rule)\tfake reason\n")
    with pytest.raises(ParseError, match="BLOCK"):
        parse_rules(p)


def test_rules_tsv_wrong_column_count_is_parse_error(tmp_path):
    p = _rules_file(tmp_path, "10001\tFAIL\t(Fake rule)\n")
    with pytest.raises(ParseError, match="4 tab-separated"):
        parse_rules(p)


def test_rules_tsv_empty_reason_is_parse_error(tmp_path):
    p = _rules_file(tmp_path, "10001\tFAIL\t(Fake rule)\t  \n")
    with pytest.raises(ParseError, match="reason"):
        parse_rules(p)


def test_rules_tsv_duplicate_is_parse_error(tmp_path):
    p = _rules_file(tmp_path, "10001\tFAIL\t(Fake rule)\tfake reason\n10001\tWARN\t(Fake rule)\tfake\n")
    with pytest.raises(ParseError, match="duplicate"):
        parse_rules(p)


def test_rules_tsv_comments_and_blank_lines_skipped(tmp_path):
    p = _rules_file(tmp_path, "# header\n\n10001\tOUTOFSCOPE\t(Fake rule)\tfake reason\n")
    assert parse_rules(p) == {"10001": "OUTOFSCOPE"}


def test_rules_tsv_missing_file_is_parse_error(tmp_path):
    with pytest.raises(ParseError):
        parse_rules(tmp_path / "missing.tsv")

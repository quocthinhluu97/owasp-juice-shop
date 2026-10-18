"""Waivers (D12): valid, expired, expiring within 14 days, stale, malformed (exit 2), 90-day horizon."""

from datetime import date
from pathlib import Path
import pytest

from triage.model import Finding
from triage.waivers import WaiverError, apply_waivers, load_waivers

TODAY = date(2026, 10, 18)  # the run date used by every test; the clock is injected, never read here


def _write(tmp_path, text):
    p = tmp_path / "waivers.yaml"
    p.write_text(text, encoding="utf-8")
    return p


def _finding(fingerprint="vuln:CVE-2026-19481:@fastify/busboy:2.1.1", cve="CVE-2026-19481",
             location="@fastify/busboy@2.1.1", category="vuln"):
    return Finding(tool="trivy", rule_id=cve or "GHSA-x", category=category, severity="high",
                   location=location, fingerprint=fingerprint, cve=cve)


def _entry(expires="2026-12-31", owner="quocthinhluu97", reason="Fake reason for a test.", selector=None):
    sel = selector if selector is not None else "fingerprint: 'vuln:CVE-2026-19481:@fastify/busboy:2.1.1'"
    return (f"  - {sel}\n    reason: \"{reason}\"\n    owner: {owner}\n    expires: {expires}\n")


def _load(tmp_path, body, today=TODAY):
    return load_waivers(_write(tmp_path, "waivers:\n" + body), today)


# valid

def test_fingerprint_waiver_applies(tmp_path):
    waivers = _load(tmp_path, _entry())
    res = apply_waivers([_finding(), _finding("vuln:OTHER:x:1", "OTHER", "x@1")], waivers, TODAY)
    assert len(res.waived) == 1 and res.waived[0][0].cve == "CVE-2026-19481"
    assert [f.fingerprint for f in res.active] == ["vuln:OTHER:x:1"]
    assert res.expired == [] and res.warnings == []


def test_cve_and_package_waiver_applies(tmp_path):
    body = _entry(selector="cve: CVE-2026-19481\n    package: '@fastify/busboy'")
    res = apply_waivers([_finding()], _load(tmp_path, body), TODAY)
    assert len(res.waived) == 1 and res.active == []


def test_cve_waiver_does_not_match_another_package(tmp_path):
    body = _entry(selector="cve: CVE-2026-19481\n    package: 'some-other-pkg'")
    res = apply_waivers([_finding()], _load(tmp_path, body), TODAY)
    assert res.waived == [] and len(res.active) == 1
    assert any("matches no finding" in w for w in res.warnings)


def test_expiry_day_itself_still_applies(tmp_path):
    res = apply_waivers([_finding()], _load(tmp_path, _entry(expires="2026-10-18")), TODAY)
    assert len(res.waived) == 1


def test_quoted_and_unquoted_dates_both_accepted(tmp_path):
    a = _load(tmp_path, _entry(expires="2026-12-31"))
    b = _load(tmp_path, _entry(expires="'2026-12-31'"))
    assert a[0].expires == b[0].expires == date(2026, 12, 31)


# expired

def test_expired_waiver_is_listed_and_not_applied(tmp_path):
    waivers = _load(tmp_path, _entry(expires="2026-10-17"))
    res = apply_waivers([_finding()], waivers, TODAY)
    assert res.waived == []
    assert len(res.active) == 1  # blocks again
    assert [w.expires for w in res.expired] == [date(2026, 10, 17)]
    assert not any("stale" in w for w in res.warnings)  # expired is reported as expired, not stale


# expiring soon / stale

def test_expires_within_14_days_warns(tmp_path):
    res = apply_waivers([_finding()], _load(tmp_path, _entry(expires="2026-11-01")), TODAY)  # 14 days
    assert any("expires in 14 day(s)" in w for w in res.warnings)


def test_expires_after_14_days_does_not_warn(tmp_path):
    res = apply_waivers([_finding()], _load(tmp_path, _entry(expires="2026-11-02")), TODAY)  # 15 days
    assert not any("expires in" in w for w in res.warnings)


def test_stale_waiver_warns(tmp_path):
    body = _entry(selector="fingerprint: 'vuln:GONE:gone:0'")
    res = apply_waivers([_finding()], _load(tmp_path, body), TODAY)
    assert any("matches no finding (stale)" in w for w in res.warnings)


def test_empty_waivers_list_is_fine(tmp_path):
    assert _load(tmp_path, "  []\n") == []


def test_waivers_key_null_is_empty(tmp_path):
    assert load_waivers(_write(tmp_path, "waivers:\n"), TODAY) == []


# malformed: all exit 2

@pytest.mark.parametrize(("label", "body"), [
    ("missing reason", "  - fingerprint: 'x'\n    owner: quocthinhluu97\n    expires: 2026-12-31\n"),
    ("missing owner", "  - fingerprint: 'x'\n    reason: 'r'\n    expires: 2026-12-31\n"),
    ("missing expires", "  - fingerprint: 'x'\n    reason: 'r'\n    owner: quocthinhluu97\n"),
    ("bad date", _entry(expires="2026-02-30")),
    ("date not ISO", _entry(expires="31/12/2026")),
    ("datetime not date", _entry(expires="2026-12-31T10:00:00")),
    ("bad owner", _entry(owner="not a handle!")),
    ("empty reason", "  - fingerprint: 'x'\n    reason: '  '\n    owner: quocthinhluu97\n    expires: 2026-12-31\n"),
    ("both selectors", "  - fingerprint: 'x'\n    cve: CVE-2026-19481\n    package: p\n"
                       "    reason: 'r'\n    owner: quocthinhluu97\n    expires: 2026-12-31\n"),
    ("no selector", "  - reason: 'r'\n    owner: quocthinhluu97\n    expires: 2026-12-31\n"),
    ("cve without package", "  - cve: CVE-2026-19481\n    reason: 'r'\n    owner: quocthinhluu97\n    expires: 2026-12-31\n"),
    ("bad cve", "  - cve: GHSA-1234\n    package: p\n    reason: 'r'\n    owner: quocthinhluu97\n    expires: 2026-12-31\n"),
    ("unknown key", _entry() + "    typo: 1\n"),
    ("beyond 90 days", _entry(expires="2027-01-17")),
])
def test_malformed_entry_is_waiver_error(tmp_path, label, body):
    with pytest.raises(WaiverError):
        _load(tmp_path, body)


def test_exactly_90_days_is_allowed(tmp_path):
    assert _load(tmp_path, _entry(expires="2027-01-16"))[0].expires == date(2027, 1, 16)


def test_horizon_error_names_the_date(tmp_path):
    with pytest.raises(WaiverError, match="90 days"):
        _load(tmp_path, _entry(expires="2027-06-01"))


def test_missing_file_is_waiver_error(tmp_path):
    with pytest.raises(WaiverError):
        load_waivers(tmp_path / "missing.yaml", TODAY)


def test_invalid_yaml_is_waiver_error(tmp_path):
    with pytest.raises(WaiverError, match="YAML"):
        load_waivers(_write(tmp_path, "waivers: [unclosed\n"), TODAY)


def test_top_level_without_waivers_key_is_error(tmp_path):
    with pytest.raises(WaiverError):
        load_waivers(_write(tmp_path, "entries: []\n"), TODAY)


def test_error_message_names_entry_not_free_text(tmp_path):
    # Messages name the file and entry number; they do not echo free text.
    with pytest.raises(WaiverError) as exc:
        _load(tmp_path, _entry(owner="bad owner value"))
    assert "waiver #1" in str(exc.value)



def test_fingerprint_waiver_keeps_matching_when_zap_instances_change(tmp_path):
    # D20: the fingerprint is plugin + site, so ZAP reselecting its instances does not stop the waiver.
    import copy as _copy
    import json as _json
    from triage.parsers.zap import parse_zap

    base = _json.loads((Path(__file__).parent / "fixtures" / "zap" / "zap.json").read_text(encoding="utf-8"))
    run2 = _copy.deepcopy(base)
    for alert in run2["site"][0]["alerts"]:
        if alert["alertRef"] == "10038-1":
            alert["instances"] = [{"uri": "http://juice:3000/other-page", "param": ""}]
    waivers = _load(tmp_path, _entry(selector="fingerprint: 'dast:10038:http://juice:3000'"))
    for doc in (base, run2):
        p = tmp_path / "zap.json"
        p.write_text(_json.dumps(doc), encoding="utf-8")
        res = apply_waivers(parse_zap(p), waivers, TODAY)
        assert [f.rule_id for f, _ in res.waived] == ["10038"]
        assert not any(f.rule_id == "10038" for f in res.active)

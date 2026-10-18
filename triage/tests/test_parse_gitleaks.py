"""Gitleaks parser against the trimmed CI report. Counts come from the fixture list itself."""

import copy
import json
from pathlib import Path

import pytest

from triage.model import ParseError
from triage.parsers.gitleaks import parse_gitleaks

FIXTURE = Path(__file__).parent / "fixtures" / "gitleaks.json"


def _raw():
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def _write(tmp_path, data):
    p = tmp_path / "gitleaks.json"
    p.write_text(json.dumps(data), encoding="utf-8")
    return p


def test_one_finding_per_entry():
    assert len(parse_gitleaks(FIXTURE)) == len(_raw())


def test_fields_from_fixture():
    findings = {f.location: f for f in parse_gitleaks(FIXTURE)}
    users_151 = findings["app/data/static/users.yml:151"]
    assert users_151.tool == "gitleaks"
    assert users_151.rule_id == "generic-api-key"
    assert users_151.category == "secret"
    assert users_151.severity == "high"
    assert users_151.tools == ["gitleaks"] and users_151.sources == ["gitleaks"]
    assert users_151.cve is None and users_151.fixed_version == []
    # StartLine 0 (file-level rule) is kept as-is.
    assert "app/ctf.key:0" in findings


def test_fingerprint_is_rule_file_hash_without_commit(tmp_path):
    entry = _raw()[0]
    (finding,) = parse_gitleaks(_write(tmp_path, [entry]))
    assert finding.fingerprint == f"secret:{entry['RuleID']}:{entry['File']}:{entry['Secret']}"
    assert entry["Commit"] not in finding.fingerprint


def test_key_files_with_empty_hash_stay_separate_by_file(tmp_path):
    # The key-files finding hashes the empty string, so only the file tells them apart.
    ctf = next(e for e in _raw() if e["File"] == "app/ctf.key")
    other = copy.deepcopy(ctf)
    other["File"] = "app/encryptionkeys/premium.key"
    other["Fingerprint"] = other["Fingerprint"].replace("app/ctf.key", other["File"])
    findings = parse_gitleaks(_write(tmp_path, [ctf, other]))
    assert ctf["Secret"] == other["Secret"]
    assert len({f.fingerprint for f in findings}) == 2


def test_same_hash_in_two_files_is_not_one_fingerprint():
    # users.yml:88 and login.ts:64 share one sha256 (fixture); different files, so different fingerprints.
    findings = parse_gitleaks(FIXTURE)
    by_loc = {f.location: f for f in findings}
    assert by_loc["app/data/static/users.yml:88"].fingerprint != by_loc["app/routes/login.ts:64"].fingerprint


def test_same_secret_in_two_commits_gives_one_fingerprint(tmp_path):
    # Synthetic copy with an obviously fake commit id. Commit is not part of the fingerprint.
    entry = next(e for e in _raw() if e["File"] == "app/data/static/users.yml" and e["StartLine"] == 151)
    later = copy.deepcopy(entry)
    later["Commit"] = "0" * 40
    later["Fingerprint"] = f"{later['Commit']}:{later['File']}:{later['RuleID']}:{later['StartLine']}"
    findings = parse_gitleaks(_write(tmp_path, [entry, later]))
    assert len(findings) == 2
    assert findings[0].fingerprint == findings[1].fingerprint


def test_refuses_raw_secret(tmp_path):
    entry = copy.deepcopy(_raw()[0])
    entry["Secret"] = "FAKE-not-a-real-secret-0000"
    with pytest.raises(ParseError) as exc:
        parse_gitleaks(_write(tmp_path, [entry]))
    assert "FAKE-not-a-real-secret" not in str(exc.value)


def test_refuses_unredacted_match(tmp_path):
    entry = copy.deepcopy(_raw()[0])
    entry["Match"] = "FAKE-token-0000"
    with pytest.raises(ParseError, match="REDACTED"):
        parse_gitleaks(_write(tmp_path, [entry]))


@pytest.mark.parametrize("missing", ["RuleID", "File", "StartLine", "Match", "Secret"])
def test_missing_key_is_parse_error(tmp_path, missing):
    entry = copy.deepcopy(_raw()[0])
    del entry[missing]
    with pytest.raises(ParseError, match=missing):
        parse_gitleaks(_write(tmp_path, [entry]))


def test_missing_file_is_parse_error(tmp_path):
    with pytest.raises(ParseError):
        parse_gitleaks(tmp_path / "nope.json")


def test_not_a_list_is_parse_error(tmp_path):
    with pytest.raises(ParseError):
        parse_gitleaks(_write(tmp_path, {"findings": []}))

"""Trivy parser against the trimmed image and fs reports. Counts come from the raw Vulnerabilities lists."""

import copy
import json
from pathlib import Path

import pytest

from triage.model import ParseError
from triage.parsers.trivy import parse_trivy

FIXTURES = Path(__file__).parent / "fixtures"
IMAGE = FIXTURES / "trivy-image.json"
FS = FIXTURES / "trivy-fs.json"


def _raw(path):
    return json.loads(path.read_text(encoding="utf-8"))


def _vuln_count(doc):
    return sum(len(r.get("Vulnerabilities") or []) for r in doc["Results"])


def _by_key(findings):
    return {(f.rule_id, f.location): f for f in findings}


def test_image_count_matches_fixture_rows():
    assert len(parse_trivy(IMAGE, "image")) == _vuln_count(_raw(IMAGE)) == 5


def test_fs_count_matches_fixture_rows():
    assert len(parse_trivy(FS, "fs")) == _vuln_count(_raw(FS)) == 7


def test_image_source_and_tool():
    findings = parse_trivy(IMAGE, "image")
    assert {f.sources[0] for f in findings} == {"trivy-image"}
    assert {f.tools[0] for f in findings} == {"trivy"}
    assert {f.category for f in findings} == {"vuln"}


def test_fs_source_is_relative_to_app_dir():
    sources = {f.sources[0] for f in parse_trivy(FS, "fs")}
    assert sources == {"trivy-fs:app/package-lock.json", "trivy-fs:app/frontend/package-lock.json"}


def test_fixed_and_unfixed_pair():
    by = _by_key(parse_trivy(IMAGE, "image"))
    fixed = by[("CVE-2026-19481", "@fastify/busboy@2.1.1")]
    unfixed = by[("CVE-2026-8674", "libc6@2.41-12+deb13u4")]
    assert fixed.fixed_version == ["3.2.1"]
    assert unfixed.fixed_version == []  # Status affected: no fix counted, even with no FixedVersion


def test_multi_value_fixed_version_is_a_list():
    by = _by_key(parse_trivy(FS, "fs"))
    assert by[("CVE-2026-75899", "fast-uri@3.1.5")].fixed_version == ["2.4.5", "3.1.6", "4.1.3"]


def test_non_cve_id_has_no_cve_field():
    by = _by_key(parse_trivy(IMAGE, "image"))
    ghsa = by[("GHSA-rvg8-pwq2-xj7q", "base64url@0.0.6")]
    assert ghsa.cve is None
    assert ghsa.rule_id == "GHSA-rvg8-pwq2-xj7q"
    assert by[("CVE-2026-19481", "@fastify/busboy@2.1.1")].cve == "CVE-2026-19481"


def test_fingerprint_is_vuln_id_package_version():
    by = _by_key(parse_trivy(IMAGE, "image"))
    f = by[("CVE-2026-19481", "@fastify/busboy@2.1.1")]
    assert f.fingerprint == "vuln:CVE-2026-19481:@fastify/busboy:2.1.1"


def test_image_and_fs_share_fingerprint_for_same_package():
    image = {f.fingerprint for f in parse_trivy(IMAGE, "image")}
    fs = {f.fingerprint for f in parse_trivy(FS, "fs")}
    assert "vuln:CVE-2026-19481:@fastify/busboy:2.1.1" in image & fs


def test_undici_joined_to_parent_through_depends_on():
    by = _by_key(parse_trivy(FS, "fs"))
    undici = by[("CVE-2026-84961", "undici@7.29.0")]
    assert undici.relationship == "indirect"
    assert undici.parents == ["jsdom@29.1.1"]
    assert undici.sources == ["trivy-fs:app/frontend/package-lock.json"]


def test_root_lockfile_relationship_and_parent():
    by = _by_key(parse_trivy(FS, "fs"))
    assert by[("GHSA-5mrr-rgp6-x4gr", "marsdb@0.6.11")].relationship == "direct"
    decompress = by[("CVE-2026-101894", "decompress@4.2.1")]
    assert decompress.relationship == "indirect"
    assert decompress.parents == ["download@8.0.0"]


def test_severity_mapped_from_trivy_values():
    by = _by_key(parse_trivy(IMAGE, "image"))
    assert by[("CVE-2026-8674", "libc6@2.41-12+deb13u4")].severity == "medium"
    assert by[("GHSA-5mrr-rgp6-x4gr", "marsdb@0.6.11")].severity == "critical"


def test_artifact_type_must_match_kind():
    with pytest.raises(ParseError, match="ArtifactType"):
        parse_trivy(IMAGE, "fs")
    with pytest.raises(ParseError, match="ArtifactType"):
        parse_trivy(FS, "image")


def test_missing_vuln_key_is_parse_error(tmp_path):
    doc = copy.deepcopy(_raw(IMAGE))
    del doc["Results"][0]["Vulnerabilities"][0]["Severity"]
    p = tmp_path / "trivy.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    with pytest.raises(ParseError, match="Severity"):
        parse_trivy(p, "image")


def test_unknown_severity_is_unknown_severity_error(tmp_path):
    from triage.model import UnknownSeverityError

    doc = copy.deepcopy(_raw(IMAGE))
    doc["Results"][0]["Vulnerabilities"][0]["Severity"] = "BOGUS"
    p = tmp_path / "trivy.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    with pytest.raises(UnknownSeverityError):
        parse_trivy(p, "image")


def test_missing_file_is_parse_error(tmp_path):
    with pytest.raises(ParseError):
        parse_trivy(tmp_path / "missing.json", "fs")


def test_undici_top_parent_is_direct_jsdom():
    by = _by_key(parse_trivy(FS, "fs"))
    assert by[("CVE-2026-84961", "undici@7.29.0")].top_parents == ["jsdom@29.1.1"]


def test_fast_uri_reaches_direct_parents_through_ajv():
    # Real chain in the CI report: fast-uri -> ajv -> @angular-devkit/core -> @angular/cli (direct).
    by = _by_key(parse_trivy(FS, "fs"))
    fast_uri = by[("CVE-2026-75899", "fast-uri@3.1.5")]
    assert fast_uri.parents == ["ajv@8.20.0"]
    assert fast_uri.top_parents == [
        "@angular/build@22.1.3",
        "@angular/cli@22.1.3",
        "@cyclonedx/cyclonedx-esbuild@1.4.3",
    ]


def test_direct_package_is_its_own_top_parent():
    by = _by_key(parse_trivy(FS, "fs"))
    assert by[("GHSA-5mrr-rgp6-x4gr", "marsdb@0.6.11")].top_parents == ["marsdb@0.6.11"]


def test_image_findings_have_no_top_parents():
    assert all(f.top_parents == [] for f in parse_trivy(IMAGE, "image"))


def _fs_doc(packages, vuln_pkg_id):
    return {
        "ArtifactType": "filesystem",
        "Results": [{
            "Target": "package-lock.json",
            "Packages": packages,
            "Vulnerabilities": [{
                "VulnerabilityID": "CVE-2099-0001", "PkgID": vuln_pkg_id, "PkgName": vuln_pkg_id.split("@")[0],
                "InstalledVersion": vuln_pkg_id.split("@")[1], "Status": "affected", "Severity": "LOW",
            }],
        }],
    }


def test_dead_end_is_marked_not_guessed(tmp_path):
    # Synthetic: leaf -> orphan, orphan is indirect and has no parent in the trimmed graph.
    packages = [
        {"ID": "leaf@1.0.0", "Name": "leaf", "Version": "1.0.0", "Relationship": "indirect", "DependsOn": []},
        {"ID": "orphan@2.0.0", "Name": "orphan", "Version": "2.0.0", "Relationship": "indirect",
         "DependsOn": ["leaf@1.0.0"]},
    ]
    p = tmp_path / "trivy-fs.json"
    p.write_text(json.dumps(_fs_doc(packages, "leaf@1.0.0")), encoding="utf-8")
    (f,) = parse_trivy(p, "fs")
    assert f.top_parents == ["?orphan@2.0.0"]


def test_cycle_terminates(tmp_path):
    # Synthetic cycle a <-> b with no direct package: the walk must stop, and both ends are dead ends.
    packages = [
        {"ID": "a@1.0.0", "Name": "a", "Version": "1.0.0", "Relationship": "indirect", "DependsOn": ["b@1.0.0"]},
        {"ID": "b@1.0.0", "Name": "b", "Version": "1.0.0", "Relationship": "indirect", "DependsOn": ["a@1.0.0"]},
    ]
    p = tmp_path / "trivy-fs.json"
    p.write_text(json.dumps(_fs_doc(packages, "a@1.0.0")), encoding="utf-8")
    (f,) = parse_trivy(p, "fs")
    assert f.top_parents == ["?b@1.0.0"]  # the walk from a reaches b, then a again (cut), so b is the dead end

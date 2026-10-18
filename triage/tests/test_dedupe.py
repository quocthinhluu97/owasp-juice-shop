"""Dedupe (D5, D6) across tools, on the real fixtures plus small synthetic copies where the fixture has no case."""

import copy
import json
from dataclasses import replace
from pathlib import Path

from triage.dedupe import dedupe
from triage.model import Finding
from triage.parsers.checkov import parse_checkov
from triage.parsers.gitleaks import parse_gitleaks
from triage.parsers.semgrep import parse_semgrep
from triage.parsers.trivy import parse_trivy
from triage.parsers.zap import parse_zap

FIXTURES = Path(__file__).parent / "fixtures"


def _raw_gitleaks():
    return json.loads((FIXTURES / "gitleaks.json").read_text(encoding="utf-8"))


def _write(tmp_path, name, doc):
    p = tmp_path / name
    p.write_text(json.dumps(doc), encoding="utf-8")
    return p


def _gitleaks_copy(tmp_path, entries):
    return parse_gitleaks(_write(tmp_path, "gitleaks.json", entries))


def test_trivy_image_and_fs_same_cve_counted_once():
    image = parse_trivy(FIXTURES / "trivy-image.json", "image")
    fs = parse_trivy(FIXTURES / "trivy-fs.json", "fs")
    merged = dedupe(image + fs)
    # 5 image rows + 7 fs rows, 4 keys in both: 8 distinct vulnerabilities.
    assert len(merged) == 8
    (busboy,) = [f for f in merged if f.rule_id == "CVE-2026-19481"]
    assert busboy.tools == ["trivy"]
    assert sorted(busboy.sources) == ["trivy-fs:app/package-lock.json", "trivy-image"]


def test_trivy_non_cve_duplicate_counted_once():
    image = parse_trivy(FIXTURES / "trivy-image.json", "image")
    fs = parse_trivy(FIXTURES / "trivy-fs.json", "fs")
    merged = dedupe(image + fs)
    (ghsa,) = [f for f in merged if f.rule_id == "GHSA-5mrr-rgp6-x4gr"]
    assert len(ghsa.sources) == 2


def test_fixed_version_survives_merge():
    image = parse_trivy(FIXTURES / "trivy-image.json", "image")
    fs = parse_trivy(FIXTURES / "trivy-fs.json", "fs")
    (busboy,) = [f for f in dedupe(image + fs) if f.rule_id == "CVE-2026-19481"]
    assert busboy.fixed_version == ["3.2.1"]


def test_users_yml_semgrep_secret_merges_into_gitleaks():
    gl = parse_gitleaks(FIXTURES / "gitleaks.json")
    sg = parse_semgrep(FIXTURES / "semgrep.json")
    merged = dedupe(gl + sg)
    assert not any(f.tool == "semgrep" and f.category == "secret" for f in merged)
    (finding,) = [f for f in merged if f.location == "app/data/static/users.yml:151"]
    assert finding.tool == "gitleaks"
    assert finding.tools == ["gitleaks", "semgrep"]
    assert finding.sources == ["gitleaks", "semgrep"]


def test_unmatched_semgrep_secret_stays_separate(tmp_path):
    # Synthetic: same rule, but no Gitleaks finding at line 999. It must remain as a Semgrep finding.
    doc = json.loads((FIXTURES / "semgrep.json").read_text(encoding="utf-8"))
    for r in doc["results"]:
        if r["check_id"].startswith("generic.secrets."):
            r["start"]["line"] = 999
    sg = parse_semgrep(_write(tmp_path, "semgrep.json", doc))
    merged = dedupe(parse_gitleaks(FIXTURES / "gitleaks.json") + sg)
    leftover = [f for f in merged if f.tool == "semgrep" and f.category == "secret"]
    assert [f.location for f in leftover] == ["app/data/static/users.yml:999"]
    (gl_151,) = [f for f in merged if f.location == "app/data/static/users.yml:151"]
    assert gl_151.tools == ["gitleaks"]


def test_key_files_in_different_files_do_not_merge(tmp_path):
    # ctf.key hashes the empty string; the fixture has no second key-files entry, so make one with a different file.
    ctf = next(e for e in _raw_gitleaks() if e["File"] == "app/ctf.key")
    other = copy.deepcopy(ctf)
    other["File"] = "app/encryptionkeys/premium.key"
    other["Fingerprint"] = f"{other['Commit']}:{other['File']}:{other['RuleID']}:{other['StartLine']}"
    merged = dedupe(_gitleaks_copy(tmp_path, [ctf, other]))
    assert len(merged) == 2
    assert ctf["Secret"] == other["Secret"]


def test_same_hash_in_two_files_does_not_merge():
    merged = dedupe(parse_gitleaks(FIXTURES / "gitleaks.json"))
    locs = {f.location for f in merged}
    assert {"app/data/static/users.yml:88", "app/routes/login.ts:64"} <= locs
    assert len(merged) == 6


def test_same_secret_in_two_commits_counted_once(tmp_path):
    # Synthetic copy of users.yml:151 with an obviously fake commit id. Commit is not in the fingerprint.
    entry = next(e for e in _raw_gitleaks() if e["File"] == "app/data/static/users.yml" and e["StartLine"] == 151)
    later = copy.deepcopy(entry)
    later["Commit"] = "0" * 40
    later["Fingerprint"] = f"{later['Commit']}:{later['File']}:{later['RuleID']}:{later['StartLine']}"
    merged = dedupe(_gitleaks_copy(tmp_path, [entry, later]))
    assert len(merged) == 1


def test_zap_alerts_are_one_finding_each_after_dedupe():
    zap = parse_zap(FIXTURES / "zap" / "zap.json")
    merged = dedupe(zap)
    # D20: one finding per alert per site. 6 alerts, 6 distinct plugin+site keys; instances are kept.
    assert len(zap) == 6
    assert len(merged) == 6
    (sid,) = [f for f in merged if f.rule_id == "3"]
    assert sid.fingerprint == "dast:3:http://juice:3000"
    assert sid.instances == ["/socket.io/ [param=sid]"]


def test_zap_same_key_from_two_alerts_merges_instances(tmp_path):
    import copy as _copy
    doc = json.loads((FIXTURES / "zap" / "zap.json").read_text(encoding="utf-8"))
    extra = _copy.deepcopy(doc["site"][0]["alerts"][1])
    extra["instances"] = [{"uri": "http://juice:3000/extra", "param": ""}]
    doc["site"][0]["alerts"].append(extra)
    p = tmp_path / "zap.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    merged = dedupe(parse_zap(p))
    (f,) = [x for x in merged if x.rule_id == "10038"]
    assert "/extra" in f.instances and "/" in f.instances
    assert len(merged) == 6


def test_zap_variants_under_one_pluginid_keep_every_name(tmp_path):
    # Same pluginid and site, two alert names (a variant): one finding, both names kept, instances unioned.
    doc = json.loads((FIXTURES / "zap" / "zap.json").read_text(encoding="utf-8"))
    variant = copy.deepcopy(doc["site"][0]["alerts"][1])
    variant["name"] = "Variant name from a second alert"
    variant["instances"] = [{"uri": "http://juice:3000/variant-page", "param": ""}]
    doc["site"][0]["alerts"].append(variant)
    p = tmp_path / "zap.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    merged = dedupe(parse_zap(p))
    (f,) = [x for x in merged if x.rule_id == "10038"]
    assert f.names == [doc["site"][0]["alerts"][1]["name"], "Variant name from a second alert"]
    assert "/variant-page" in f.instances
    assert len(merged) == 6


def test_dedupe_does_not_mutate_inputs():
    original = parse_gitleaks(FIXTURES / "gitleaks.json")
    snapshot = [replace(f, tools=list(f.tools), sources=list(f.sources)) for f in original]
    dedupe(original + parse_semgrep(FIXTURES / "semgrep.json"))
    assert original == snapshot


def test_checkov_findings_pass_through_unchanged():
    checkov = parse_checkov(FIXTURES / "checkov" / "results_json.json")
    assert len(dedupe(checkov)) == len(checkov) == 3


def _vuln_pair(image_rel=None, fs_rel="direct", image_parents=(), fs_parents=("sqlite3@5.0.0",),
               fs_top=("tar@6.0.0",)):
    common = dict(tool="trivy", rule_id="CVE-2099-0002", category="vuln", severity="high",
                  location="tar@6.0.0", fingerprint="vuln:CVE-2099-0002:tar:6.0.0", cve="CVE-2099-0002")
    image = Finding(**common, relationship=image_rel, parents=list(image_parents), tools=["trivy"],
                    sources=["trivy-image"])
    fs = Finding(**common, relationship=fs_rel, parents=list(fs_parents), top_parents=list(fs_top),
                 tools=["trivy"], sources=["trivy-fs:app/package-lock.json"])
    return image, fs


def test_image_and_fs_merge_keeps_the_fs_lockfile_facts():
    # The image side has no relationship (None, []). The merged finding must carry the fs facts.
    image, fs = _vuln_pair()
    (merged,) = dedupe([image, fs])
    assert merged.relationship == "direct"
    assert merged.parents == ["sqlite3@5.0.0"]
    assert merged.top_parents == ["tar@6.0.0"]
    assert sorted(merged.sources) == ["trivy-fs:app/package-lock.json", "trivy-image"]


def test_merge_is_the_same_whichever_side_comes_first():
    image, fs = _vuln_pair()
    (a,) = dedupe([image, fs])
    (b,) = dedupe([fs, image])
    assert (a.relationship, a.parents, a.top_parents) == (b.relationship, b.parents, b.top_parents)


def test_parents_union_without_duplicates():
    image, fs = _vuln_pair(image_parents=("sqlite3@5.0.0", "cacache@1.0.0"), fs_parents=("sqlite3@5.0.0",))
    (merged,) = dedupe([image, fs])
    assert merged.parents == ["sqlite3@5.0.0", "cacache@1.0.0"]


def test_different_relationships_from_two_lockfiles_are_both_kept():
    _, root = _vuln_pair(fs_rel="direct")
    _, frontend = _vuln_pair(fs_rel="indirect")
    frontend.sources = ["trivy-fs:app/frontend/package-lock.json"]
    (merged,) = dedupe([root, frontend])
    assert merged.relationship == "direct / indirect"

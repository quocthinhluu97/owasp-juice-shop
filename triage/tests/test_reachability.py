"""Reachability hints (D11, D7 labels) on a tiny fake app/ tree built in tmp_path. Labels only."""

import json
from pathlib import Path

import pytest

from triage.model import Finding, ParseError
from triage.reachability import add_hints


def _tree(tmp_path: Path) -> Path:
    app = tmp_path / "app"
    (app / "routes").mkdir(parents=True)
    (app / "lib").mkdir()
    (app / "models").mkdir()
    (app / "data").mkdir()
    (app / "frontend").mkdir()
    # First-party backend: one route imports jsonwebtoken, one lib file requires marsdb.
    (app / "routes" / "login.ts").write_text("import jwt from 'jsonwebtoken';\nexport {};\n", encoding="utf-8")
    (app / "lib" / "db.ts").write_text("const marsdb = require('marsdb');\n", encoding="utf-8")
    (app / "server.ts").write_text("// no vulnerable imports here\n", encoding="utf-8")
    (app / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": {
        "": {"name": "juice-shop"},
        "node_modules/jsonwebtoken": {"version": "0.4.0"},
        "node_modules/marsdb": {"version": "0.6.11", "devOptional": True},
        "node_modules/express/node_modules/foo": {"version": "1.0.0", "dev": True},
    }}), encoding="utf-8")
    (app / "frontend" / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": {
        "": {"name": "frontend"},
        "node_modules/undici": {"version": "7.29.0"},
    }}), encoding="utf-8")
    return app


def _vuln(location, sources, relationship=None, top_parents=None, cve="CVE-2099-0001"):
    return Finding(tool="trivy", rule_id=cve, category="vuln", severity="high", location=location,
                   fingerprint=f"vuln:{cve}:{location}", cve=cve, relationship=relationship,
                   top_parents=top_parents or [], sources=sources, tools=["trivy"])


def _hints(finding):
    return finding.hints


def test_direct_dependency_with_image_and_fs_presence_and_import_evidence(tmp_path):
    app = _tree(tmp_path)
    f = _vuln("jsonwebtoken@0.4.0", ["trivy-image", "trivy-fs:app/package-lock.json"], "direct",
              ["jsonwebtoken@0.4.0"])
    add_hints([f], app)
    h = _hints(f)
    assert "dependency: direct" in h
    assert "presence: image and fs" in h
    assert "stage: reached from production dependency (jsonwebtoken@0.4.0)" in h
    assert any(x.startswith("import: grep-level evidence in routes/login.ts") for x in h)


def test_devoptional_is_read_from_the_lockfile(tmp_path):
    app = _tree(tmp_path)
    f = _vuln("marsdb@0.6.11", ["trivy-fs:app/package-lock.json"], "direct", ["marsdb@0.6.11"])
    add_hints([f], app)
    assert "dependency: devOptional in trivy-fs:app/package-lock.json (Trivy counts it as production)" in _hints(f)
    assert "presence: fs only" in _hints(f)
    assert any(x.startswith("import: grep-level evidence in lib/db.ts") for x in _hints(f))


def test_dev_only_lockfile_flag(tmp_path):
    app = _tree(tmp_path)
    f = _vuln("foo@1.0.0", ["trivy-fs:app/package-lock.json"], "indirect", ["express@4.0.0"])
    add_hints([f], app)
    assert "dependency: dev only in trivy-fs:app/package-lock.json" in _hints(f)


def test_build_stage_only_via_frontend_build_tool(tmp_path):
    app = _tree(tmp_path)
    f = _vuln("undici@7.29.0", ["trivy-fs:app/frontend/package-lock.json"], "indirect", ["jsdom@29.1.1"])
    add_hints([f], app)
    h = _hints(f)
    assert "stage: build stage only (via jsdom@29.1.1)" in h
    assert "import: no grep-level evidence in first-party backend code" in h


def test_dead_end_marker_is_reported_as_incomplete_chain(tmp_path):
    app = _tree(tmp_path)
    f = _vuln("fast-uri@3.1.5", ["trivy-fs:app/package-lock.json"], "indirect", ["?ajv@8.20.0"])
    add_hints([f], app)
    assert "stage: parent chain incomplete (?ajv@8.20.0)" in _hints(f)


def test_mixed_build_and_production_parents_are_production(tmp_path):
    app = _tree(tmp_path)
    f = _vuln("x@1.0.0", ["trivy-fs:app/package-lock.json"], "indirect", ["jsdom@29.1.1", "express@4.0.0"])
    add_hints([f], app)
    assert any(h.startswith("stage: reached from production dependency") for h in _hints(f))


def test_image_only_package_has_no_lockfile_relationship(tmp_path):
    app = _tree(tmp_path)
    f = _vuln("libc6@2.41", ["trivy-image"])
    add_hints([f], app)
    h = _hints(f)
    assert "dependency: image package (no lockfile relationship in the image report)" in h
    assert "presence: image only" in h
    assert not any(x.startswith("stage:") for x in h)


def test_missing_lockfile_is_labelled_not_silent(tmp_path):
    app = _tree(tmp_path)
    f = _vuln("x@1.0.0", ["trivy-fs:app/other/package-lock.json"], "direct", ["x@1.0.0"])
    add_hints([f], app)
    assert "dependency flags: lockfile missing for trivy-fs:app/other/package-lock.json" in _hints(f)


def test_evidence_list_is_capped(tmp_path):
    app = _tree(tmp_path)
    for i in range(7):
        (app / "routes" / f"extra{i}.ts").write_text("import x from 'jsonwebtoken';\n", encoding="utf-8")
    f = _vuln("jsonwebtoken@0.4.0", ["trivy-fs:app/package-lock.json"], "direct", ["jsonwebtoken@0.4.0"])
    add_hints([f], app)
    line = next(h for h in _hints(f) if h.startswith("import:"))
    assert "(+3 more)" in line  # 8 files in total, 5 shown


def test_import_patterns_do_not_match_a_different_package(tmp_path):
    app = _tree(tmp_path)
    f = _vuln("jwt@1.0.0", ["trivy-fs:app/package-lock.json"], "direct", ["jwt@1.0.0"])
    add_hints([f], app)
    assert "import: no grep-level evidence in first-party backend code" in _hints(f)


def test_non_trivy_findings_are_untouched(tmp_path):
    app = _tree(tmp_path)
    other = Finding(tool="semgrep", rule_id="r", category="code", severity="low", location="a:1",
                    fingerprint="code:x")
    add_hints([other], app)
    assert other.hints == []


def test_malformed_lockfile_is_parse_error(tmp_path):
    app = _tree(tmp_path)
    (app / "package-lock.json").write_text("{not json", encoding="utf-8")
    f = _vuln("x@1.0.0", ["trivy-fs:app/package-lock.json"], "direct", ["x@1.0.0"])
    with pytest.raises(ParseError):
        add_hints([f], app)


def test_lockfile_without_packages_map_is_parse_error(tmp_path):
    app = _tree(tmp_path)
    (app / "package-lock.json").write_text(json.dumps({"lockfileVersion": 1}), encoding="utf-8")
    f = _vuln("x@1.0.0", ["trivy-fs:app/package-lock.json"], "direct", ["x@1.0.0"])
    with pytest.raises(ParseError, match="packages"):
        add_hints([f], app)


def test_hints_come_from_the_merged_finding_not_the_image_side(tmp_path):
    # Image + fs pair for one package: only the fs side knows the relationship. After dedupe, the hints
    # must say direct (fs), never "image package (no lockfile relationship)".
    from triage.dedupe import dedupe

    app = _tree(tmp_path)
    common = dict(tool="trivy", rule_id="CVE-2099-0003", category="vuln", severity="high",
                  location="jsonwebtoken@0.4.0", fingerprint="vuln:CVE-2099-0003:jsonwebtoken:0.4.0",
                  cve="CVE-2099-0003")
    image = Finding(**common, sources=["trivy-image"], tools=["trivy"])
    fs = Finding(**common, relationship="direct", top_parents=["jsonwebtoken@0.4.0"],
                 sources=["trivy-fs:app/package-lock.json"], tools=["trivy"])
    (merged,) = dedupe([image, fs])
    add_hints([merged], app)
    assert "dependency: direct" in merged.hints
    assert not any("image package" in h for h in merged.hints)
    assert "presence: image and fs" in merged.hints

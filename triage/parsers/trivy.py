"""Trivy JSON (trivy-image.json or trivy-fs.json) -> Finding (vuln).

The file name is not trusted: ArtifactType must match the kind the caller asked for.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

from triage.model import Finding, ParseError, map_severity
from triage.parsers.common import load_json, require_keys

ARTIFACT_TYPES = {"image": "container_image", "fs": "filesystem"}
VULN_KEYS = ("VulnerabilityID", "PkgID", "PkgName", "InstalledVersion", "Status", "Severity")


def parse_trivy(path: Path, kind: Literal["image", "fs"]) -> list[Finding]:
    doc = load_json(path)
    require_keys(doc, ("ArtifactType", "Results"), str(path))
    if doc["ArtifactType"] != ARTIFACT_TYPES[kind]:
        raise ParseError(f"{path}: ArtifactType is {doc['ArtifactType']!r}, expected {ARTIFACT_TYPES[kind]!r} for {kind}")
    if not isinstance(doc["Results"], list):
        raise ParseError(f"{path}: Results is not a list")

    findings: list[Finding] = []
    for r in doc["Results"]:
        require_keys(r, ("Target",), f"{path}: Results entry")
        target = r["Target"]
        # fs scans run in app/, so Target is relative to that directory (ArtifactName /src/app).
        source = "trivy-image" if kind == "image" else f"trivy-fs:app/{target}"
        packages = {p["ID"]: p for p in (r.get("Packages") or []) if isinstance(p, dict) and "ID" in p}
        for v in r.get("Vulnerabilities") or []:
            where = f"{path}: {target}: vulnerability"
            require_keys(v, VULN_KEYS, where)
            findings.append(_finding(v, packages, source, kind == "fs"))
    return findings


def _finding(v: dict[str, Any], packages: dict[str, dict[str, Any]], source: str, is_fs: bool) -> Finding:
    vuln_id, name, version = v["VulnerabilityID"], v["PkgName"], v["InstalledVersion"]
    pkg = packages.get(v["PkgID"], {})
    # D8: a fix exists only when Status is fixed and FixedVersion is non-empty.
    fixed = v.get("FixedVersion") or ""
    fixed_version = [x.strip() for x in fixed.split(",") if x.strip()] if v["Status"] == "fixed" else []
    cwes = v.get("CweIDs") or []
    parents = sorted(p_id for p_id, p in packages.items() if v["PkgID"] in (p.get("DependsOn") or []))
    top_parents = _top_parents(v["PkgID"], packages) if is_fs else []
    return Finding(
        tool="trivy",
        rule_id=vuln_id,
        category="vuln",
        severity=map_severity("trivy", v["Severity"]),
        location=f"{name}@{version}",
        cve=vuln_id if vuln_id.startswith("CVE-") else None,
        cwe=cwes[0] if cwes else None,
        fixed_version=fixed_version,
        relationship=pkg.get("Relationship"),
        parents=parents,
        top_parents=top_parents,
        # D5: vuln_id + package + installed version. The same key from image and fs counts once.
        fingerprint=f"vuln:{vuln_id}:{name}:{version}",
        tools=["trivy"],
        sources=[source],
    )


def _top_parents(pkg_id: str, packages: dict[str, dict[str, Any]]) -> list[str]:
    """Walk DependsOn upwards inside one Results entry and collect the direct ancestors (D7).

    A direct package is its own top parent and ends its branch. A non-direct package whose walk reaches
    no direct package is a dead end: "?name@version" marks the chain as incomplete. A package already on
    the current walk (a cycle) contributes nothing; a cycle with no direct root still ends in a marker.
    """
    ups_of: dict[str, list[str]] = {}
    for p_id, p in packages.items():
        for dep in p.get("DependsOn") or []:
            ups_of.setdefault(dep, []).append(p_id)

    memo: dict[str, frozenset[str]] = {}
    on_walk: set[str] = set()

    def tops(current: str) -> frozenset[str]:
        if current in memo:
            return memo[current]
        if current in on_walk:
            return frozenset()
        pkg = packages.get(current)
        if pkg is not None and pkg.get("Relationship") == "direct":
            memo[current] = frozenset({current})
            return memo[current]
        on_walk.add(current)
        found: set[str] = set()
        for up in ups_of.get(current, []):
            found |= tops(up)
        on_walk.discard(current)
        memo[current] = frozenset(found) if found else frozenset({f"?{current}"})
        return memo[current]

    return sorted(tops(pkg_id))

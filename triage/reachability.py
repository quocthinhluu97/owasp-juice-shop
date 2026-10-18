"""Reachability hints (D11, D7 labels). Labels only: they never gate on their own (policy.py decides).

Labels: dependency type (Trivy fs Relationship, devOptional read from the lockfile itself), presence
(image / fs / both), build-stage label from top parents (D7), and grep-level import evidence.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from triage.model import Finding, ParseError
from triage.policy import BUILD_TOOL_PARENTS

# Backend first-party code, relative to app/ (D11). Frontend build output is not scanned here.
IMPORT_DIRS = ("routes", "lib", "models")
IMPORT_FILES = ("server.ts", "app.ts")
MAX_EVIDENCE_FILES = 5


def add_hints(findings: list[Finding], app_dir: Path) -> None:
    """Fill Finding.hints for vulns. app_dir is the app/ directory; lockfile sources are relative to its parent."""
    repo_root = Path(app_dir).resolve().parent
    lockfiles: dict[str, dict[str, dict[str, bool]]] = {}
    for f in findings:
        if f.category != "vuln" or f.tool != "trivy":
            continue
        f.hints = _hints(f, app_dir, repo_root, lockfiles)


def _hints(f: Finding, app_dir: Path, repo_root: Path,
           lockfiles: dict[str, dict[str, dict[str, bool]]]) -> list[str]:
    hints: list[str] = []
    name = f.location.rsplit("@", 1)[0] if "@" in f.location else f.location

    if f.relationship:
        hints.append(f"dependency: {f.relationship}")
    else:
        hints.append("dependency: image package (no lockfile relationship in the image report)")

    # A merged finding can come from several lockfiles: check each one, label each one.
    for source in f.sources:
        if source.startswith("trivy-fs:"):
            flags = _lockfile_flags(repo_root / source.split(":", 1)[1], lockfiles)
            if flags is None:
                hints.append(f"dependency flags: lockfile missing for {source}")
            elif flags.get(f.location, {}).get("devOptional"):
                hints.append(f"dependency: devOptional in {source} (Trivy counts it as production)")
            elif flags.get(f.location, {}).get("dev"):
                hints.append(f"dependency: dev only in {source}")

    has_image = any(s == "trivy-image" for s in f.sources)
    has_fs = any(s.startswith("trivy-fs:") for s in f.sources)
    if has_image and has_fs:
        hints.append("presence: image and fs")
    elif has_image:
        hints.append("presence: image only")
    else:
        hints.append("presence: fs only")

    if f.relationship is not None:
        hints.append(_stage_hint(f.top_parents))

    hits = _import_evidence(name, app_dir)
    if hits:
        shown = ", ".join(hits[:MAX_EVIDENCE_FILES])
        more = f" (+{len(hits) - MAX_EVIDENCE_FILES} more)" if len(hits) > MAX_EVIDENCE_FILES else ""
        hints.append(f"import: grep-level evidence in {shown}{more}")
    else:
        hints.append("import: no grep-level evidence in first-party backend code")
    return hints


def _stage_hint(top_parents: list[str]) -> str:
    if not top_parents:
        return "stage: no top parent found"
    unresolved = [t for t in top_parents if t.startswith("?")]
    if unresolved:
        return f"stage: parent chain incomplete ({', '.join(unresolved)})"
    names = [t.rsplit("@", 1)[0] for t in top_parents]
    if all(n in BUILD_TOOL_PARENTS for n in names):
        return f"stage: build stage only (via {', '.join(top_parents)})"
    return f"stage: reached from production dependency ({', '.join(top_parents)})"


def _lockfile_flags(path: Path, cache: dict[str, dict[str, dict[str, bool]]]) -> dict[str, dict[str, bool]] | None:
    """Map name@version to {devOptional, dev} read from the lockfile's packages map. None if the file is missing."""
    key = str(path)
    if key not in cache:
        if not path.exists():
            return None
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ParseError(f"{path}: lockfile is not readable JSON") from exc
        packages = doc.get("packages") if isinstance(doc, dict) else None
        if not isinstance(packages, dict):
            raise ParseError(f"{path}: lockfile has no packages map")
        flags: dict[str, dict[str, bool]] = {}
        for pkg_path, entry in packages.items():
            if not pkg_path or not isinstance(entry, dict) or "version" not in entry:
                continue
            name = pkg_path.rsplit("node_modules/", 1)[-1]
            flags[f"{name}@{entry['version']}"] = {
                "devOptional": bool(entry.get("devOptional")),
                "dev": bool(entry.get("dev")),
            }
        cache[key] = flags
    return cache[key]


def _import_evidence(name: str, app_dir: Path) -> list[str]:
    """Files under the backend dirs that import or require the package. Grep-level only; not a call graph."""
    pattern = re.compile(
        r"""require\(\s*['"]{0}['"]\s*\)|from\s+['"]{0}(?:/[^'"]*)?['"]""".format(re.escape(name))
    )
    files: list[Path] = []
    for d in IMPORT_DIRS:
        base = Path(app_dir) / d
        if base.is_dir():
            files += [p for p in base.rglob("*") if p.suffix in (".ts", ".js")]
    files += [Path(app_dir) / f for f in IMPORT_FILES if (Path(app_dir) / f).is_file()]
    data = Path(app_dir) / "data"
    if data.is_dir():
        files += [p for p in data.glob("*.ts") if p.is_file()]
    hits = []
    for p in sorted(set(files)):
        try:
            text = p.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if pattern.search(text):
            hits.append(p.relative_to(app_dir).as_posix())
    return hits

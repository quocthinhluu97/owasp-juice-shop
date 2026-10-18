"""ZAP baseline JSON (zap/zap.json) -> Finding (dast, one per alert per site, D20), and the rules.tsv parser (D14).

The JSON has no WARN/FAIL level. parse_rules() reads .zap/rules.tsv for that; policy.py applies it.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from triage.model import Finding, ParseError, map_severity
from triage.parsers.common import load_json, require_keys

RULE_LEVELS = frozenset({"IGNORE", "INFO", "WARN", "FAIL", "OUTOFSCOPE"})


def parse_zap(path: Path) -> list[Finding]:
    doc = load_json(path)
    require_keys(doc, ("site",), str(path))
    if not isinstance(doc["site"], list):
        raise ParseError(f"{path}: site is not a list")
    findings: list[Finding] = []
    for site in doc["site"]:
        require_keys(site, ("@name", "alerts"), f"{path}: site")
        if not isinstance(site["alerts"], list):
            raise ParseError(f"{path}: alerts is not a list")
        parts = urlsplit(site["@name"])
        if not parts.scheme or not parts.netloc:
            raise ParseError(f"{path}: site name {site['@name']!r} is not scheme://host:port")
        site_name = urlunsplit((parts.scheme, parts.netloc, "", "", ""))
        for alert in site["alerts"]:
            findings.append(_finding(site_name, alert, path))
    return findings


def parse_rules(path: Path) -> dict[str, str]:
    """Read .zap/rules.tsv: pluginid, LEVEL, (name), reason. Returns {pluginid: LEVEL}. Any bad line raises."""
    try:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ParseError(f"{path}: cannot read ({exc.strerror})") from exc
    rules: dict[str, str] = {}
    for n, line in enumerate(lines, start=1):
        if not line.strip() or line.startswith("#"):
            continue
        fields = line.split("\t")
        if len(fields) != 4:
            raise ParseError(f"{path}:{n}: expected 4 tab-separated fields, found {len(fields)}")
        plugin_id, level, _name, reason = fields
        if not plugin_id.isdigit():
            raise ParseError(f"{path}:{n}: pluginid {plugin_id!r} is not numeric")
        if level not in RULE_LEVELS:
            raise ParseError(f"{path}:{n}: level {level!r} is not one of {sorted(RULE_LEVELS)}")
        if not reason.strip():
            raise ParseError(f"{path}:{n}: empty reason (every rule needs one)")
        if plugin_id in rules:
            raise ParseError(f"{path}:{n}: duplicate pluginid {plugin_id}")
        rules[plugin_id] = level
    return rules


def _finding(site_name: str, alert: dict[str, Any], path: Path) -> Finding:
    """One Finding per alert per site (D20). Instances are kept for the report, not in the fingerprint."""
    where = f"{path}: alert"
    require_keys(alert, ("pluginid", "name", "riskcode", "instances"), where)
    if not isinstance(alert["instances"], list):
        raise ParseError(f"{where}: instances is not a list")
    plugin = alert["pluginid"]
    cwe_id = str(alert.get("cweid") or "")
    instances: set[str] = set()
    for inst in alert["instances"]:
        require_keys(inst, ("uri",), f"{where}: instance")
        url_path = urlsplit(inst["uri"]).path or "/"  # "" and "/" are the same path
        param = inst.get("param") or ""
        instances.add(f"{url_path} [param={param}]" if param else url_path)
    return Finding(
        tool="zap",
        rule_id=plugin,
        category="dast",
        severity=map_severity("zap", alert["riskcode"]),
        location=site_name,
        cwe=f"CWE-{cwe_id}" if cwe_id not in ("", "-1", "0") else None,
        # D20: pluginid + site. The site is scheme://host:port, from the site[] entry.
        fingerprint=f"dast:{plugin}:{site_name}",
        instances=sorted(instances),
        names=[alert["name"]],
        tools=["zap"],
        sources=["zap"],
    )

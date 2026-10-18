"""Waivers (gating-policy.md "Waivers", D12): load triage/waivers.yaml and apply it to findings.

Each waiver selects one finding by fingerprint, or by CVE + package. It needs a reason, an owner
(GitHub handle) and an expiry date. An expired waiver stops applying, so the finding blocks again.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any

import yaml

from triage.model import Finding, ParseError

EXPIRY_HORIZON_DAYS = 90  # D12: a waiver further out than this is an error (exit 2)
WARN_WITHIN_DAYS = 14  # D12: warn when a waiver expires within this many days
GITHUB_HANDLE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$")
CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,19}$")
ALLOWED_KEYS = {"fingerprint", "cve", "package", "reason", "owner", "expires"}


class WaiverError(ParseError):
    """A waiver file or entry is malformed. The CLI turns this into exit 2."""


@dataclass(frozen=True)
class Waiver:
    index: int  # position in the file, for messages
    reason: str
    owner: str
    expires: date  # last day the waiver applies (inclusive)
    fingerprint: str | None = None
    cve: str | None = None
    package: str | None = None

    def matches(self, finding: Finding) -> bool:
        if self.fingerprint is not None:
            return finding.fingerprint == self.fingerprint
        return finding.cve == self.cve and _package_of(finding) == self.package

    def label(self) -> str:
        sel = f"fingerprint {self.fingerprint}" if self.fingerprint else f"{self.cve} {self.package}"
        return f"waiver #{self.index} ({sel}, owner {self.owner}, expires {self.expires.isoformat()})"


@dataclass
class WaiverResult:
    active: list[Finding]  # not waived: still eligible to block
    waived: list[tuple[Finding, Waiver]]
    expired: list[Waiver]  # listed, not applied
    warnings: list[str] = field(default_factory=list)


def _package_of(finding: Finding) -> str | None:
    """Vuln location is name@version; the name is everything before the last @ (scoped names keep their @)."""
    if finding.category != "vuln" or "@" not in finding.location:
        return None
    return finding.location.rsplit("@", 1)[0]


def load_waivers(path: Path, today: date) -> list[Waiver]:
    try:
        doc = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    except OSError as exc:
        raise WaiverError(f"{path}: cannot read ({exc.strerror})") from exc
    except (yaml.YAMLError, ValueError) as exc:  # ValueError: an unquoted impossible date such as 2026-02-30
        raise WaiverError(f"{path}: not valid YAML (or a date that does not exist)") from exc
    if not isinstance(doc, dict) or "waivers" not in doc:
        raise WaiverError(f"{path}: top level must be a mapping with a 'waivers' list")
    if doc["waivers"] is None:
        return []
    if not isinstance(doc["waivers"], list):
        raise WaiverError(f"{path}: 'waivers' must be a list")
    return [_waiver(entry, i, path, today) for i, entry in enumerate(doc["waivers"], start=1)]


def _waiver(entry: Any, index: int, path: Path, today: date) -> Waiver:
    where = f"{path}: waiver #{index}"
    if not isinstance(entry, dict):
        raise WaiverError(f"{where}: must be a mapping")
    unknown = set(entry) - ALLOWED_KEYS
    if unknown:
        raise WaiverError(f"{where}: unknown key(s): {', '.join(sorted(unknown))}")
    for key in ("reason", "owner", "expires"):
        if key not in entry:
            raise WaiverError(f"{where}: missing required key {key!r}")

    has_fp = "fingerprint" in entry
    has_pair = "cve" in entry or "package" in entry
    if has_fp == has_pair:
        raise WaiverError(f"{where}: give exactly one selector: 'fingerprint' or 'cve' + 'package'")
    fingerprint = cve = package = None
    if has_fp:
        fingerprint = entry["fingerprint"]
        if not isinstance(fingerprint, str) or not fingerprint.strip():
            raise WaiverError(f"{where}: fingerprint must be a non-empty string")
    else:
        if "cve" not in entry or "package" not in entry:
            raise WaiverError(f"{where}: cve and package must be given together")
        cve, package = entry["cve"], entry["package"]
        if not isinstance(cve, str) or not CVE_ID.match(cve):
            raise WaiverError(f"{where}: cve must look like CVE-YYYY-NNNN")
        if not isinstance(package, str) or not package.strip():
            raise WaiverError(f"{where}: package must be a non-empty string")

    reason = entry["reason"]
    if not isinstance(reason, str) or not reason.strip():
        raise WaiverError(f"{where}: reason must be a non-empty string")
    owner = entry["owner"]
    if not isinstance(owner, str) or not GITHUB_HANDLE.match(owner):
        raise WaiverError(f"{where}: owner must be a GitHub handle")

    expires = _expiry(entry["expires"], where)
    if expires > today + timedelta(days=EXPIRY_HORIZON_DAYS):
        raise WaiverError(
            f"{where}: expires {expires.isoformat()} is more than {EXPIRY_HORIZON_DAYS} days after "
            f"{today.isoformat()}; shorten it or renew it when it is nearer"
        )
    return Waiver(index=index, reason=reason.strip(), owner=owner, expires=expires,
                  fingerprint=fingerprint, cve=cve, package=package)


def _expiry(value: Any, where: str) -> date:
    # YAML turns an unquoted 2026-12-31 into a date; a quoted one stays a string. Both must be YYYY-MM-DD.
    if isinstance(value, datetime):
        raise WaiverError(f"{where}: expires must be a date (YYYY-MM-DD), not a datetime")
    if isinstance(value, date):
        return value
    if isinstance(value, str) and re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
        try:
            return date.fromisoformat(value)
        except ValueError as exc:
            raise WaiverError(f"{where}: expires {value!r} is not a real date") from exc
    raise WaiverError(f"{where}: expires must be YYYY-MM-DD")


def apply_waivers(findings: list[Finding], waivers: list[Waiver], today: date) -> WaiverResult:
    """A waiver applies through its expiry date. Expired waivers apply to nothing and are listed.

    Warnings: a waiver expiring within WARN_WITHIN_DAYS, and a live waiver that matches no finding (stale).
    """
    result = WaiverResult(active=list(findings), waived=[], expired=[])
    live: list[Waiver] = []
    for w in waivers:
        if today > w.expires:
            result.expired.append(w)
        else:
            live.append(w)
            days_left = (w.expires - today).days
            if days_left <= WARN_WITHIN_DAYS:
                result.warnings.append(f"{w.label()} expires in {days_left} day(s)")

    matched_any: set[int] = set()
    still_active: list[Finding] = []
    for finding in result.active:
        hit = next((w for w in live if w.matches(finding)), None)
        if hit is None:
            still_active.append(finding)
        else:
            result.waived.append((finding, hit))
            matched_any.add(hit.index)
    result.active = still_active

    for w in live:
        if w.index not in matched_any:
            result.warnings.append(f"{w.label()} matches no finding (stale): remove it or fix the selector")
    return result

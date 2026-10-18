"""CISA KEV enrichment (D9): cache with a fetched_at sidecar, 24 h freshness, stale fallback up to 7 days.

Tests never reach the network: they pass a --kev-file style path, or an injected clock and fetch function.
"""

from __future__ import annotations

import http.client
import json
import re
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

from triage.model import Finding, ParseError

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
FRESH_FOR = timedelta(hours=24)  # D9: reuse the cache if fetched less than this long ago
STALE_OK_FOR = timedelta(days=7)  # D9: a cache up to this old is used with a warning when the download fails
FUTURE_SKEW = timedelta(minutes=5)  # a fetched_at this far after the clock is unusable: never treated as fresh
CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,19}$")
REQUIRED_TOP = ("catalogVersion", "dateReleased", "count", "vulnerabilities")


class KevError(ParseError):
    """No usable KEV feed (download failed and no cache within 7 days, or a bad file). Exit 2."""


@dataclass
class KevCatalog:
    catalog_version: str
    date_released: str
    cves: frozenset[str]
    source: str  # "file <path>", "download", or "cache (fetched <iso>)"
    warnings: list[str] = field(default_factory=list)


def load_kev_file(path: Path, source: str | None = None) -> KevCatalog:
    try:
        doc = json.loads(Path(path).read_text(encoding="utf-8"))
    except OSError as exc:
        raise KevError(f"{path}: cannot read ({exc.strerror})") from exc
    except json.JSONDecodeError as exc:
        raise KevError(f"{path}: not valid JSON") from exc
    if not isinstance(doc, dict) or any(k not in doc for k in REQUIRED_TOP):
        raise KevError(f"{path}: not a KEV catalog (needs {', '.join(REQUIRED_TOP)})")
    if not isinstance(doc["vulnerabilities"], list):
        raise KevError(f"{path}: vulnerabilities is not a list")
    # A cut-off download still parses as JSON. The count and the list must agree, and the list is never empty.
    if not doc["vulnerabilities"]:
        raise KevError(f"{path}: vulnerabilities is empty (truncated feed?)")
    if doc["count"] != len(doc["vulnerabilities"]):
        raise KevError(f"{path}: count is {doc['count']} but the feed lists {len(doc['vulnerabilities'])} "
                       "entries (truncated feed?)")
    cves: set[str] = set()
    for entry in doc["vulnerabilities"]:
        cve = entry.get("cveID") if isinstance(entry, dict) else None
        if not isinstance(cve, str) or not CVE_ID.match(cve):
            raise KevError(f"{path}: an entry has a cveID that is not CVE-YYYY-NNNN")
        cves.add(cve)
    return KevCatalog(
        catalog_version=str(doc["catalogVersion"]),
        date_released=str(doc["dateReleased"]),
        cves=frozenset(cves),
        source=source or f"file {path}",
    )


def download_kev(dest: Path, timeout: float = 30) -> None:
    """Fetch the feed to dest, validated before it replaces anything. Network errors raise KevError."""
    try:
        with urllib.request.urlopen(KEV_URL, timeout=timeout) as resp:  # noqa: S310 (fixed https URL)
            body = resp.read()
    except (urllib.error.URLError, http.client.HTTPException, TimeoutError, OSError) as exc:
        # HTTPException covers a cut-off body (IncompleteRead) and a bad status line: both are outages.
        raise KevError(f"KEV download failed: {exc}") from exc
    tmp = Path(str(dest) + ".tmp")
    tmp.parent.mkdir(parents=True, exist_ok=True)
    tmp.write_bytes(body)
    try:
        load_kev_file(tmp, source="download")  # validate before replacing the cache
    except KevError:
        tmp.unlink(missing_ok=True)
        raise
    tmp.replace(dest)


def get_kev(
    cache_dir: Path,
    now: datetime,
    *,
    offline: bool = False,
    kev_file: Path | None = None,
    fetch: Callable[[Path], None] = download_kev,
) -> KevCatalog:
    """Return the catalog to use, following D9. now must be timezone-aware."""
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    if kev_file is not None:
        return load_kev_file(kev_file)

    cache = Path(cache_dir) / "kev.json"
    meta = Path(cache_dir) / "kev.json.meta"
    fetched_at = _read_fetched_at(meta) if cache.exists() else None
    if fetched_at is not None and fetched_at - now > FUTURE_SKEW:
        fetched_at = None  # unknown age (clock skew or a bad sidecar): never fresh, never a fallback
    if fetched_at is not None and now - fetched_at < FRESH_FOR:
        return _cached(cache, fetched_at)

    failure = "offline" if offline else None
    if not offline:
        try:
            fetch(cache)
            _write_meta(meta, now)
            return load_kev_file(cache, source="download")
        except KevError as exc:
            failure = str(exc)

    if fetched_at is not None and now - fetched_at <= STALE_OK_FOR:
        cat = _cached(cache, fetched_at)
        cat.warnings.append(
            f"KEV feed is {int((now - fetched_at).total_seconds() // 3600)} h old ({failure}); using the cache"
        )
        return cat
    raise KevError(
        f"no usable KEV feed: {failure}; cache is "
        + ("missing" if fetched_at is None and not cache.exists() else "older than 7 days or has no fetched_at")
    )


def _cached(cache: Path, fetched_at: datetime) -> KevCatalog:
    return load_kev_file(cache, source=f"cache (fetched {fetched_at.isoformat()})")


def _read_fetched_at(meta: Path) -> datetime | None:
    if not meta.exists():
        return None
    try:
        raw = json.loads(meta.read_text(encoding="utf-8"))["fetched_at"]
        value = datetime.fromisoformat(raw)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise KevError(f"{meta}: unreadable fetched_at sidecar") from exc
    if value.tzinfo is None:
        raise KevError(f"{meta}: fetched_at has no timezone")
    return value


def _write_meta(meta: Path, now: datetime) -> None:
    meta.parent.mkdir(parents=True, exist_ok=True)
    meta.write_text(json.dumps({"fetched_at": now.astimezone(timezone.utc).isoformat(), "url": KEV_URL}) + "\n",
                    encoding="utf-8")


def annotate_kev(findings: list[Finding], catalog: KevCatalog) -> None:
    """Set Finding.kev for vulns. A non-CVE id is "not_checkable", never "not_in_kev"."""
    for f in findings:
        if f.category != "vuln":
            continue
        if f.cve is None:
            f.kev = "not_checkable"
        else:
            f.kev = "in_kev" if f.cve in catalog.cves else "not_in_kev"

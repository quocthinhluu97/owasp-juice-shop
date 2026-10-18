"""KEV enrichment (D9). No test touches the network: urllib is replaced by a guard that fails the test if it is called.

Clock and fetch are injected. The download function itself is tested with a fake urlopen response.
"""

import http.client
import io
import json
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from triage import enrich
from triage.enrich import KevError, annotate_kev, download_kev, get_kev, load_kev_file
from triage.model import Finding

FIXTURE = Path(__file__).parent / "fixtures" / "kev.json"
NOW = datetime(2026, 10, 18, 12, 0, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError("network call attempted from a test")

    monkeypatch.setattr(urllib.request, "urlopen", refuse)


def _no_fetch(dest):
    raise AssertionError("fetch must not be called in this test")


def _fetch_writes_fixture(dest):
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(FIXTURE.read_bytes())


def _fetch_fails(dest):
    raise KevError("KEV download failed: simulated outage")


def _cache(cache_dir: Path, fetched_at: datetime):
    cache_dir.mkdir(parents=True, exist_ok=True)
    (cache_dir / "kev.json").write_bytes(FIXTURE.read_bytes())
    (cache_dir / "kev.json.meta").write_text(json.dumps({"fetched_at": fetched_at.isoformat()}), encoding="utf-8")


def _finding(cve, location="pkg@1.0.0", category="vuln"):
    return Finding(tool="trivy", rule_id=cve or "GHSA-x", category=category, severity="high",
                   location=location, fingerprint=f"vuln:{cve}:{location}", cve=cve)


# loading the file

def test_load_fixture_catalog():
    cat = load_kev_file(FIXTURE)
    assert cat.catalog_version == "2026.10.02"
    assert "CVE-2099-0001" in cat.cves and len(cat.cves) == 4


def test_bad_cve_id_in_feed_is_kev_error(tmp_path):
    bad = tmp_path / "kev.json"
    bad.write_text(json.dumps({"catalogVersion": "x", "dateReleased": "x", "count": 1,
                               "vulnerabilities": [{"cveID": "GHSA-1234-abcd"}]}), encoding="utf-8")
    with pytest.raises(KevError, match="cveID"):
        load_kev_file(bad)


def test_empty_vulnerability_list_is_kev_error(tmp_path):
    bad = tmp_path / "kev.json"
    bad.write_text(json.dumps({"catalogVersion": "x", "dateReleased": "x", "count": 0,
                               "vulnerabilities": []}), encoding="utf-8")
    with pytest.raises(KevError, match="empty"):
        load_kev_file(bad)


def test_count_mismatch_is_kev_error_as_truncated_feed(tmp_path):
    bad = tmp_path / "kev.json"
    bad.write_text(json.dumps({"catalogVersion": "x", "dateReleased": "x", "count": 2,
                               "vulnerabilities": [{"cveID": "CVE-2099-0001"}]}), encoding="utf-8")
    with pytest.raises(KevError, match="truncated"):
        load_kev_file(bad)


def test_missing_top_level_key_is_kev_error(tmp_path):
    bad = tmp_path / "kev.json"
    bad.write_text(json.dumps({"vulnerabilities": []}), encoding="utf-8")
    with pytest.raises(KevError):
        load_kev_file(bad)


# get_kev: freshness, injected clock

def test_explicit_kev_file_is_used_without_cache_or_fetch(tmp_path):
    cat = get_kev(tmp_path / "cache", NOW, kev_file=FIXTURE, fetch=_no_fetch)
    assert cat.source.startswith("file ")
    assert not (tmp_path / "cache").exists()


def test_fresh_cache_under_24h_is_reused_without_fetch(tmp_path):
    _cache(tmp_path, NOW - timedelta(hours=23))
    cat = get_kev(tmp_path, NOW, fetch=_no_fetch)
    assert cat.source.startswith("cache (fetched")
    assert cat.warnings == []


def test_cache_older_than_24h_is_refreshed(tmp_path):
    _cache(tmp_path, NOW - timedelta(hours=25))
    cat = get_kev(tmp_path, NOW, fetch=_fetch_writes_fixture)
    assert cat.source == "download"
    meta = json.loads((tmp_path / "kev.json.meta").read_text(encoding="utf-8"))
    assert datetime.fromisoformat(meta["fetched_at"]) == NOW


def test_no_cache_and_download_fails_is_error(tmp_path):
    with pytest.raises(KevError, match="no usable KEV feed"):
        get_kev(tmp_path, NOW, fetch=_fetch_fails)


def test_download_fails_with_cache_2_days_old_uses_cache_with_warning(tmp_path):
    _cache(tmp_path, NOW - timedelta(days=2))
    cat = get_kev(tmp_path, NOW, fetch=_fetch_fails)
    assert cat.source.startswith("cache (fetched")
    assert any("using the cache" in w for w in cat.warnings)


def test_download_fails_with_cache_8_days_old_is_error(tmp_path):
    _cache(tmp_path, NOW - timedelta(days=8))
    with pytest.raises(KevError, match="older than 7 days"):
        get_kev(tmp_path, NOW, fetch=_fetch_fails)


def test_cache_exactly_7_days_old_is_still_usable(tmp_path):
    _cache(tmp_path, NOW - timedelta(days=7))
    cat = get_kev(tmp_path, NOW, fetch=_fetch_fails)
    assert cat.warnings


def test_offline_fresh_cache_does_not_fetch(tmp_path):
    _cache(tmp_path, NOW - timedelta(hours=1))
    assert get_kev(tmp_path, NOW, offline=True, fetch=_no_fetch).source.startswith("cache")


def test_offline_stale_cache_uses_it_with_warning_and_no_fetch(tmp_path):
    _cache(tmp_path, NOW - timedelta(days=3))
    cat = get_kev(tmp_path, NOW, offline=True, fetch=_no_fetch)
    assert any("using the cache" in w for w in cat.warnings)


def test_offline_without_cache_is_error(tmp_path):
    with pytest.raises(KevError):
        get_kev(tmp_path, NOW, offline=True, fetch=_no_fetch)


def test_cache_without_sidecar_counts_as_unknown_age(tmp_path):
    tmp_path.mkdir(exist_ok=True)
    (tmp_path / "kev.json").write_bytes(FIXTURE.read_bytes())
    with pytest.raises(KevError):
        get_kev(tmp_path, NOW, offline=True, fetch=_no_fetch)


def test_sidecar_slightly_in_future_is_still_fresh(tmp_path):
    _cache(tmp_path, NOW + timedelta(minutes=2))
    cat = get_kev(tmp_path, NOW, fetch=_no_fetch)
    assert cat.source.startswith("cache (fetched")


def test_sidecar_far_in_future_is_not_fresh_and_is_refetched(tmp_path):
    _cache(tmp_path, NOW + timedelta(hours=1))
    cat = get_kev(tmp_path, NOW, fetch=_fetch_writes_fixture)
    assert cat.source == "download"


def test_sidecar_far_in_future_is_no_fallback_when_download_fails(tmp_path):
    _cache(tmp_path, NOW + timedelta(hours=1))
    with pytest.raises(KevError, match="no usable KEV feed"):
        get_kev(tmp_path, NOW, fetch=_fetch_fails)


def test_corrupt_sidecar_is_error(tmp_path):
    _cache(tmp_path, NOW)
    (tmp_path / "kev.json.meta").write_text("not json", encoding="utf-8")
    with pytest.raises(KevError, match="fetched_at"):
        get_kev(tmp_path, NOW, fetch=_no_fetch)


def test_naive_clock_is_rejected(tmp_path):
    with pytest.raises(ValueError):
        get_kev(tmp_path, datetime(2026, 10, 18, 12, 0), fetch=_no_fetch)


# download_kev with a fake response (urlopen replaced, never the network)

class _FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_download_writes_validated_feed(tmp_path, monkeypatch):
    monkeypatch.setattr(urllib.request, "urlopen", lambda url, timeout: _FakeResponse(FIXTURE.read_bytes()))
    dest = tmp_path / "kev.json"
    download_kev(dest)
    assert dest.exists() and not (tmp_path / "kev.json.tmp").exists()
    assert load_kev_file(dest).catalog_version == "2026.10.02"


def test_download_rejects_bad_body_and_keeps_old_cache(tmp_path, monkeypatch):
    dest = tmp_path / "kev.json"
    dest.write_text("old good copy", encoding="utf-8")
    monkeypatch.setattr(urllib.request, "urlopen", lambda url, timeout: _FakeResponse(b"<html>error</html>"))
    with pytest.raises(KevError):
        download_kev(dest)
    assert dest.read_text(encoding="utf-8") == "old good copy"
    assert not (tmp_path / "kev.json.tmp").exists()


def test_download_network_error_is_kev_error(tmp_path, monkeypatch):
    def boom(url, timeout):
        raise urllib.error.URLError("simulated")

    monkeypatch.setattr(urllib.request, "urlopen", boom)
    with pytest.raises(KevError, match="download failed"):
        download_kev(tmp_path / "kev.json")


class _BrokenResponse:
    """A body that stops early, as a dropped connection does: read() raises IncompleteRead."""

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self):
        raise http.client.IncompleteRead(b'{"catalogVersion": "x"')


def test_download_truncated_body_keeps_old_cache(tmp_path, monkeypatch):
    dest = tmp_path / "kev.json"
    dest.write_text("old good copy", encoding="utf-8")
    body = json.loads(FIXTURE.read_text(encoding="utf-8"))
    body["vulnerabilities"] = body["vulnerabilities"][:1]  # count says 4, one entry arrives
    monkeypatch.setattr(urllib.request, "urlopen", lambda url, timeout: _FakeResponse(json.dumps(body).encode()))
    with pytest.raises(KevError, match="truncated"):
        download_kev(dest)
    assert dest.read_text(encoding="utf-8") == "old good copy"


def test_download_incomplete_read_is_kev_error(tmp_path, monkeypatch):
    dest = tmp_path / "kev.json"
    dest.write_text("old good copy", encoding="utf-8")
    monkeypatch.setattr(urllib.request, "urlopen", lambda url, timeout: _BrokenResponse())
    with pytest.raises(KevError, match="download failed"):
        download_kev(dest)
    assert dest.read_text(encoding="utf-8") == "old good copy"


def test_incomplete_read_falls_back_to_stale_cache(tmp_path, monkeypatch):
    _cache(tmp_path, NOW - timedelta(days=2))
    monkeypatch.setattr(urllib.request, "urlopen", lambda url, timeout: _BrokenResponse())
    cat = get_kev(tmp_path, NOW, fetch=download_kev)
    assert cat.source.startswith("cache (fetched")
    assert any("using the cache" in w for w in cat.warnings)


def test_download_uses_fixed_cisa_url(tmp_path, monkeypatch):
    seen = []

    def record(url, timeout):
        seen.append(url)
        return _FakeResponse(FIXTURE.read_bytes())

    monkeypatch.setattr(urllib.request, "urlopen", record)
    download_kev(tmp_path / "kev.json")
    assert seen == [enrich.KEV_URL]
    assert enrich.KEV_URL.startswith("https://www.cisa.gov/")


# annotate_kev

def test_kev_states_for_vulns():
    cat = load_kev_file(FIXTURE)
    findings = [
        _finding("CVE-2099-0001"),  # synthetic KEV entry in the fixture
        _finding("CVE-2026-59310"),  # real KEV entry in the fixture
        _finding("CVE-2026-19481"),  # real CVE, not in the fixture catalog
        _finding(None, location="base64url@0.0.6"),  # GHSA-style id: not checkable
    ]
    findings[3].rule_id = "GHSA-rvg8-pwq2-xj7q"
    annotate_kev(findings, cat)
    assert [f.kev for f in findings] == ["in_kev", "in_kev", "not_in_kev", "not_checkable"]


def test_non_vuln_findings_get_no_kev_state():
    cat = load_kev_file(FIXTURE)
    f = _finding("CVE-2099-0001", category="code")
    annotate_kev([f], cat)
    assert f.kev is None

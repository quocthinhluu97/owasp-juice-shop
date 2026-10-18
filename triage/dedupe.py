"""Dedupe on the fingerprint (D5), then merge Semgrep generic.secrets into Gitleaks (D6).

One output Finding per fingerprint. tools[] and sources[] collect every tool and report that saw it.
"""

from __future__ import annotations

from dataclasses import replace

from triage.model import Finding


def dedupe(findings: list[Finding]) -> list[Finding]:
    merged: dict[str, Finding] = {}
    for f in findings:
        if f.fingerprint not in merged:
            merged[f.fingerprint] = replace(f, tools=list(f.tools), sources=list(f.sources))
        else:
            _absorb(merged[f.fingerprint], f)
    return _merge_semgrep_secrets(list(merged.values()))


def _absorb(into: Finding, other: Finding) -> None:
    for tool in other.tools:
        if tool not in into.tools:
            into.tools.append(tool)
    for source in other.sources:
        if source not in into.sources:
            into.sources.append(source)
    into.instances = sorted(set(into.instances) | set(other.instances))
    # ZAP variants that share a pluginid keep every distinct alert name (the gate never reads names).
    into.names = _union(into.names, other.names)
    # Lockfile facts come from the fs side; the image side has none. Keep every value visible, never pick one.
    into.parents = _union(into.parents, other.parents)
    into.top_parents = _union(into.top_parents, other.top_parents)
    into.relationship = _join_relationships(into.relationship, other.relationship)


def _union(a: list[str], b: list[str]) -> list[str]:
    out = list(a)
    for x in b:
        if x not in out:
            out.append(x)
    return out


def _join_relationships(a: str | None, b: str | None) -> str | None:
    """None is "no lockfile relationship" (image). Equal values stay one. Different values are kept side by side,
    e.g. "direct / indirect" when the same name@version is direct in one lockfile and indirect in another."""
    values: list[str] = []
    for v in (a, b):
        if v is not None and v not in values:
            values.append(v)
    return " / ".join(values) if values else None


def _merge_semgrep_secrets(findings: list[Finding]) -> list[Finding]:
    """A Semgrep generic.secrets finding folds into the Gitleaks finding at the same file:line (tolerance 0).

    Only the first matching Gitleaks finding absorbs it. Semgrep secrets with no match stay as they are:
    policy reports them and never gates on them (gating-policy.md rule 4).
    """
    gitleaks_at: dict[str, Finding] = {}
    for f in findings:
        if f.tool == "gitleaks":
            gitleaks_at.setdefault(f.location, f)
    kept: list[Finding] = []
    for f in findings:
        if f.tool == "semgrep" and f.category == "secret" and f.location in gitleaks_at:
            _absorb(gitleaks_at[f.location], f)
            continue
        kept.append(f)
    return kept

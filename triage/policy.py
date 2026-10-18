"""The gating rule (gating-policy.md, rules 1-6). This module is the source of truth for the gate.

evaluate() gives every active (not waived) finding a Verdict: blocking or not, the rule number, one
sentence of why, and the next step. A non-blocking Verdict also records the written reason it does not gate.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit

from triage.model import Finding

# D7 / gating-policy.md rule 3: top-level packages that only exist in the build stage. A frontend-lockfile
# vuln whose top parents are all in this list is labelled "build stage only" (reported, not gated).
# The list is short and named on purpose; anything else gates.
BUILD_TOOL_PARENTS: frozenset[str] = frozenset({
    "@angular/build",
    "@angular/cli",
    "@angular/compiler-cli",
    "@cyclonedx/cyclonedx-esbuild",
    "sass",
    "typescript",
    "vitest",
    "jsdom",
})

# gating-policy.md rule 5: the only Checkov checks that gate, and only in app/Dockerfile and .github/workflows/.
RULE5_CHECKS: frozenset[str] = frozenset({
    "CKV_DOCKER_3",
    "CKV_DOCKER_8",
    "CKV_DOCKER_1",
    "CKV_DOCKER_7",
    "CKV_GHA_2",
    "CKV2_GHA_1",
    "CKV_GHA_1",
})
RULE5_FILES: frozenset[str] = frozenset({"/app/Dockerfile"})
RULE5_DIRS: tuple[str, ...] = ("/.github/workflows/",)

# gating-policy.md rule 6 applies to the app itself; alerts on other sites are report only (D14).
ZAP_SITE = "juice:3000"
GATING_SEVERITIES: frozenset[str] = frozenset({"critical", "high"})


@dataclass(frozen=True)
class Verdict:
    blocking: bool
    rule: str | None  # "rule 1" .. "rule 6", or None when no gating rule is about this finding
    why: str  # one sentence: why it blocks, or the written reason it does not
    next_step: str  # what the developer does next


def evaluate(findings: list[Finding], zap_rules: dict[str, str]) -> list[tuple[Finding, Verdict]]:
    """Verdict for each finding. zap_rules is {pluginid: LEVEL} from .zap/rules.tsv (D14)."""
    return [(f, _verdict(f, zap_rules)) for f in findings]


def _verdict(f: Finding, zap_rules: dict[str, str]) -> Verdict:
    if f.tool == "gitleaks" and f.category == "secret":
        return _rule1(f)
    if f.tool == "semgrep" and f.category == "secret":
        return _semgrep_secret(f)
    if f.tool == "trivy" and f.category == "vuln":
        return _vuln(f)
    if f.tool == "semgrep" and f.category == "code":
        return _semgrep_code(f)
    if f.tool == "checkov" and f.category == "iac":
        return _checkov(f)
    if f.tool == "zap" and f.category == "dast":
        return _zap(f, zap_rules)
    return Verdict(False, None, f"{f.tool} {f.category}: no gating rule applies", "none")


# rule 1

def _rule1(f: Finding) -> Verdict:
    return Verdict(
        True, "rule 1",
        f"Gitleaks found a secret ({f.rule_id}) that is not waived; a leaked credential is always actionable.",
        "Rotate the credential, remove it from the code and history, then waive only a deliberate fake.",
    )


def _semgrep_secret(f: Finding) -> Verdict:
    return Verdict(
        False, "rule 4",
        "Semgrep generic.secrets with no Gitleaks finding at the same file and line: reported, never blocks; "
        "secrets are rule 1's job.",
        "Check whether Gitleaks should see this line; no action is needed for the gate.",
    )


# rules 2 and 3

def _vuln(f: Finding) -> Verdict:
    in_scope, scope = _scope(f)
    if f.kev == "in_kev":
        # D19: rule 2 gates everywhere, in any scope, including build-stage-only packages.
        return Verdict(
            True, "rule 2",
            f"{f.cve} is in CISA KEV (known exploited) in {scope}; KEV gates at any severity and in any scope (D19).",
            "Upgrade to a fixed version (fixed_version), or waive with a reason and an expiry.",
        )
    if f.severity not in GATING_SEVERITIES:
        return Verdict(False, None, f"{f.severity} severity is not a gating class (rules 2 and 3 gate critical/high or KEV).", "none")
    if not in_scope:
        return Verdict(
            False, "rule 3",
            f"{f.severity} {f.rule_id} is {scope}: reported, not gated by rule 3 (D7 build-tool exception).",
            "Nothing to do for the gate; upgrade when convenient.",
        )
    if not f.fixed_version:
        return Verdict(
            False, "rule 3",
            f"{f.severity} {f.rule_id} has no fix available: reported, not blocking, because the developer cannot act on it.",
            "Watch for a fixed release; waive only with a reason.",
        )
    chain = " A parent chain is incomplete, so the build-stage check could not be made." if _incomplete(f) else ""
    return Verdict(
        True, "rule 3",
        f"{f.severity} {f.rule_id} in {f.location} has a fix ({', '.join(f.fixed_version)}) and is in {scope}.{chain}",
        f"Upgrade {f.location.rsplit('@', 1)[0]} to one of: {', '.join(f.fixed_version)}, or waive with a reason.",
    )


def _incomplete(f: Finding) -> bool:
    return any(p.startswith("?") for p in f.top_parents)


def _scope(f: Finding) -> tuple[bool, str]:
    """(in the final image or production dependencies, label). Root lockfile and image gate as written (D7)."""
    if any(s == "trivy-image" for s in f.sources):
        return True, "the final image"
    fs = [s for s in f.sources if s.startswith("trivy-fs:")]
    if not fs:
        return True, "an unknown source (gated as written)"
    if any(not s.endswith("frontend/package-lock.json") for s in fs):
        return True, "production dependencies (root lockfile)"
    if _incomplete(f) or not f.top_parents:
        return True, "production dependencies (frontend, chain incomplete)"
    names = [p.rsplit("@", 1)[0] for p in f.top_parents]
    if all(n in BUILD_TOOL_PARENTS for n in names):
        return False, f"build stage only (via {', '.join(f.top_parents)})"
    return True, f"production dependencies (frontend, via {', '.join(f.top_parents)})"


# rule 4

def _semgrep_code(f: Finding) -> Verdict:
    path = f.location.rsplit(":", 1)[0]
    excluded = _rule4_excluded(path)
    if excluded is not None:
        return Verdict(False, "rule 4", excluded, "Nothing to do for the gate.")
    if f.severity in GATING_SEVERITIES:
        return Verdict(
            True, "rule 4",
            f"Semgrep {f.rule_id} is {f.severity} (ERROR/HIGH/CRITICAL) in first-party code at {f.location}.",
            "Fix the code at that line, or waive with a reason and an expiry.",
        )
    return Verdict(False, "rule 4", f"Semgrep severity {f.severity} is below ERROR/HIGH/CRITICAL: report only.",
                   "Nothing to do for the gate.")


def _rule4_excluded(path: str) -> str | None:
    if path.startswith(("app/terraform/", "app/infrastructure/")):
        return "challenge material (misplaced IaC files): reported, never blocks (rule 4)"
    if path.endswith(".npmrc"):
        return "package-manager config, not code: reported, never blocks (rule 4)"
    if "node_modules/" in path:
        return "under node_modules: not first-party code (rule 4 scope)"
    if path.startswith("app/test/") or path.endswith(".spec.ts"):
        return "test code: not first-party code (rule 4 scope)"
    if path.startswith(("app/frontend/dist/", "app/build/")):
        return "frontend build output: not first-party code (rule 4 scope)"
    if not path.startswith("app/"):
        return "outside app/: not first-party code (rule 4 scope)"
    return None


# rule 5

def _checkov(f: Finding) -> Verdict:
    path = f.location.rsplit(":", 1)[0]
    if path.startswith("/app/infrastructure/"):
        return Verdict(False, "rule 5", f"{f.rule_id} in app/infrastructure: challenge material, reported never gates (rule 5).",
                       "Nothing to do for the gate.")
    in_gated_file = path in RULE5_FILES or path.startswith(RULE5_DIRS)
    if f.rule_id in RULE5_CHECKS and in_gated_file:
        return Verdict(
            True, "rule 5",
            f"Checkov {f.rule_id} fails in {path}: a high-impact check on the image or a workflow (rule 5 list).",
            "Fix the file as the check describes, or waive with a reason and an expiry.",
        )
    if f.rule_id not in RULE5_CHECKS:
        return Verdict(False, "rule 5", f"{f.rule_id} is not in the rule 5 list: report only, rule 5.",
                       "Nothing to do for the gate.")
    return Verdict(False, "rule 5", f"{f.rule_id} is in the rule 5 list but outside app/Dockerfile and "
                   ".github/workflows/: report only, rule 5.", "Nothing to do for the gate.")


# rule 6

def _zap(f: Finding, zap_rules: dict[str, str]) -> Verdict:
    parts = urlsplit(f.location)  # D20: location is the site (scheme://host:port)
    if parts.netloc != ZAP_SITE:
        return Verdict(False, "rule 6", f"Alert on {parts.netloc or 'another site'}: report only (D14; rule 6 is for the app).",
                       "Nothing to do for the gate.")
    level = zap_rules.get(f.rule_id)
    if level is None:
        return Verdict(False, "rule 6", f"Plugin {f.rule_id} is not in .zap/rules.tsv: report only (D14).",
                       "Add a level and a reason to rules.tsv if it should gate.")
    if level == "FAIL":
        return Verdict(
            True, "rule 6",
            f"ZAP plugin {f.rule_id} is FAIL in .zap/rules.tsv and fired on {f.location} ({len(f.instances)} instance(s)).",
            "Fix the app behaviour (see docs/findings/zap.md), or waive with a reason and an expiry.",
        )
    return Verdict(False, "rule 6", f"ZAP plugin {f.rule_id} is {level} in .zap/rules.tsv: report only (rule 6 gates FAIL).",
                   "Nothing to do for the gate.")

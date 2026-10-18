"""Gating rules 1-6 (gating-policy.md). Each rule has a blocking case and a non-blocking case."""

import pytest

from triage.model import Finding
from triage.policy import BUILD_TOOL_PARENTS, evaluate

ZAP_RULES = {"10028": "FAIL", "10038": "FAIL", "10115": "FAIL", "10020": "WARN", "10110": "WARN", "10049": "IGNORE"}


def _one(finding, zap_rules=ZAP_RULES):
    ((_, verdict),) = evaluate([finding], zap_rules)
    return verdict


def _vuln(location="pkg@1.0.0", severity="high", sources=("trivy-image",), fixed=("1.0.1",), kev=None,
          top_parents=(), relationship=None, cve="CVE-2099-0001"):
    return Finding(tool="trivy", rule_id=cve or "GHSA-x", category="vuln", severity=severity, location=location,
                   fingerprint=f"vuln:{location}", cve=cve, fixed_version=list(fixed), kev=kev,
                   top_parents=list(top_parents), relationship=relationship, sources=list(sources),
                   tools=["trivy"])


def _code(location, severity, rule="javascript.x.rule"):
    return Finding(tool="semgrep", rule_id=rule, category="code", severity=severity, location=location,
                   fingerprint=f"code:{location}", tools=["semgrep"], sources=["semgrep"])


def _iac(check, path, line=1):
    return Finding(tool="checkov", rule_id=check, category="iac", severity="info", location=f"{path}:{line}",
                   fingerprint=f"iac:{check}:{path}:{line}", tools=["checkov"], sources=["checkov"])


def _dast(plugin, location):
    return Finding(tool="zap", rule_id=plugin, category="dast", severity="high", location=location,
                   fingerprint=f"dast:{plugin}:http://juice:3000", tools=["zap"], sources=["zap"])


def _secret(tool="gitleaks", location="app/data/static/users.yml:151", rule="generic-api-key"):
    return Finding(tool=tool, rule_id=rule, category="secret", severity="high", location=location,
                   fingerprint=f"secret:{rule}:{location}", tools=[tool], sources=[tool])


# rule 1

def test_rule1_gitleaks_secret_blocks():
    v = _one(_secret())
    assert v.blocking and v.rule == "rule 1"


def test_rule1_semgrep_only_secret_does_not_block():
    v = _one(_secret(tool="semgrep", rule="generic.secrets.x"))
    assert not v.blocking and v.rule == "rule 4"
    assert "rule 1's job" in v.why


# rule 2

def test_rule2_kev_in_image_blocks_at_any_severity():
    v = _one(_vuln(severity="low", kev="in_kev"))
    assert v.blocking and v.rule == "rule 2"


def test_rule2_kev_build_stage_only_blocks():
    # D19: rule 2 gates in every scope, including build-stage-only packages.
    v = _one(_vuln(sources=("trivy-fs:app/frontend/package-lock.json",), relationship="indirect",
                   top_parents=["jsdom@29.1.1"], kev="in_kev", severity="high"))
    assert v.blocking and v.rule == "rule 2"
    assert "build stage only" in v.why


def test_same_package_not_in_kev_stays_report_only_under_rule3():
    v = _one(_vuln(sources=("trivy-fs:app/frontend/package-lock.json",), relationship="indirect",
                   top_parents=["jsdom@29.1.1"], kev="not_in_kev", severity="high"))
    assert not v.blocking and v.rule == "rule 3"


def test_rule2_not_checkable_id_does_not_block_on_kev():
    v = _one(_vuln(severity="low", kev="not_checkable", cve=None))
    assert not v.blocking


# rule 3

def test_rule3_high_with_fix_in_image_blocks():
    v = _one(_vuln(severity="high", fixed=("3.2.1",)))
    assert v.blocking and v.rule == "rule 3"
    assert "3.2.1" in v.next_step


def test_rule3_no_fix_is_reported_not_blocking():
    v = _one(_vuln(severity="critical", fixed=()))
    assert not v.blocking and v.rule == "rule 3"
    assert "no fix available" in v.why


def test_rule3_medium_is_not_a_gating_class():
    v = _one(_vuln(severity="medium"))
    assert not v.blocking and v.rule is None


def test_rule3_frontend_build_tool_chain_is_build_stage_only():
    v = _one(_vuln(sources=("trivy-fs:app/frontend/package-lock.json",), relationship="indirect",
                   top_parents=["@angular/build@22.1.3", "@angular/cli@22.1.3"]))
    assert not v.blocking and v.rule == "rule 3"
    assert "build stage only" in v.why


def test_rule3_one_parent_outside_the_list_gates():
    v = _one(_vuln(sources=("trivy-fs:app/frontend/package-lock.json",), relationship="indirect",
                   top_parents=["jsdom@29.1.1", "@angular/core@22.1.1"]))
    assert v.blocking and v.rule == "rule 3"


def test_rule3_incomplete_chain_gates_with_hint():
    v = _one(_vuln(sources=("trivy-fs:app/frontend/package-lock.json",), relationship="indirect",
                   top_parents=["?ajv@8.20.0"]))
    assert v.blocking and v.rule == "rule 3"
    assert "incomplete" in v.why


def test_rule3_root_lockfile_gates_even_for_a_build_list_name():
    # D7: the build-tool exception is for the frontend lockfile only. Root lockfile gates as written.
    v = _one(_vuln(sources=("trivy-fs:app/package-lock.json",), relationship="direct",
                   top_parents=["typescript@6.0.3"]))
    assert v.blocking and v.rule == "rule 3"


def test_build_tool_list_is_the_documented_eight():
    assert BUILD_TOOL_PARENTS == frozenset({
        "@angular/build", "@angular/cli", "@angular/compiler-cli", "@cyclonedx/cyclonedx-esbuild",
        "sass", "typescript", "vitest", "jsdom",
    })


# rule 4

@pytest.mark.parametrize("severity", ["high", "critical"])
def test_rule4_error_or_critical_first_party_blocks(severity):
    v = _one(_code("app/routes/login.ts:34", severity))
    assert v.blocking and v.rule == "rule 4"


def test_rule4_warning_is_not_blocking():
    v = _one(_code("app/routes/redirect.ts:18", "medium"))
    assert not v.blocking


@pytest.mark.parametrize("location, reason", [
    ("app/terraform/networking.tf:18", "challenge material"),
    ("app/infrastructure/terraform/networking.tf:18", "challenge material"),
    ("app/.npmrc:1", "package-manager config"),
    ("app/frontend/.npmrc:1", "package-manager config"),
    ("app/node_modules/x/index.ts:3", "node_modules"),
    ("app/test/smoke.ts:3", "test code"),
    ("app/routes/login.spec.ts:3", "test code"),
    ("app/frontend/dist/main.ts:3", "frontend build output"),
    ("lib/outside.ts:3", "outside app/"),
])
def test_rule4_excluded_paths_never_block(location, reason):
    v = _one(_code(location, "high"))
    assert not v.blocking and v.rule == "rule 4"
    assert reason in v.why


def test_rule4_generic_secret_never_blocks_here():
    v = _one(_secret(tool="semgrep", location="app/routes/login.ts:34", rule="generic.secrets.x"))
    assert not v.blocking


# rule 5

def test_rule5_listed_check_in_app_dockerfile_blocks():
    v = _one(_iac("CKV_DOCKER_7", "/app/Dockerfile", 22))
    assert v.blocking and v.rule == "rule 5"


def test_rule5_listed_check_in_workflow_blocks():
    v = _one(_iac("CKV_GHA_1", "/.github/workflows/security.yml", 23))
    assert v.blocking and v.rule == "rule 5"


def test_rule5_healthcheck_is_report_only():
    v = _one(_iac("CKV_DOCKER_2", "/app/Dockerfile", 1))
    assert not v.blocking
    assert "CKV_DOCKER_2" in v.why and "report only" in v.why


def test_rule5_infrastructure_dockerfile_never_gates():
    v = _one(_iac("CKV_DOCKER_7", "/app/infrastructure/Dockerfile", 14))
    assert not v.blocking and "challenge material" in v.why


def test_rule5_listed_check_outside_gated_files_is_report_only():
    v = _one(_iac("CKV_DOCKER_3", "/other/Dockerfile", 1))
    assert not v.blocking


# rule 6

def test_rule6_fail_level_on_app_site_blocks():
    v = _one(_dast("10038", "http://juice:3000"))
    assert v.blocking and v.rule == "rule 6"


def test_rule6_warn_level_is_report_only():
    v = _one(_dast("10110", "http://juice:3000/main.js"))
    assert not v.blocking and "WARN" in v.why


def test_rule6_unlisted_plugin_is_report_only():
    v = _one(_dast("999999", "http://juice:3000/"))
    assert not v.blocking and "not in .zap/rules.tsv" in v.why


def test_rule6_fail_on_another_site_is_report_only():
    v = _one(_dast("10038", "http://example.org/x"))
    assert not v.blocking and "example.org" in v.why


# every verdict is explained

def test_every_verdict_has_text():
    findings = [_secret(), _vuln(), _code("app/routes/a.ts:1", "high"), _iac("CKV_DOCKER_7", "/app/Dockerfile"),
                _dast("10038", "http://juice:3000/")]
    for _, v in evaluate(findings, ZAP_RULES):
        assert v.why and v.next_step

# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: Copyright (C) 2026 iris-GmbH infrared & intelligent sensors.

"""Report findings and strict failures agree on every defect
(ticket #11, enforcement equivalence).

A defect that produces an `unmet` finding in report mode must reject
the very same input under strict enforcement, and the structured
failure must name EVERY machine-detectable violation at once - the
build log shows the full repair list, not one defect per round trip.
"""

import pytest

from helpers import (default_facts, file_entry, file_ref, fragment, pkg,
                     profile_config, render_all, vuln)


def defect_tax001():
    return default_facts(
        config=profile_config(),
        fragments={"busybox": fragment(pkgs=[pkg(
            "busybox", "1.36", "ref-busybox",
            properties=[{"name": "bsi:component:exectuable",
                         "value": "executable"}])])})


def defect_tax003():
    return default_facts(
        config=profile_config(),
        fragments={"busybox": fragment(pkgs=[pkg(
            "busybox", "1.36", "ref-busybox",
            properties=[{"name": "bsi:component:executable",
                         "value": "executable"}])])})


def defect_iden002():
    return default_facts(
        config=profile_config(),
        fragments={"busybox": fragment(pkgs=[pkg(
            "busybox", "1.36", "ref-busybox", purl="not-a-purl")])})


def defect_iden004():
    return default_facts(
        config=profile_config(),
        file_inventory={"busybox": [
            file_entry("/usr/bin/busybox", sha512="nothex" * 20)]})


def defect_file002():
    return default_facts(
        config=profile_config(),
        file_inventory={"busybox": [
            file_entry("/usr/bin/busybox", error="unreadable")]})


def defect_fmt002():
    return default_facts(
        config=profile_config(),
        fragments={"busybox": fragment(pkgs=[pkg(
            "busybox", "1.36", "ref-busybox",
            type="not-a-component-type")])})


def defect_vuln002():
    return default_facts(
        config=profile_config(),
        file_inventory={"busybox": [
            file_entry("/usr/bin/busybox", sha512="a" * 128)]},
        fragments={"busybox": fragment(
            pkgs=[pkg("busybox", "1.36", "ref-busybox")],
            cves=[vuln("CVE-2024-42",
                       file_ref("busybox", "/usr/bin/busybox"))])})


EQUIVALENCE_SAMPLES = [
    ("REQ-TAX-001", defect_tax001),
    ("REQ-TAX-003", defect_tax003),
    ("REQ-IDEN-002", defect_iden002),
    ("REQ-IDEN-004", defect_iden004),
    ("REQ-FILE-002", defect_file002),
    ("REQ-FMT-002", defect_fmt002),
    ("REQ-VULN-002", defect_vuln002),
]


@pytest.mark.parametrize("requirement,build_facts", EQUIVALENCE_SAMPLES)
def test_report_finding_and_strict_failure_agree_per_defect(requirement,
                                                            build_facts):
    if requirement == "REQ-FMT-002":
        import alignment_profile
        if alignment_profile._schema_validation().availability("1.7"):
            pytest.skip("schema validation unavailable: the schema verdict "
                        "is honestly unverifiable, not testable here")
    report_docs, _logs = render_all(build_facts())
    finding = next(entry for entry in report_docs["report"]["findings"]
                   if entry["requirementId"] == requirement)
    assert finding["verdict"] == "unmet"

    strict_facts = build_facts()
    strict_facts["config"] = profile_config(enforcement="strict")
    strict_docs, _logs = render_all(strict_facts)
    failure = strict_docs["failure"]
    assert requirement in failure["unmetRequirementIds"]
    violation = next(entry for entry in failure["violations"]
                     if entry["requirementId"] == requirement)
    assert violation["diagnosticMessage"] == finding["diagnosticMessage"]
    assert violation.get("bomRefs") == finding.get("bomRefs")


def test_strict_failure_aggregates_every_defect_at_once():
    facts = default_facts(
        config=profile_config(enforcement="strict"),
        file_inventory={"busybox": [
            file_entry("/usr/bin/busybox", error="unreadable")]},
        fragments={"busybox": fragment(
            pkgs=[pkg("busybox", "1.36", "ref-busybox",
                      purl="not-a-purl",
                      properties=[{"name": "bsi:vendor:custom",
                                   "value": "x"}])])})
    docs, _logs = render_all(facts)
    unmet = docs["failure"]["unmetRequirementIds"]
    for requirement in ("REQ-TAX-001", "REQ-IDEN-002", "REQ-FILE-002"):
        assert requirement in unmet
    assert [entry["requirementId"]
            for entry in docs["failure"]["violations"]] == unmet

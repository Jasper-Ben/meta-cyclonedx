# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: Copyright (C) 2026 iris-GmbH infrared & intelligent sensors.

"""Every emitted document is validated against its selected official
CycloneDX schema before publication (ticket #11, user stories 46).

The verdict lives in the requirements matrix, so it is observed through
the renderer seam as alignment findings and strict-enforcement failures.
`jsonschema` is feature-detected: with the library present the finding
is a real document verdict; with it absent the requirement degrades to
`unverifiable`, never to a silent pass.
"""

import pytest
import schema_validation
from helpers import (default_facts, finding_by_id, fragment, pkg,
                     profile_config, render_all, vuln)

SCHEMA_ROWS = ("REQ-FMT-002", "REQ-FMT-003")


def _valid_finding_verdict(spec_version="1.7"):
    """verified when validation can run, honestly unverifiable when not."""
    return "verified" if schema_validation.availability(spec_version) is None \
        else "unverifiable"


def _requires_jsonschema():
    if schema_validation.availability("1.6") or \
            schema_validation.availability("1.7"):
        pytest.skip("requires the jsonschema package to run the validation")


def test_emitted_sbom_and_vex_are_validated_against_the_selected_schema():
    docs, _logs = render_all(default_facts(config=profile_config()))
    for requirement in SCHEMA_ROWS:
        finding = finding_by_id(docs["report"], requirement)
        assert finding["verdict"] == _valid_finding_verdict()
        assert finding["applicability"] == "applicable"


def test_emitted_16_documents_are_validated_against_the_16_schema():
    docs, _logs = render_all(default_facts(
        config=profile_config(spec_version="1.6")))
    for requirement in SCHEMA_ROWS:
        assert finding_by_id(docs["report"],
                             requirement)["verdict"] == _valid_finding_verdict("1.6")


def test_each_supported_schema_version_gets_its_own_schema():
    """The module selects the schema named by the profile baseline."""
    _requires_jsonschema()
    docs, _logs = render_all(default_facts(
        config=profile_config(add_citation=True)))
    # Root citations exist only in the 1.7 schema.
    assert schema_validation.check(docs["sbom"], "1.7")[0] == "valid"
    assert schema_validation.check(docs["sbom"], "1.6")[0] == "invalid"


def test_schema_invalid_sbom_is_an_unmet_finding_never_a_silent_pass():
    facts = default_facts(
        config=profile_config(),
        fragments={"busybox": fragment(
            pkgs=[pkg("busybox", "1.36", "ref-busybox",
                     type="not-a-component-type")])})
    docs, _logs = render_all(facts)
    if schema_validation.availability("1.7") is None:
        finding = finding_by_id(docs["report"], "REQ-FMT-002")
        assert finding["verdict"] == "unmet"
        assert "not-a-component-type" in finding["diagnosticMessage"]
    else:
        assert finding_by_id(docs["report"], "REQ-FMT-002")["verdict"] == \
            "unverifiable"


def test_schema_invalid_vex_is_an_unmet_finding_never_a_silent_pass():
    facts = default_facts(
        config=profile_config(),
        fragments={"busybox": fragment(
            pkgs=[pkg("busybox", "1.36", "ref-busybox")],
            cves=[vuln("CVE-2024-0001", "ref-busybox", state="not-a-state")])})
    docs, _logs = render_all(facts)
    if schema_validation.availability("1.7") is None:
        finding = finding_by_id(docs["report"], "REQ-FMT-003")
        assert finding["verdict"] == "unmet"
        assert "not-a-state" in finding["diagnosticMessage"]
        # The SBOM itself stays valid.
        assert finding_by_id(docs["report"],
                             "REQ-FMT-002")["verdict"] == "verified"
    else:
        assert finding_by_id(docs["report"],
                             "REQ-FMT-003")["verdict"] == "unverifiable"


def test_strict_enforcement_rejects_schema_invalid_documents():
    _requires_jsonschema()
    facts = default_facts(
        config=profile_config(enforcement="strict"),
        fragments={"busybox": fragment(
            pkgs=[pkg("busybox", "1.36", "ref-busybox",
                     type="not-a-component-type")])})
    docs, _logs = render_all(facts)
    assert "failure" in docs
    assert "sbom" not in docs and "vex" not in docs
    assert "REQ-FMT-002" in docs["failure"]["unmetRequirementIds"]


def test_unavailable_validator_degrades_to_unverifiable_not_verified(monkeypatch):
    monkeypatch.setattr(schema_validation, "_load_jsonschema", lambda: None)
    docs, _logs = render_all(default_facts(config=profile_config()))
    for requirement in SCHEMA_ROWS:
        finding = finding_by_id(docs["report"], requirement)
        assert finding["verdict"] == "unverifiable"
        assert "jsonschema" in finding["diagnosticMessage"]


def test_strict_enforcement_does_not_fail_on_unverifiable_validation(monkeypatch):
    monkeypatch.setattr(schema_validation, "_load_jsonschema", lambda: None)
    docs, _logs = render_all(default_facts(
        config=profile_config(enforcement="strict")))
    # Unverifiable schema validation never joins the unmet set, whatever
    # else strict enforcement does with this evidence.
    unmet = docs.get("failure", {}).get("unmetRequirementIds", [])
    assert "REQ-FMT-002" not in unmet and "REQ-FMT-003" not in unmet


def test_validation_results_are_stable_across_repeated_checks():
    facts = default_facts(
        config=profile_config(),
        fragments={"busybox": fragment(
            pkgs=[pkg("busybox", "1.36", "ref-busybox",
                     type="not-a-component-type")])})
    first, _logs = render_all(facts)
    second, _logs = render_all(facts)
    assert finding_by_id(first["report"], "REQ-FMT-002") == \
        finding_by_id(second["report"], "REQ-FMT-002")

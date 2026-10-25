"""The alignment report artifact at the renderer seam.

Report enforcement must publish the SBOM, the separate VEX and an adjacent
deterministic alignment report evaluated against the exact profile baseline
and the project-owned requirements matrix, without making a conformance
claim of any kind.
"""

import helpers
import meta_cyclonedx
from helpers import (default_facts, finding_by_id, fragment,
                     pkg, profile_config, render_all)


def test_no_profile_emits_no_alignment_report():
    docs, _logs = render_all(default_facts())
    assert "report" not in docs
    assert "failure" not in docs


def test_report_records_exact_profile_baseline():
    docs, _logs = render_all(default_facts(config=profile_config()))
    report = docs["report"]
    assert docs["sbom"]["specVersion"] == "1.7"
    assert docs["vex"]["specVersion"] == "1.7"
    assert report["alignmentProfile"] == "tr03183-2.1"
    assert report["alignmentEnforcement"] == "report"
    assert report["profileBaseline"] == {
        "guideline": "BSI TR-03183-2",
        "guidelineVersion": "2.1.0",
        "propertyTaxonomyVersion": "0.1.2",
        "cyclonedxSchemaVersion": "1.7",
        "requirementsMatrixVersion": "2.1.0-r4",
    }


def test_report_records_the_selected_cyclonedx_schema():
    docs, _logs = render_all(
        default_facts(config=profile_config(spec_version="1.6")))
    assert docs["report"]["profileBaseline"]["cyclonedxSchemaVersion"] == "1.6"

def test_report_classifies_document_evaluable_requirements():
    docs, _logs = render_all(default_facts(config=profile_config()))
    report = docs["report"]

    fmt = finding_by_id(report, "REQ-FMT-001")
    assert fmt["verdict"] == "verified"
    assert fmt["normativeSource"] == "BSI TR-03183-2 v2.1.0 \u00a74 (format requirements)"
    assert fmt["cyclonedxRepresentation"] == ("bomFormat CycloneDX with "
                                              "specVersion 1.6 or later")
    assert fmt["applicability"] == "applicable"
    assert fmt["evidenceOrigin"] == "generated-document"

    creator = finding_by_id(report, "REQ-SBOM-001")
    assert creator["verdict"] == "unmet"
    assert "creator" in creator["diagnosticMessage"].lower()


def test_report_enforcement_emits_documents_despite_unmet_requirements():
    docs, _logs = render_all(default_facts(config=profile_config()))
    assert docs["sbom"]["bomFormat"] == "CycloneDX"
    assert docs["vex"]["bomFormat"] == "CycloneDX"
    assert any(f["verdict"] == "unmet" for f in docs["report"]["findings"])

def test_creator_asserted_identity_yields_asserted_not_verified():
    docs, _logs = render_all(default_facts(config=profile_config()))
    finding = finding_by_id(docs["report"], "REQ-COMP-003")
    assert finding["verdict"] == "asserted"
    assert finding["evidenceOrigin"] == "caller-assertion"


def test_missing_assertion_is_unmet_never_verified():
    facts = default_facts(config=profile_config(), primary={})
    docs, _logs = render_all(facts)
    finding = finding_by_id(docs["report"], "REQ-COMP-003")
    assert finding["verdict"] == "unmet"


def test_assertion_evidence_alone_never_produces_verified():
    docs, _logs = render_all(default_facts(config=profile_config()))
    for finding in docs["report"]["findings"]:
        if (finding["evidenceOrigin"] == "caller-assertion"
                and finding["applicability"] == "applicable"):
            assert finding["verdict"] in ("asserted", "unmet")

def test_report_records_unverifiable_requirements_without_blocking_output():
    docs, _logs = render_all(default_facts(config=profile_config()))
    finding = finding_by_id(docs["report"], "REQ-DEPS-001")
    assert finding["verdict"] == "unverifiable"
    assert finding["applicability"] == "applicable"
    assert finding["evidenceOrigin"] == "external-evidence"
    assert docs["sbom"]["bomFormat"] == "CycloneDX"
    assert docs["vex"]["bomFormat"] == "CycloneDX"

def test_file_component_requirements_are_not_applicable_without_file_components():
    docs, _logs = render_all(default_facts(config=profile_config()))
    for requirement_id in ("REQ-COMP-004", "REQ-COMP-005", "REQ-COMP-006",
                           "REQ-COMP-007", "REQ-COMP-008"):
        finding = finding_by_id(docs["report"], requirement_id)
        assert finding["applicability"] == "not-applicable"
        assert finding["verdict"] == "unverifiable"
        assert "file component" in finding["diagnosticMessage"]


def test_file_component_requirements_apply_and_report_missing_bsi_fields():
    facts = default_facts(
        config=profile_config(),
        fragments={"busybox": fragment(
            pkgs=[pkg("busybox", "1.36", "ref-busybox", type="file")])},
    )
    docs, _logs = render_all(facts)
    for requirement_id in ("REQ-COMP-004", "REQ-COMP-005", "REQ-COMP-006",
                           "REQ-COMP-007", "REQ-COMP-008"):
        finding = finding_by_id(docs["report"], requirement_id)
        assert finding["applicability"] == "applicable"
        assert finding["verdict"] == "unmet"
        assert finding["bomRefs"] == ["ref-busybox"]


def test_file_component_requirements_pass_with_bsi_fields_and_hash():
    file_component = pkg(
        "busybox", "1.36", "ref-busybox", type="file",
        hashes=[{"alg": "SHA-512", "content": "0" * 128}],
        properties=[
            {"name": "bsi:component:filename", "value": "busybox"},
            {"name": "bsi:component:executable", "value": "executable"},
            {"name": "bsi:component:archive", "value": "no archive"},
            {"name": "bsi:component:structured", "value": "unstructured"},
        ],
    )
    facts = default_facts(
        config=profile_config(),
        fragments={"busybox": fragment(pkgs=[file_component])},
    )
    docs, _logs = render_all(facts)
    for requirement_id in ("REQ-COMP-004", "REQ-COMP-005", "REQ-COMP-006",
                           "REQ-COMP-007", "REQ-COMP-008"):
        finding = finding_by_id(docs["report"], requirement_id)
        assert finding["verdict"] == "verified", requirement_id


def test_conditional_uri_requirements_record_their_applicability():
    docs, _logs = render_all(default_facts(config=profile_config()))
    for requirement_id in ("REQ-URI-001", "REQ-URI-002", "REQ-URI-003"):
        finding = finding_by_id(docs["report"], requirement_id)
        assert finding["applicability"] == "not-applicable"
        assert finding["verdict"] == "unverifiable"

    primary = {"type": "firmware", "name": "core-image", "version": "1.0",
               "external_references": [
                   {"type": "vcs", "url": "https://example.invalid/layer.git"}]}
    docs, _logs = render_all(default_facts(config=profile_config(),
                                           primary=primary))
    finding = finding_by_id(docs["report"], "REQ-URI-002")
    assert finding["applicability"] == "applicable"
    assert finding["verdict"] == "verified"

def test_component_version_finding_names_affected_components():
    facts = default_facts(
        config=profile_config(),
        fragments={"busybox": fragment(pkgs=[
            pkg("busybox", "unknown", "ref-busybox"),
            pkg("zlib", "1.3", "ref-zlib"),
        ])},
    )
    docs, _logs = render_all(facts)

    version = finding_by_id(docs["report"], "REQ-COMP-002")
    assert version["verdict"] == "unmet"
    assert version["bomRefs"] == ["ref-busybox"]

    name = finding_by_id(docs["report"], "REQ-COMP-001")
    assert name["verdict"] == "verified"
    assert "bomRefs" not in name

def test_requirements_matrix_assigns_the_four_attributes_to_every_row():
    docs, _logs = render_all(default_facts(config=profile_config()))
    findings = docs["report"]["findings"]
    assert len(findings) == len({f["requirementId"] for f in findings})
    for finding in findings:
        assert set(finding) >= {"requirementId", "normativeSource",
                                "cyclonedxRepresentation", "applicability",
                                "verdict", "evidenceOrigin",
                                "diagnosticMessage"}
        assert finding["verdict"] in ("verified", "asserted", "unmet",
                                      "unverifiable")
        assert finding["applicability"] in ("applicable", "not-applicable")
        assert finding["normativeSource"].startswith("BSI TR-03183-2 v2.1.0")
        assert finding["cyclonedxRepresentation"]
        assert finding["diagnosticMessage"]

    sources = " ".join(f["normativeSource"] for f in findings)
    for section in ("\u00a73.1", "\u00a74 ", "\u00a75.2.1", "\u00a75.2.2",
                    "\u00a75.2.3", "\u00a75.2.4", "\u00a76.1"):
        assert section in sources, section

def test_strict_enforcement_fails_on_machine_detectable_violations():
    docs, _logs = render_all(default_facts(config=profile_config(
        enforcement="strict")))
    assert "sbom" not in docs
    assert "vex" not in docs
    failure = docs["failure"]
    assert failure["alignmentEnforcement"] == "strict"
    # Machine-detectable violations block the output...
    assert "REQ-COMP-011" in failure["unmetRequirementIds"]
    assert failure["unmetRequirementIds"] == sorted(failure["unmetRequirementIds"])
    # ...while unverifiable findings do not.
    assert "REQ-DEPS-001" not in failure["unmetRequirementIds"]
    assert "REQ-COMP-011" in failure["diagnosticMessage"]
    # The evaluated report rides along for build-log diagnostics.
    assert failure["report"]["alignmentProfile"] == "tr03183-2.1"


def test_report_enforcement_never_fails_on_findings():
    docs, _logs = render_all(default_facts(config=profile_config()))
    assert "failure" not in docs
    assert any(f["verdict"] in ("unmet", "unverifiable")
               for f in docs["report"]["findings"])

def test_alignment_report_bytes_are_deterministic_for_equivalent_facts():
    first, _logs = render_all(default_facts(config=profile_config()))
    second, _logs = render_all(default_facts(config=profile_config()))
    assert meta_cyclonedx.serialize_report(first["report"]) == \
        meta_cyclonedx.serialize_report(second["report"])


def test_alignment_report_carries_no_wall_clock_or_document_serial():
    docs, _logs = render_all(default_facts(config=profile_config()))
    text = meta_cyclonedx.serialize_report(docs["report"])
    assert "urn:uuid" not in text
    assert helpers.TIMESTAMP not in text

def test_generated_alignment_report_makes_no_conformance_claim():
    docs, _logs = render_all(default_facts(config=profile_config()))
    report = docs["report"]
    text = meta_cyclonedx.serialize_report(report)
    assert "conformant" not in text.lower()
    statement = report["conformanceDetermination"].lower()
    assert "conformance determination" in statement
    assert "meta-cyclonedx makes no tr-03183-2 or cra conformance claim" in statement

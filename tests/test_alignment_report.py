"""The alignment report artifact at the renderer seam.

Report enforcement must publish the SBOM, the separate VEX and an adjacent
deterministic alignment report evaluated against the exact profile baseline
and the project-owned requirements matrix, without making a conformance
claim of any kind.
"""

from helpers import (default_facts, finding_by_id, profile_config,
                     render_all)


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
        "requirementsMatrixVersion": "2.1.0-r1",
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

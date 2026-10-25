"""Creator evidence and trustworthy URIs at the renderer seam.

The product integration supplies the SBOM creator and the primary
component creator explicitly; third-party creators follow the
precedence explicit override, then trustworthy upstream metadata, then
unresolved. The product manufacturer is never the blanket creator of
bundled third-party software, missing evidence yields honest findings
instead of fabricated metadata, and source or deployable URIs appear
only from trustworthy metadata, syntax-validated when present.
"""

import meta_cyclonedx
from helpers import (default_facts, finding_by_id, fragment, pkg,
                     profile_config, render_all)


def test_sbom_creator_grammar_becomes_metadata_authors():
    facts = default_facts(
        config=profile_config(),
        sbom_creator="Acme SBOM Team <sbom@acme.example>; https://acme.example",
    )
    docs, _logs = render_all(facts)
    assert docs["sbom"]["metadata"]["authors"] == [
        {"url": ["https://acme.example"]},
        {"name": "Acme SBOM Team", "email": ["sbom@acme.example"]},
    ]


def test_sbom_creator_requirement_is_asserted_from_caller_evidence():
    facts = default_facts(config=profile_config(),
                          sbom_creator="sbom@acme.example")
    docs, _logs = render_all(facts)
    finding = finding_by_id(docs["report"], "REQ-SBOM-001")
    assert finding["verdict"] == "asserted"
    assert finding["evidenceOrigin"] == "caller-assertion"


def test_missing_sbom_creator_is_unmet_not_fabricated():
    docs, _logs = render_all(default_facts(config=profile_config()))
    assert "authors" not in docs["sbom"]["metadata"]
    finding = finding_by_id(docs["report"], "REQ-SBOM-001")
    assert finding["verdict"] == "unmet"


def test_unusable_sbom_creator_contact_is_rejected_not_emitted():
    facts = default_facts(config=profile_config(),
                          sbom_creator="Acme GmbH")
    docs, logs = render_all(facts)
    assert "authors" not in docs["sbom"]["metadata"]
    assert any("sbom_creator" in message or "creator" in message.lower()
               for level, message in logs if level == "warn")
    finding = finding_by_id(docs["report"], "REQ-SBOM-001")
    assert finding["verdict"] == "unmet"


def test_equivalent_creator_evidence_order_produces_identical_authors():
    first = default_facts(
        config=profile_config(),
        sbom_creator="Acme SBOM Team <sbom@acme.example>; https://acme.example",
    )
    second = default_facts(
        config=profile_config(),
        sbom_creator="https://acme.example; Acme SBOM Team <sbom@acme.example>",
    )
    first_docs, _logs = render_all(first)
    second_docs, _logs = render_all(second)
    assert first_docs["sbom"]["metadata"]["authors"] == \
        second_docs["sbom"]["metadata"]["authors"]
    assert meta_cyclonedx.serialize_report(first_docs["report"]) == \
        meta_cyclonedx.serialize_report(second_docs["report"])

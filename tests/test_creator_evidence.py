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


def test_explicit_primary_component_creator_names_the_product_manufacturer():
    facts = default_facts(
        config=profile_config(),
        primary={"type": "firmware", "name": "core-image", "version": "1.0",
                 "creator": "Acme GmbH <product@acme.example>"},
    )
    docs, _logs = render_all(facts)
    component = docs["sbom"]["metadata"]["component"]
    assert component["author"] == "Acme GmbH"
    assert component["contact"] == ["product@acme.example"]
    finding = finding_by_id(docs["report"], "REQ-COMP-012")
    assert finding["verdict"] == "asserted"
    assert finding["evidenceOrigin"] == "caller-assertion"


def test_missing_primary_component_creator_is_unmet_not_fabricated():
    docs, _logs = render_all(default_facts(config=profile_config()))
    component = docs["sbom"]["metadata"]["component"]
    assert "author" not in component
    assert "contact" not in component
    finding = finding_by_id(docs["report"], "REQ-COMP-012")
    assert finding["verdict"] == "unmet"


def test_explicit_component_creator_override_wins_over_upstream_metadata():
    facts = default_facts(
        config=profile_config(),
        sbom_creator="sbom@acme.example",
        fragments={"zlib": fragment(
            creator="Zlib upstream team <devel@zlib.example>",
            pkgs=[pkg("zlib", "1.3", "ref-zlib",
                      purl="pkg:github/zliborg/zlib")])},
    )
    docs, _logs = render_all(facts)
    zlib = docs["sbom"]["components"][0]
    assert zlib["author"] == "Zlib upstream team"
    assert zlib["contact"] == ["devel@zlib.example"]
    finding = finding_by_id(docs["report"], "REQ-COMP-010")
    assert finding["verdict"] == "asserted"
    assert finding["evidenceOrigin"] == "caller-assertion"


def test_trustworthy_upstream_purl_records_the_creator_as_verified():
    facts = default_facts(
        config=profile_config(),
        sbom_creator="sbom@acme.example",
        fragments={"openssl": fragment(
            pkgs=[pkg("openssl", "3.0", "ref-openssl",
                      purl="pkg:github/openssl/openssl")])},
    )
    docs, _logs = render_all(facts)
    openssl = docs["sbom"]["components"][0]
    assert openssl["author"] == "openssl"
    assert openssl["contact"] == ["https://github.com/openssl/openssl"]
    finding = finding_by_id(docs["report"], "REQ-COMP-010")
    assert finding["verdict"] == "verified"
    assert finding["evidenceOrigin"] == "upstream-metadata"


def test_trustworthy_vcs_reference_records_the_upstream_creator():
    facts = default_facts(
        config=profile_config(),
        sbom_creator="sbom@acme.example",
        fragments={"gnutls": fragment(pkgs=[pkg(
            "gnutls", "3.8", "ref-gnutls",
            purl="pkg:yocto/gnutls@3.8",
            externalReferences=[
                {"type": "vcs", "url": "https://gitlab.com/gnutls/gnutls.git"}])])},
    )
    docs, _logs = render_all(facts)
    gnutls = docs["sbom"]["components"][0]
    assert gnutls["author"] == "gnutls"
    assert gnutls["contact"] == ["https://gitlab.com/gnutls/gnutls"]


def test_unresolved_third_party_creator_is_unverifiable_not_manufacturer():
    facts = default_facts(
        config=profile_config(),
        sbom_creator="sbom@acme.example",
        primary={"type": "firmware", "name": "core-image", "version": "1.0",
                 "creator": "Acme GmbH <product@acme.example>"},
    )
    docs, _logs = render_all(facts)
    busybox = docs["sbom"]["components"][0]
    assert "author" not in busybox
    assert "contact" not in busybox
    finding = finding_by_id(docs["report"], "REQ-COMP-010")
    assert finding["verdict"] == "unverifiable"
    assert finding["bomRefs"] == ["ref-busybox"]


def test_unresolved_third_party_creators_do_not_block_strict_output():
    facts = default_facts(
        config=profile_config(enforcement="strict"),
        sbom_creator="sbom@acme.example",
        primary={"type": "firmware", "name": "core-image", "version": "1.0",
                 "creator": "Acme GmbH <product@acme.example>"},
    )
    docs, _logs = render_all(facts)
    if "failure" in docs:
        assert "REQ-COMP-010" not in docs["failure"]["unmetRequirementIds"]
    else:
        finding = finding_by_id(docs["report"], "REQ-COMP-010")
        assert finding["verdict"] == "unverifiable"


def test_trustworthy_source_reference_is_emitted_and_verified():
    facts = default_facts(
        config=profile_config(),
        sbom_creator="sbom@acme.example",
        fragments={"gitrepo": fragment(pkgs=[pkg(
            "gitrepo", "1.0", "ref-gitrepo",
            purl="pkg:yocto/gitrepo@1.0",
            externalReferences=[
                {"type": "vcs", "url": "https://github.com/gitrepo/gitrepo.git"}])])},
    )
    docs, _logs = render_all(facts)
    gitrepo = docs["sbom"]["components"][0]
    assert {"type": "vcs",
            "url": "https://github.com/gitrepo/gitrepo.git"} in \
        gitrepo["externalReferences"]
    finding = finding_by_id(docs["report"], "REQ-URI-002")
    assert finding["applicability"] == "applicable"
    assert finding["verdict"] == "verified"


def test_invalid_source_uri_is_not_emitted_and_reports_unmet():
    facts = default_facts(
        config=profile_config(),
        sbom_creator="sbom@acme.example",
        fragments={"broken": fragment(pkgs=[pkg(
            "broken", "1.0", "ref-broken",
            purl="pkg:yocto/broken@1.0",
            externalReferences=[
                {"type": "vcs", "url": "git: not a uri @@ //"}])])},
    )
    docs, logs = render_all(facts)
    broken = docs["sbom"]["components"][0]
    assert all(ref["type"] != "vcs"
               for ref in broken.get("externalReferences") or ())
    assert any(level == "warn" for level, _message in logs)
    finding = finding_by_id(docs["report"], "REQ-URI-002")
    assert finding["applicability"] == "applicable"
    assert finding["verdict"] == "unmet"
    assert finding["bomRefs"] == ["ref-broken"]


def test_explicit_deployable_uri_override_is_trustworthy_evidence():
    facts = default_facts(
        config=profile_config(),
        sbom_creator="sbom@acme.example",
        fragments={"zlib": fragment(
            deployable_uri="https://zlib.example/zlib-1.3.tar.gz",
            pkgs=[pkg("zlib", "1.3", "ref-zlib")])},
    )
    docs, _logs = render_all(facts)
    zlib = docs["sbom"]["components"][0]
    assert {"type": "distribution",
            "url": "https://zlib.example/zlib-1.3.tar.gz"} in \
        zlib["externalReferences"]
    finding = finding_by_id(docs["report"], "REQ-URI-003")
    assert finding["verdict"] == "verified"


def test_invalid_primary_source_uri_is_rejected_and_reported():
    facts = default_facts(
        config=profile_config(),
        sbom_creator="sbom@acme.example",
        primary={"type": "firmware", "name": "core-image", "version": "1.0",
                 "source_uri": "::::"},
    )
    docs, _logs = render_all(facts)
    assert all(ref["type"] != "vcs" for ref in
               docs["sbom"]["metadata"]["component"]
               .get("externalReferences") or ())
    finding = finding_by_id(docs["report"], "REQ-URI-002")
    assert finding["verdict"] == "unmet"


def test_primary_source_and_deployable_uris_are_emitted_when_valid():
    facts = default_facts(
        config=profile_config(),
        sbom_creator="sbom@acme.example",
        primary={"type": "firmware", "name": "core-image", "version": "1.0",
                 "source_uri": "https://source.example/core-image",
                 "deployable_uri": "https://download.example/core-image.img"},
    )
    docs, _logs = render_all(facts)
    references = docs["sbom"]["metadata"]["component"]["externalReferences"]
    assert {"type": "vcs",
            "url": "https://source.example/core-image"} in references
    assert {"type": "distribution",
            "url": "https://download.example/core-image.img"} in references
    assert finding_by_id(docs["report"], "REQ-URI-002")["verdict"] == "verified"
    assert finding_by_id(docs["report"], "REQ-URI-003")["verdict"] == "verified"


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

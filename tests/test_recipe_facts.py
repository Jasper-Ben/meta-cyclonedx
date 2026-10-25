"""Normalized-fact construction: component identity and VEX statements from
recipe CVE status. These facts are what do_populate_cyclonedx stores per
recipe; assertions target the fact content, not helper plumbing."""

import re

import meta_cyclonedx

from helpers import PLACEHOLDER


def test_aliases_collapse_into_one_logical_component():
    pkg = meta_cyclonedx.component_identity(
        "foo", "1.2", "pkg:yocto/foo@1.2", cve_products="libfoo foo")

    assert pkg["name"] == "foo"
    assert pkg["version"] == "1.2"
    assert pkg["purl"] == "pkg:yocto/foo@1.2"
    products = [p["value"] for p in pkg["properties"]
                if p["name"] == "yocto:cve:product"]
    assert products == ["foo", "libfoo"]
    assert pkg["cpe"] == "cpe:2.3:*:*:foo:1.2:-:*:*:*:*:*:*"


def test_identity_overrides_take_precedence():
    pkg = meta_cyclonedx.component_identity(
        "yocto-recipe", "9.9-r0", "pkg:yocto/x@9.9", cve_products="foo",
        name_override="libfoo-upstream", version_override="2.4.1")

    assert pkg["name"] == "libfoo-upstream"
    assert pkg["version"] == "2.4.1"
    # CVE_VERSION defaults to PV: the correlation CPEs stay on the recipe
    # version, never on the overridden logical version.
    assert ":foo:9.9-r0:" in pkg["cpe"]


def test_semantically_valid_bpn_and_pv_are_the_identity_defaults():
    pkg = meta_cyclonedx.component_identity("libfoo", "1.2.3-r0", "p")
    assert pkg["name"] == "libfoo"
    assert pkg["version"] == "1.2.3-r0"


def test_degenerate_pv_falls_back_to_the_unknown_placeholder():
    pkg = meta_cyclonedx.component_identity("app", "6.6+gitAUTOINC+abcdef", "p")
    assert pkg["version"] == "6.6"

    pkg = meta_cyclonedx.component_identity("app", "  ", "p")
    assert pkg["version"] == "unknown"
    assert ":unknown:" in pkg["cpe"]

    # A PV without any version signal (no digit) is not semantically valid.
    pkg = meta_cyclonedx.component_identity("app", "git+${SRCPV}", "p")
    assert pkg["version"] == "unknown"


def test_overrides_are_authoritative_verbatim():
    pkg = meta_cyclonedx.component_identity(
        "app", "1.0", "p", name_override="upstream name",
        version_override="nightly-2026")
    assert pkg["name"] == "upstream name"
    assert pkg["version"] == "nightly-2026"


def test_vendor_qualifier_qualifies_only_correlation_data():
    pkg = meta_cyclonedx.component_identity(
        "libfoo", "1.2", "pkg:yocto/x", cve_products="vendor:libfoo")

    assert pkg["name"] == "libfoo"
    assert "group" not in pkg
    assert pkg["cpe"] == "cpe:2.3:*:vendor:libfoo:1.2:-:*:*:*:*:*:*"
    products = [p["value"] for p in pkg["properties"]
                if p["name"] == "yocto:cve:product"]
    assert products == ["vendor:libfoo"]


def test_every_alias_version_reaches_the_correlation_cpe_set():
    pkg = meta_cyclonedx.component_identity(
        "foo", "1.3", "p", cve_products="foo", cve_versions="1.2 1.3")

    assert pkg["version"] == "1.3"
    assert pkg["cpe"] == "cpe:2.3:*:*:foo:1.2:-:*:*:*:*:*:*"
    cpes = [p["value"] for p in pkg["properties"] if p["name"] == "yocto:cve:cpe"]
    assert cpes == ["cpe:2.3:*:*:foo:1.2:-:*:*:*:*:*:*",
                    "cpe:2.3:*:*:foo:1.3:-:*:*:*:*:*:*"]


def test_external_references_are_attached_when_supplied():
    refs = [{"type": "vcs", "url": "https://example.org/src.git@deadbeef"}]
    pkg = meta_cyclonedx.component_identity("app", "1", "p",
                                            external_references=refs)
    assert pkg["externalReferences"] == refs


def test_patched_status_becomes_resolved_statement():
    statements = []
    meta_cyclonedx.add_status_vex_statement(
        ("CVE-2025-52886", "Patched", "Fixed in 1.2.3", ""), statements,
        "ref-x", "myrecipe", PLACEHOLDER, add_timestamps=False)

    [statement] = statements
    assert statement["id"] == "CVE-2025-52886"
    assert statement["analysis"]["state"] == "resolved"
    assert statement["affects"] == [{"ref": f"urn:cdx:{PLACEHOLDER}/1#ref-x"}]
    assert statement["source"]["name"] == "NVD"


def test_ignored_status_becomes_not_affected_with_justification():
    statements = []
    meta_cyclonedx.add_status_vex_statement(
        ("CVE-2025-1", "Ignored", "Discarded reason", "upstream not affected"),
        statements, "ref-x", "myrecipe", PLACEHOLDER, add_timestamps=False)

    [statement] = statements
    assert statement["analysis"]["state"] == "not_affected"
    assert "JUSTIFICATION: upstream not affected" in statement["analysis"]["detail"]


def test_irrelevant_status_produces_no_statement():
    statements = []
    meta_cyclonedx.add_status_vex_statement(
        ("CVE-2025-2", "Unpatched", "Needs triage", ""), statements,
        "ref-x", "myrecipe", PLACEHOLDER, add_timestamps=False)

    assert statements == []


def test_patch_suffixes_collapse_into_one_statement_with_details():
    statements = []
    for cve_id in ("CVE-2025-52886-0001", "CVE-2025-52886-0002"):
        meta_cyclonedx.add_status_vex_statement(
            (cve_id, "Patched", "Backported patch", ""), statements,
            "ref-x", "myrecipe", PLACEHOLDER, add_timestamps=False)

    [statement] = statements
    assert statement["id"] == "CVE-2025-52886"
    assert "Patch file: CVE-2025-52886-0001" in statement["analysis"]["detail"]
    assert "Additional patch: CVE-2025-52886-0002" in statement["analysis"]["detail"]
    assert statement["affects"] == [{"ref": f"urn:cdx:{PLACEHOLDER}/1#ref-x"}]


def test_alias_components_attract_the_same_statement():
    statements = []
    for bom_ref in ("ref-a", "ref-b"):
        meta_cyclonedx.add_status_vex_statement(
            ("CVE-2025-3", "Patched", "Fixed", ""), statements,
            bom_ref, "myrecipe", PLACEHOLDER, add_timestamps=False)

    [statement] = statements
    assert statement["affects"] == [
        {"ref": f"urn:cdx:{PLACEHOLDER}/1#ref-a"},
        {"ref": f"urn:cdx:{PLACEHOLDER}/1#ref-b"},
    ]


def test_timestamps_follow_configuration():
    statements = []
    meta_cyclonedx.add_status_vex_statement(
        ("CVE-2025-4", "Patched", "Fixed", ""), statements,
        "ref-x", "myrecipe", PLACEHOLDER, add_timestamps=True)

    analysis = statements[0]["analysis"]
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T.*", analysis["firstIssued"])
    assert analysis["firstIssued"] == analysis["lastUpdated"]


def test_kernel_not_affected_statement_covers_all_kernel_components():
    statement = meta_cyclonedx.kernel_vex_statement(
        "CVE-2024-777", ["ref-k1", "ref-k2"], PLACEHOLDER, "file never compiled")

    assert statement["analysis"] == {
        "state": "not_affected",
        "justification": "code_not_present",
        "detail": "file never compiled",
    }
    assert statement["affects"] == [
        {"ref": f"urn:cdx:{PLACEHOLDER}/1#{r}"} for r in ("ref-k1", "ref-k2")]

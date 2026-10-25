"""Logical component identity at the document surface: creator-assigned
identity instead of CVE aliases, one component per recipe, instances that
share a CPE, and collision reporting. Ordinary output and the alignment
profile are held to the same model (ADR-0006, ADR-0009)."""

import meta_cyclonedx

from helpers import (component_by_name, default_facts, finding_by_id, fragment,
                     pkg, profile_config, render_all, render_docs, vuln)

SHARED_CPE = "cpe:2.3:*:*:widget:1.0:*:*:*:*:*:*:*"


def identity_fragment(recipe_bpn, recipe_pv, purl, bom_ref, cve_products=None,
                      **overrides):
    """A fragment as do_populate_cyclonedx produces it for one recipe."""
    identity = meta_cyclonedx.component_identity(
        recipe_bpn, recipe_pv, purl, cve_products=cve_products)
    identity["bom-ref"] = bom_ref
    identity.update(overrides)
    return fragment(pkgs=[identity])


def test_rendered_components_carry_creator_assigned_identity_not_aliases():
    facts = default_facts(fragments={
        "widget-src": identity_fragment(
            "widget-src", "2.1", "pkg:yocto/meta/widget@2.1", "ref-w",
            cve_products="libwidget widget"),
    })
    sbom, _vex, _logs = render_docs(facts)

    component = component_by_name(sbom, "widget-src")
    assert component["version"] == "2.1"
    assert len(sbom["components"]) == 1
    products = [p["value"] for p in component["properties"]
                if p["name"] == "yocto:cve:product"]
    assert products == ["libwidget", "widget"]


def test_identity_override_survives_rendering():
    identity = meta_cyclonedx.component_identity(
        "recipe-x", "1.0", "pkg:yocto/recipe-x@1.0", cve_products="foo",
        name_override="upstream-widget")
    identity["bom-ref"] = "ref-x"
    facts = default_facts(fragments={"recipe-x": fragment(pkgs=[identity])})
    sbom, _vex, _logs = render_docs(facts)

    component = component_by_name(sbom, "upstream-widget")
    # Yocto/package identity remains through the package purl.
    assert component["purl"] == "pkg:yocto/recipe-x@1.0"


def test_aliases_produce_one_component_and_no_duplicate_vex_findings():
    identity = meta_cyclonedx.component_identity(
        "foo", "1.2", "pkg:yocto/foo@1.2", cve_products="libfoo foo")
    identity["bom-ref"] = "ref-w"
    facts = default_facts(fragments={
        "foo": fragment(pkgs=[identity], cves=[vuln("CVE-2024-1", "ref-w")]),
    })
    sbom, vex, _logs = render_docs(facts)

    assert len(sbom["components"]) == 1
    serial = sbom["serialNumber"].split("urn:uuid:")[-1]
    statement = meta_cyclonedx.normalize_cve_id("CVE-2024-1")
    matches = [v for v in vex["vulnerabilities"] if v["id"] == statement]
    assert len(matches) == 1
    assert matches[0]["affects"] == [{"ref": f"urn:cdx:{serial}/1#ref-w"}]


def test_backported_fix_does_not_change_the_logical_version():
    # A patched CVE is recorded in the VEX; the upstream version stays the
    # recipe's logical version (the fix did not change it).
    facts = default_facts(fragments={
        "nginx": dict(identity_fragment(
            "nginx", "1.25.3", "pkg:yocto/nginx@1.25.3", "ref-n",
            cve_products="nginx"),
            cves=[vuln("CVE-2024-7", "ref-n")]),
    })
    sbom, vex, _logs = render_docs(facts)

    assert component_by_name(sbom, "nginx")["version"] == "1.25.3"
    statement = next(v for v in vex["vulnerabilities"] if v["id"] == "CVE-2024-7")
    assert statement["analysis"]["state"] == "resolved"


def test_distinct_evidence_instances_sharing_a_cpe_stay_separate_and_verified():
    facts = default_facts(
        config=profile_config(),
        fragments={
            "widget-a": fragment(pkgs=[pkg(
                "widget", "1.0", "ref-a", cpe=SHARED_CPE,
                licenses=[{"license": {"id": "MIT"}}])]),
            "widget-b": fragment(pkgs=[pkg(
                "widget", "1.0", "ref-b", cpe=SHARED_CPE,
                licenses=[{"license": {"id": "GPL-2.0-only"}}])]),
        })
    docs, _logs = render_all(facts)

    assert [c["bom-ref"] for c in docs["sbom"]["components"]
            if c["name"] == "widget"] == ["ref-a", "ref-b"]
    finding = finding_by_id(docs["report"], "REQ-IDEN-001")
    assert finding["verdict"] == "verified"
    assert "bomRefs" not in finding


def test_vulnerability_status_difference_explains_a_collision():
    facts = default_facts(
        config=profile_config(),
        fragments={
            "widget-a": fragment(
                pkgs=[pkg("widget", "1.0", "ref-a", cpe=SHARED_CPE)],
                cves=[vuln("CVE-2024-9", "ref-a")]),
            "widget-b": fragment(
                pkgs=[pkg("widget", "1.0", "ref-b", cpe=SHARED_CPE)]),
        })
    docs, _logs = render_all(facts)

    finding = finding_by_id(docs["report"], "REQ-IDEN-001")
    assert finding["verdict"] == "verified"


def test_unexplained_collision_names_affected_bom_refs():
    facts = default_facts(
        config=profile_config(),
        fragments={
            "widget-a": fragment(pkgs=[pkg("widget", "1.0", "ref-a",
                                           cpe=SHARED_CPE)]),
            "widget-b": fragment(pkgs=[pkg("widget", "1.0", "ref-b",
                                           cpe=SHARED_CPE)]),
        })
    docs, _logs = render_all(facts)

    finding = finding_by_id(docs["report"], "REQ-IDEN-001")
    assert finding["verdict"] == "unmet"
    assert finding["bomRefs"] == ["ref-a", "ref-b"]


def test_strict_enforcement_rejects_unexplained_collisions():
    facts = default_facts(
        config=profile_config(enforcement="strict"),
        fragments={
            "widget-a": fragment(pkgs=[pkg("widget", "1.0", "ref-a",
                                           cpe=SHARED_CPE)]),
            "widget-b": fragment(pkgs=[pkg("widget", "1.0", "ref-b",
                                           cpe=SHARED_CPE)]),
        })
    docs, _logs = render_all(facts)

    assert "failure" in docs
    assert "REQ-IDEN-001" in docs["failure"]["unmetRequirementIds"]


def test_ordinary_output_warns_about_unexplained_collisions():
    facts = default_facts(fragments={
        "widget-a": fragment(pkgs=[pkg("widget", "1.0", "ref-a",
                                       cpe=SHARED_CPE)]),
        "widget-b": fragment(pkgs=[pkg("widget", "1.0", "ref-b",
                                       cpe=SHARED_CPE)]),
    })
    _sbom, _vex, logs = render_docs(facts)

    warnings = [message for level, message in logs if level == "warn"]
    assert any("ref-a" in message and "ref-b" in message
               and "collision" in message.lower() for message in warnings)


def test_distinct_cpes_produce_no_collision_finding():
    docs, _logs = render_all(default_facts(config=profile_config()))

    finding = finding_by_id(docs["report"], "REQ-IDEN-001")
    assert finding["verdict"] == "verified"
    assert "bomRefs" not in finding


def test_ordinary_and_profile_output_share_the_identity_model():
    fragments = {
        "widget-a": fragment(pkgs=[pkg("widget", "1.0", "ref-a",
                                       cpe=SHARED_CPE)]),
        "widget-b": fragment(pkgs=[pkg("widget", "1.0", "ref-b",
                                       cpe=SHARED_CPE)]),
    }
    plain, _logs = render_all(default_facts(fragments=fragments))
    profiled, _logs = render_all(
        default_facts(config=profile_config(), fragments=fragments))

    assert plain["sbom"]["components"] == profiled["sbom"]["components"]

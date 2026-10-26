"""Logical component identity at the document surface: creator-assigned
identity instead of CVE aliases, one component per recipe, instances that
share a CPE, and collision reporting. Ordinary output and the alignment
profile are held to the same model (ADR-0006, ADR-0009)."""

import json

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


def test_first_declared_aliases_select_cpe_and_keep_all_correlation_properties():
    identity = meta_cyclonedx.component_identity(
        "linux-yocto", "6.6", "pkg:yocto/linux-yocto@6.6",
        cve_products="linux_kernel linux linux_kernel",
        cve_versions="6.6 6.5 6.6+gitAUTOINC+abc 6.5")
    identity["bom-ref"] = "ref-k"
    sbom, _vex, _logs = render_docs(default_facts(
        fragments={"linux-yocto": fragment(pkgs=[identity])}))

    [component] = sbom["components"]
    assert component["name"] == "linux-yocto"
    assert component["cpe"] == "cpe:2.3:*:*:linux_kernel:6.6:*:*:*:*:*:*:*"
    properties = component["properties"]
    assert [p["value"] for p in properties if p["name"] == "yocto:cve:product"] == [
        "linux_kernel", "linux"]
    assert [p["value"] for p in properties if p["name"] == "yocto:cve:version"] == [
        "6.6", "6.5"]
    assert [p["value"] for p in properties if p["name"] == "yocto:cve:cpe"] == [
        "cpe:2.3:*:*:linux_kernel:6.6:*:*:*:*:*:*:*",
        "cpe:2.3:*:*:linux_kernel:6.5:*:*:*:*:*:*:*",
        "cpe:2.3:*:*:linux:6.6:*:*:*:*:*:*:*",
        "cpe:2.3:*:*:linux:6.5:*:*:*:*:*:*:*",
    ]


def test_alias_order_changes_only_the_primary_cpe_not_collisions_or_vex():
    def render_with(products):
        identity = meta_cyclonedx.component_identity(
            "linux-yocto", "6.6", "pkg:yocto/linux-yocto@6.6",
            cve_products=products)
        identity["bom-ref"] = "ref-k"
        other = meta_cyclonedx.component_identity(
            "linux-other", "6.6", "pkg:yocto/linux-other@6.6",
            cve_products="linux")
        other["bom-ref"] = "ref-l"
        return render_all(default_facts(
            config=profile_config(),
            fragments={
                "linux-yocto": fragment(
                    pkgs=[identity], cves=[vuln("CVE-2024-9", "ref-k")]),
                "linux-other": fragment(
                    pkgs=[other], cves=[vuln("CVE-2024-9", "ref-l")]),
            }))

    alphabetical, alphabetical_logs = render_with("linux linux_kernel")
    declared, declared_logs = render_with("linux_kernel linux")
    assert component_by_name(alphabetical["sbom"], "linux-yocto")["cpe"] == (
        "cpe:2.3:*:*:linux:6.6:*:*:*:*:*:*:*")
    assert component_by_name(declared["sbom"], "linux-yocto")["cpe"] == (
        "cpe:2.3:*:*:linux_kernel:6.6:*:*:*:*:*:*:*")
    assert finding_by_id(alphabetical["report"], "REQ-IDEN-001") == (
        finding_by_id(declared["report"], "REQ-IDEN-001"))
    assert [message for _level, message in alphabetical_logs
            if "share CPE(s)" in message] == [
                message for _level, message in declared_logs
                if "share CPE(s)" in message]

    for docs in (alphabetical, declared):
        serial = docs["sbom"]["serialNumber"].removeprefix("urn:uuid:")
        assert sorted(affect["ref"].removeprefix(f"urn:cdx:{serial}/1#")
                      for statement in docs["vex"]["vulnerabilities"]
                      for affect in statement["affects"]) == ["ref-k", "ref-l"]

    def vex_bytes(docs):
        serial = docs["sbom"]["serialNumber"].removeprefix("urn:uuid:")
        return json.dumps(docs["vex"]["vulnerabilities"],
                          sort_keys=True).replace(serial, "<serial>")

    assert vex_bytes(alphabetical) == vex_bytes(declared)


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

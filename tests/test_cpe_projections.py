"""Opt-in CPE collision view through the public renderer and configuration gate."""

import copy
import json
import re

import meta_cyclonedx

from helpers import (default_config, default_facts, dep, fragment, pkg,
                     render_docs, vuln)

CPE = "cpe:2.3:*:*:gcc:13:*:*:*:*:*:*:*"


def twin_facts(**config):
    return default_facts(
        config=default_config(**config),
        fragments={
            "libgcc": fragment(
                pkgs=[pkg("libgcc", "13", "ref-z", cpe=CPE,
                          purl="pkg:yocto/libgcc@13",
                          properties=[{"name": "yocto:cve:product", "value": "gcc"}])],
                dependencies=[dep("ref-z", ["gcc-runtime", "libgcc", "helper"])],
                cves=[vuln("CVE-2025-1", "ref-z"),
                      vuln("CVE-2025-2", "ref-z", state="not_affected")]),
            "gcc-runtime": fragment(
                pkgs=[pkg("gcc-runtime", "13", "ref-a", cpe=CPE,
                          purl="pkg:yocto/gcc-runtime@13",
                          properties=[{"name": "yocto:cve:version", "value": "13"}])],
                dependencies=[dep("ref-a", ["libgcc", "helper"])],
                cves=[vuln("CVE-2025-1", "ref-a")]),
            "helper": fragment(pkgs=[pkg("helper", "1", "ref-h")],
                               dependencies=[dep("ref-h", ["libgcc"])])},
        image_install_recipes=["libgcc", "gcc-runtime", "helper"])


def test_explained_twins_keep_lowest_purl_and_rewrite_all_references():
    facts = twin_facts(deduplicate_cpe_collisions=True)
    sbom, vex, logs = render_docs(facts)

    assert {component["name"] for component in sbom["components"]} == {
        "gcc-runtime", "helper"}
    survivor = next(c for c in sbom["components"] if c["cpe"] == CPE)
    assert survivor["bom-ref"] == "ref-a"
    assert {p["value"] for p in survivor["properties"]} == {"gcc", "13"}
    edges = {entry["ref"]: entry["dependsOn"] for entry in sbom["dependencies"]}
    assert edges["ref-a"] == ["ref-h"]
    assert edges["ref-h"] == ["ref-a"]
    assert set(edges[sbom["metadata"]["component"]["bom-ref"]]) == {
        "ref-a", "ref-h"}
    assert len(vex["vulnerabilities"]) == 2
    serial = sbom["serialNumber"].removeprefix("urn:uuid:")
    assert all(statement["affects"] == [
        {"ref": f"urn:cdx:{serial}/1#ref-a"}]
        for statement in vex["vulnerabilities"])
    assert {statement["analysis"]["state"] for statement in vex["vulnerabilities"]} == {
        "resolved", "not_affected"}
    valid_refs = {c["bom-ref"] for c in sbom["components"]} | {
        sbom["metadata"]["component"]["bom-ref"]}
    assert all(entry["ref"] in valid_refs and entry["ref"] not in entry["dependsOn"]
               and len(entry["dependsOn"]) == len(set(entry["dependsOn"]))
               and set(entry["dependsOn"]) <= valid_refs
               for entry in sbom["dependencies"])
    assert any("CYCLONEDX_DEDUPLICATE_CPE_COLLISIONS" in message
               and "pkg:yocto/libgcc@13" in message for _, message in logs)


def test_survivor_ignores_bom_ref_order_and_original_facts_are_unchanged():
    facts = twin_facts(deduplicate_cpe_collisions=True)
    facts["fragments"]["libgcc"]["pkgs"][0]["bom-ref"] = "ref-0"
    facts["fragments"]["gcc-runtime"]["pkgs"][0]["bom-ref"] = "ref-9"
    for f in facts["fragments"].values():
        for dependency in f.get("dependencies", []):
            dependency["ref"] = {"ref-z": "ref-0", "ref-a": "ref-9"}.get(
                dependency["ref"], dependency["ref"])
    before = copy.deepcopy({key: value for key, value in facts.items() if key != "log"})
    for _ in range(2):
        sbom, _vex, _logs = render_docs(facts)
        assert next(c for c in sbom["components"] if c["cpe"] == CPE)["purl"] == (
            "pkg:yocto/gcc-runtime@13")
    assert {key: value for key, value in facts.items() if key != "log"} == before


def test_flag_off_output_is_identical_with_explicit_false():
    plain, plain_vex, _ = render_docs(twin_facts())
    explicit, explicit_vex, _ = render_docs(twin_facts(
        deduplicate_cpe_collisions=False))
    # UUIDs are generated afresh for each render; normalize only minted IDs.
    def stable(sbom, vex):
        return re.sub(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
                      r"[0-9a-f]{4}-[0-9a-f]{12}", "<uuid>",
                      json.dumps((sbom, vex), sort_keys=True))
    assert stable(plain, plain_vex) == stable(explicit, explicit_vex)
    assert len(plain["components"]) == 3


def test_unrelated_vex_statements_are_not_folded_by_twin_projection():
    facts = twin_facts(deduplicate_cpe_collisions=True)
    facts["fragments"]["helper"]["cves"] = [vuln("CVE-2025-99", "ref-h")]
    facts["fragments"]["another"] = fragment(
        pkgs=[pkg("another", "1", "ref-another")],
        cves=[vuln("CVE-2025-99", "ref-another")])
    sbom, vex, _logs = render_docs(facts)

    # This collision concerns gcc, not the two independent analyses of
    # unrelated components. Their original statement boundaries survive.
    refs = {component["bom-ref"] for component in sbom["components"]}
    serial = sbom["serialNumber"].removeprefix("urn:uuid:")
    statements = [v for v in vex["vulnerabilities"] if v["id"] == "CVE-2025-99"]
    assert len(statements) == 2
    assert {statement["affects"][0]["ref"] for statement in statements} == {
        f"urn:cdx:{serial}/1#ref-h", f"urn:cdx:{serial}/1#ref-another"}
    assert refs.issuperset({"ref-h", "ref-another"})


def test_file_attachment_moves_to_survivor_without_changing_file_component():
    facts = twin_facts(deduplicate_cpe_collisions=True)
    owned_file = {"type": "file", "name": "libgcc.so", "version": "13",
                  "bom-ref": "file:libgcc.so",
                  "hashes": [{"alg": "SHA-512", "content": "a" * 128}]}
    facts["fragments"]["libgcc"].update(
        extra_components=[owned_file], extra_roots=["file:libgcc.so"])

    sbom, _vex, _logs = render_docs(facts)
    assert next(c for c in sbom["components"] if c["bom-ref"] == "file:libgcc.so") == owned_file
    assert "file:libgcc.so" in next(e for e in sbom["dependencies"]
                                    if e["ref"] == "ref-a")["dependsOn"]
    assert not any(e["ref"] == "ref-z" for e in sbom["dependencies"])
    assert all(target in {c["bom-ref"] for c in sbom["components"]} | {
        sbom["metadata"]["component"]["bom-ref"]}
        for entry in sbom["dependencies"] for target in entry["dependsOn"])


def test_included_image_with_same_cpe_stays_a_separate_graph():
    from helpers import document, vex_document

    facts = twin_facts(deduplicate_cpe_collisions=True)
    included = document(
        "11111111-2222-3333-4444-555555555555",
        [pkg("included-gcc", "13", "inc-gcc", cpe=CPE,
             purl="pkg:yocto/included-gcc@13")],
        [dep("inc-gcc")],
        metadata_component={"bom-ref": "inc-image", "type": "firmware",
                            "name": "initramfs", "version": "1"})
    facts["included_images"] = [{
        "name": "initramfs", "sbom": included,
        "vex": vex_document([vuln("CVE-2025-3", "inc-gcc")]),
        "vex_error": None}]

    sbom, vex, _logs = render_docs(facts)
    assert next(c for c in sbom["components"] if c["bom-ref"] == "inc-gcc")["purl"] == (
        "pkg:yocto/included-gcc@13")
    assert next(e for e in sbom["dependencies"]
                if e["ref"] == "inc-gcc")["dependsOn"] == []
    assert len([c for c in sbom["components"] if c.get("cpe") == CPE]) == 2
    serial = sbom["serialNumber"].removeprefix("urn:uuid:")
    assert next(v for v in vex["vulnerabilities"] if v["id"] == "CVE-2025-3")[
        "affects"] == [{"ref": f"urn:cdx:{serial}/1#inc-gcc"}]


def test_indistinguishable_twins_are_not_merged():
    facts = twin_facts(deduplicate_cpe_collisions=True)
    facts["fragments"]["libgcc"]["pkgs"][0] = copy.deepcopy(
        facts["fragments"]["gcc-runtime"]["pkgs"][0])
    facts["fragments"]["libgcc"]["pkgs"][0]["bom-ref"] = "ref-z"
    facts["fragments"]["libgcc"]["dependencies"] = []
    facts["fragments"]["gcc-runtime"]["dependencies"] = []
    facts["fragments"]["libgcc"]["cves"] = []
    facts["fragments"]["gcc-runtime"]["cves"] = []
    sbom, _vex, logs = render_docs(facts)
    assert len([c for c in sbom["components"] if c["cpe"] == CPE]) == 2
    assert any("Unexplained component identity collision" in message
               for _, message in logs)


def test_profile_with_deduplication_is_rejected_at_configuration_gate():
    for spec_version in ("1.6", "1.7"):
        for enforcement in ("report", "strict"):
            assert "CYCLONEDX_DEDUPLICATE_CPE_COLLISIONS" in (
                meta_cyclonedx.config_errors(
                    spec_version, "firmware", "tr03183-2.1", enforcement,
                    deduplicate_cpe_collisions=True) or "")
    assert meta_cyclonedx.config_errors("1.7", "firmware", "", "report",
                                        deduplicate_cpe_collisions=True) is None

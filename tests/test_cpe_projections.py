"""Opt-in CPE tooling views through the public renderer and configuration gate."""

import copy
import json
import re

import meta_cyclonedx

from helpers import (default_config, default_facts, dep, fragment, pkg,
                     render_docs, vuln)

CPE = "cpe:2.3:*:*:gcc:13:*:*:*:*:*:*:*"
ALIAS_CPE = "cpe:2.3:*:*:linux_kernel:6.6:*:*:*:*:*:*:*"
PRIMARY_CPE = "cpe:2.3:*:*:linux:6.6:*:*:*:*:*:*:*"
BRIDGE_CPE = "cpe:2.3:*:*:gcc_bridge:13:*:*:*:*:*:*:*"
THIRD_CPE = "cpe:2.3:*:*:gcc_third:13:*:*:*:*:*:*:*"
SECOND_CPE = "cpe:2.3:*:*:runtime:2:*:*:*:*:*:*:*"
UNRESOLVED_CPE = "cpe:2.3:*:*:unresolved:1:*:*:*:*:*:*:*"


def assert_no_removed_references(sbom, vex, removed):
    """Check projected graph owners/targets, assemblies, and VEX targets."""
    assert not removed & {component["bom-ref"] for component in sbom["components"]}
    assert not removed & {
        ref for entry in sbom["dependencies"]
        for ref in [entry["ref"], *(entry.get("dependsOn") or [])]}
    assert not removed & {
        ref for composition in sbom["compositions"]
        for ref in composition.get("assemblies") or []}
    assert not removed & {
        affect["ref"].rpartition("#")[2]
        for statement in vex["vulnerabilities"]
        for affect in statement.get("affects") or []}




def alias_facts(**config):
    return default_facts(
        config=default_config(**config),
        fragments={"kernel": fragment(
            pkgs=[pkg("linux-yocto", "6.6", "ref-kernel", cpe=PRIMARY_CPE,
                      properties=[
                          {"name": "yocto:cve:product", "value": "linux"},
                          {"name": "yocto:cve:product", "value": "linux_kernel"},
                          {"name": "yocto:cve:version", "value": "6.6"},
                          {"name": "yocto:cve:cpe", "value": PRIMARY_CPE},
                          {"name": "yocto:cve:cpe", "value": ALIAS_CPE}])],
            cves=[vuln("CVE-2025-1", "ref-kernel")],
            extra_components=[{"type": "file", "name": "vmlinux",
                               "version": "6.6", "bom-ref": "file:vmlinux"}],
            extra_roots=["file:vmlinux"])},
        image_install_recipes=["kernel"], runtime_recipes=["kernel"])


def test_second_recipe_alias_projects_one_marked_component_without_owning_files_or_vex():
    sbom, vex, logs = render_docs(alias_facts(expand_cve_product_aliases=True))
    logical = next(c for c in sbom["components"] if c["name"] == "linux-yocto")
    aliases = [c for c in sbom["components"] if any(
        prop.get("name") == "yocto:projection:cve-product-alias"
        for prop in c.get("properties", []))]
    assert len(aliases) == 1
    alias = aliases[0]
    assert alias["name"] == "linux_kernel"
    assert alias["cpe"] == ALIAS_CPE
    assert alias["bom-ref"] != logical["bom-ref"]
    assert {"aggregate": "unknown", "assemblies": [alias["bom-ref"]]} in (
        sbom["compositions"])
    assert next(e for e in sbom["dependencies"] if e["ref"] == alias["bom-ref"])[
        "dependsOn"] == [logical["bom-ref"]]
    assert "file:vmlinux" in next(e for e in sbom["dependencies"]
                                  if e["ref"] == logical["bom-ref"])["dependsOn"]
    assert "file:vmlinux" not in next(e for e in sbom["dependencies"]
                                      if e["ref"] == alias["bom-ref"])["dependsOn"]
    assert len(vex["vulnerabilities"]) == 1
    serial = sbom["serialNumber"].removeprefix("urn:uuid:")
    assert vex["vulnerabilities"][0]["affects"] == [
        {"ref": f"urn:cdx:{serial}/1#{logical['bom-ref']}"}]
    assert any(level == "note" and "CYCLONEDX_EXPAND_CVE_PRODUCT_ALIASES" in message
               for level, message in logs)


def test_three_distinct_product_tokens_project_only_secondary_products():
    facts = alias_facts(expand_cve_product_aliases=True)
    logical = facts["fragments"]["kernel"]["pkgs"][0]
    logical["properties"].extend([
        {"name": "yocto:cve:product", "value": "acme:linux_driver"},
        {"name": "yocto:cve:product", "value": "linux_kernel"},
        {"name": "yocto:cve:cpe",
         "value": "cpe:2.3:*:acme:linux_driver:6.6:*:*:*:*:*:*:*"},
    ])

    sbom, _vex, _logs = render_docs(facts)
    aliases = [component for component in sbom["components"]
               if {"name": "yocto:projection:cve-product-alias",
                   "value": "true"} in component.get("properties", [])]
    assert len(aliases) == 2
    assert {(alias.get("group"), alias["name"], alias["cpe"])
            for alias in aliases} == {
        (None, "linux_kernel", ALIAS_CPE),
        ("acme", "linux_driver",
         "cpe:2.3:*:acme:linux_driver:6.6:*:*:*:*:*:*:*"),
    }


def test_duplicate_products_and_multiple_versions_keep_one_row_per_product():
    facts = alias_facts(expand_cve_product_aliases=True)
    logical = facts["fragments"]["kernel"]["pkgs"][0]
    logical["version"] = "6.6+vendor1"
    logical["properties"].extend([
        {"name": "yocto:cve:product", "value": "acme:driver"},
        {"name": "yocto:cve:product", "value": "acme:driver"},
        {"name": "yocto:cve:version", "value": "6.5"},
        {"name": "yocto:cve:cpe",
         "value": "cpe:2.3:*:*:linux_kernel:6.5:*:*:*:*:*:*:*"},
        {"name": "yocto:cve:cpe",
         "value": "cpe:2.3:*:acme:driver:6.6:*:*:*:*:*:*:*"},
        {"name": "yocto:cve:cpe",
         "value": "cpe:2.3:*:acme:driver:6.5:*:*:*:*:*:*:*"},
    ])

    sbom, _vex, _logs = render_docs(facts)
    assert next(c for c in sbom["components"] if c["bom-ref"] == "ref-kernel")[
        "version"] == "6.6+vendor1"
    aliases = [component for component in sbom["components"]
               if {"name": "yocto:projection:cve-product-alias",
                   "value": "true"} in component.get("properties", [])]
    assert len(aliases) == 2
    assert {alias["version"] for alias in aliases} == {"6.6"}
    assert {(alias.get("group"), alias["name"]): (
        alias["cpe"], [prop["value"] for prop in alias["properties"]
                       if prop["name"] == "yocto:cve:cpe"])
        for alias in aliases} == {
        (None, "linux_kernel"): (
            ALIAS_CPE, ["cpe:2.3:*:*:linux_kernel:6.5:*:*:*:*:*:*:*"]),
        ("acme", "driver"): (
            "cpe:2.3:*:acme:driver:6.6:*:*:*:*:*:*:*",
            ["cpe:2.3:*:acme:driver:6.5:*:*:*:*:*:*:*"]),
    }


def test_expansion_preserves_primary_included_imported_and_embedded_graphs():
    from helpers import document, vex_document

    facts = alias_facts()
    foreign = pkg("foreign", "6.6", "ref-imported", cpe=PRIMARY_CPE,
                  properties=[
                      {"name": "yocto:cve:product", "value": "linux"},
                      {"name": "yocto:cve:product", "value": "linux_kernel"},
                      {"name": "yocto:cve:cpe", "value": ALIAS_CPE}])
    facts["fragments"]["kernel"]["extra_components"].append(foreign)
    facts["fragments"]["kernel"]["extra_dependencies"] = [dep("ref-imported")]
    embedded = pkg("embedded", "6.6", "ref-embedded", cpe=PRIMARY_CPE,
                   properties=[
                       {"name": "yocto:cve:product", "value": "linux"},
                       {"name": "yocto:cve:product", "value": "linux_kernel"},
                       {"name": "yocto:cve:cpe", "value": ALIAS_CPE}])
    facts["included_images"] = [{
        "name": "initramfs",
        "sbom": document(
            "11111111-2222-3333-4444-555555555555",
            [embedded], [dep("ref-embedded")],
            metadata_component={"type": "firmware", "name": "initramfs",
                                "version": "1", "bom-ref": "ref-initramfs"}),
        "vex": vex_document([]), "vex_error": None,
    }]
    plain, plain_vex, _ = render_docs(copy.deepcopy(facts))
    facts["config"]["expand_cve_product_aliases"] = True
    expanded, expanded_vex, _ = render_docs(facts)

    def stable(value):
        return re.sub(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
                      r"[0-9a-f]{4}-[0-9a-f]{12}", "<uuid>",
                      json.dumps(value, sort_keys=True))

    assert stable(expanded["metadata"]["component"]) == stable(
        plain["metadata"]["component"])
    for ref in ("ref-kernel", "file:vmlinux", "ref-imported",
                "ref-embedded", "ref-initramfs"):
        for key, selector in (
            ("components", lambda row: row.get("bom-ref") == ref),
            ("dependencies", lambda row: row.get("ref") == ref),
            ("compositions", lambda row: ref in row.get("assemblies", [])),
        ):
            before = [row for row in plain[key] if selector(row)]
            after = [row for row in expanded[key] if selector(row)]
            assert stable(after) == stable(before), (key, ref)

    def primary_graph(sbom):
        ref = sbom["metadata"]["component"]["bom-ref"]
        return [entry for entry in sbom["dependencies"] if entry["ref"] == ref]

    assert stable(primary_graph(expanded)) == stable(primary_graph(plain))
    assert stable(expanded_vex["vulnerabilities"]) == stable(
        plain_vex["vulnerabilities"])


def test_alias_flag_off_keeps_exact_rendered_bytes():
    plain, plain_vex, _ = render_docs(alias_facts())
    off, off_vex, _ = render_docs(alias_facts(expand_cve_product_aliases=False))

    def stable(sbom, vex):
        return re.sub(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
                      r"[0-9a-f]{4}-[0-9a-f]{12}", "<uuid>",
                      json.dumps((sbom, vex), sort_keys=True))

    assert stable(plain, plain_vex) == stable(off, off_vex)
    assert {component["name"] for component in plain["components"]} == {
        "linux-yocto", "vmlinux"}



def test_alias_expansion_does_not_project_imported_components():
    facts = alias_facts(expand_cve_product_aliases=True)
    imported = pkg("foreign", "6.6", "ref-imported", cpe=PRIMARY_CPE,
                   properties=[
                       {"name": "yocto:cve:product", "value": "linux"},
                       {"name": "yocto:cve:product", "value": "linux_kernel"},
                       {"name": "yocto:cve:version", "value": "6.6"},
                       {"name": "yocto:cve:cpe", "value": ALIAS_CPE}])
    facts["fragments"]["kernel"]["extra_components"].append(imported)

    sbom, _vex, _logs = render_docs(facts)
    aliases = [c for c in sbom["components"] if any(
        prop.get("name") == "yocto:projection:cve-product-alias"
        for prop in c.get("properties", []))]
    assert len(aliases) == 1
    assert next(c for c in sbom["components"] if c["bom-ref"] == "ref-imported") == imported


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


def test_transitive_group_keeps_every_alias_and_rewrites_file_owners():
    file_component = {"type": "file", "name": "libbridge.so",
                      "bom-ref": "file:libbridge.so"}
    facts = default_facts(
        config=default_config(deduplicate_cpe_collisions=True),
        fragments={
            "alpha": fragment(pkgs=[pkg(
                "alpha", "13", "ref-a", cpe=CPE,
                properties=[{"name": "yocto:cve:product", "value": "alpha"}])],
                dependencies=[dep("ref-a", ["beta"])]),
            "beta": fragment(pkgs=[pkg(
                "beta", "13", "ref-b", cpe=CPE,
                properties=[{"name": "yocto:cve:product", "value": "beta"},
                            {"name": "yocto:cve:cpe", "value": BRIDGE_CPE}])],
                dependencies=[dep("ref-b", ["gamma"])]),
            "gamma": fragment(pkgs=[pkg(
                "gamma", "13", "ref-c", cpe=BRIDGE_CPE,
                properties=[{"name": "yocto:cve:product", "value": "gamma"},
                            {"name": "yocto:cve:version", "value": "13"},
                            {"name": "yocto:cve:cpe", "value": THIRD_CPE}])],
                cves=[vuln("CVE-2025-3", "ref-c")],
                extra_components=[file_component],
                extra_roots=["file:libbridge.so"]),
        },
        image_install_recipes=["alpha", "beta", "gamma"])

    sbom, vex, _logs = render_docs(facts)

    assert {component["bom-ref"] for component in sbom["components"]} == {
        "ref-a", "file:libbridge.so"}
    survivor = next(c for c in sbom["components"] if c["bom-ref"] == "ref-a")
    assert {(prop["name"], prop["value"]) for prop in survivor["properties"]} == {
        ("yocto:cve:product", "alpha"),
        ("yocto:cve:product", "beta"),
        ("yocto:cve:product", "gamma"),
        ("yocto:cve:version", "13"),
        ("yocto:cve:cpe", BRIDGE_CPE),
        ("yocto:cve:cpe", THIRD_CPE)}
    assert next(entry for entry in sbom["dependencies"]
                if entry["ref"] == "ref-a")["dependsOn"] == ["file:libbridge.so"]
    assert_no_removed_references(sbom, vex, {"ref-b", "ref-c"})
    serial = sbom["serialNumber"].removeprefix("urn:uuid:")
    assert vex["vulnerabilities"][0]["affects"] == [
        {"ref": f"urn:cdx:{serial}/1#ref-a"}]

    added = meta_cyclonedx.merge_sbom_cve_check(
        sbom, vex, {"package": [
            {"name": alias, "cpes": [cpe],
             "issue": [{"id": cve, "status": "Patched", "detail": "fixed"}]}
            for alias, cpe, cve in (
                ("alpha", CPE, "CVE-2025-11"),
                ("beta", BRIDGE_CPE, "CVE-2025-12"),
                ("gamma", THIRD_CPE, "CVE-2025-13"))]},
        default_config())
    assert added == 3
    assert {statement["id"] for statement in vex["vulnerabilities"]} == {
        "CVE-2025-3", "CVE-2025-11", "CVE-2025-12", "CVE-2025-13"}
    assert all(statement["affects"] == [
        {"ref": f"urn:cdx:{serial}/1#ref-a"}]
        for statement in vex["vulnerabilities"])


def test_independent_groups_merge_without_absorbing_unexplained_twins():
    fragments = {
        "alpha": fragment(pkgs=[pkg("alpha", "13", "ref-a", cpe=CPE)]),
        "beta": fragment(
            pkgs=[pkg("beta", "13", "ref-b", cpe=CPE)],
            extra_components=[{"type": "file", "name": "beta.so",
                               "bom-ref": "file:beta.so"}],
            extra_roots=["file:beta.so"]),
        "charlie": fragment(pkgs=[pkg(
            "charlie", "2", "ref-c", cpe=SECOND_CPE)]),
        "delta": fragment(
            pkgs=[pkg("delta", "2", "ref-d", cpe=SECOND_CPE)],
            cves=[vuln("CVE-2025-22", "ref-d")]),
        "echo": fragment(pkgs=[pkg(
            "unresolved", "1", "ref-e", cpe=UNRESOLVED_CPE)]),
        "foxtrot": fragment(pkgs=[pkg(
            "unresolved", "1", "ref-f", cpe=UNRESOLVED_CPE)]),
        "helper": fragment(
            pkgs=[pkg("helper", "1", "ref-h")],
            dependencies=[dep("ref-h", ["beta", "delta", "echo"])]),
    }
    for rows in (fragments, dict(reversed(list(fragments.items())))):
        facts = default_facts(
            config=default_config(deduplicate_cpe_collisions=True),
            fragments=rows,
            image_install_recipes=list(rows))
        sbom, vex, logs = render_docs(facts)

        assert {c["bom-ref"] for c in sbom["components"]} == {
            "ref-a", "ref-c", "ref-e", "ref-f", "ref-h", "file:beta.so"}
        assert next(entry for entry in sbom["dependencies"]
                    if entry["ref"] == "ref-a")["dependsOn"] == ["file:beta.so"]
        assert set(next(entry for entry in sbom["dependencies"]
                        if entry["ref"] == "ref-h")["dependsOn"]) == {
            "ref-a", "ref-c", "ref-e"}
        assert_no_removed_references(sbom, vex, {"ref-b", "ref-d"})
        serial = sbom["serialNumber"].removeprefix("urn:uuid:")
        assert vex["vulnerabilities"][0]["affects"] == [
            {"ref": f"urn:cdx:{serial}/1#ref-c"}]
        assert sum("merged " in message for _, message in logs) == 2
        assert any("Unexplained component identity collision" in message
                   and "ref-e" in message and "ref-f" in message
                   for _, message in logs)


def test_vex_only_difference_with_equal_purls_chooses_stable_recipe():
    for first_ref, second_ref in (("ref-z", "ref-a"), ("ref-a", "ref-z")):
        facts = default_facts(
            config=default_config(deduplicate_cpe_collisions=True),
            fragments={
                "alpha": fragment(
                    pkgs=[pkg("runtime", "13", first_ref, cpe=CPE)],
                    cves=[vuln("CVE-2025-41", first_ref)]),
                "beta": fragment(pkgs=[pkg("runtime", "13", second_ref, cpe=CPE)]),
            },
            image_install_recipes=["alpha", "beta"])
        sbom, vex, _logs = render_docs(facts)

        assert {component["bom-ref"] for component in sbom["components"]} == {
            first_ref}
        assert_no_removed_references(sbom, vex, {second_ref})


def test_different_purls_without_distinct_instance_evidence_do_not_merge():
    facts = default_facts(
        config=default_config(deduplicate_cpe_collisions=True),
        fragments={
            "alpha": fragment(pkgs=[pkg("alpha", "13", "ref-a", cpe=CPE)]),
            "beta": fragment(pkgs=[pkg("beta", "13", "ref-b", cpe=CPE)]),
        },
        image_install_recipes=["alpha", "beta"])

    sbom, _vex, _logs = render_docs(facts)

    assert {component["bom-ref"] for component in sbom["components"]} == {
        "ref-a", "ref-b"}


def test_same_package_coordinates_with_distinct_artifacts_are_explained():
    shared_purl = "pkg:yocto/runtime@13"
    facts = default_facts(
        config=default_config(deduplicate_cpe_collisions=True),
        fragments={
            "runtime-a": fragment(pkgs=[pkg(
                "runtime", "13", "ref-a", cpe=CPE, purl=shared_purl,
                hashes=[{"alg": "SHA-512", "content": "a" * 128}])]),
            "runtime-b": fragment(pkgs=[pkg(
                "runtime", "13", "ref-b", cpe=CPE, purl=shared_purl,
                hashes=[{"alg": "SHA-512", "content": "b" * 128}])]),
        },
        image_install_recipes=["runtime-a", "runtime-b"],
        runtime_recipes=["runtime-a", "runtime-b"])

    sbom, _vex, logs = render_docs(facts)

    assert len([component for component in sbom["components"]
                if component.get("cpe") == CPE]) == 1
    assert not any("kept separate" in message for _, message in logs)


def test_correlation_aliases_alone_do_not_explain_identical_instances():
    facts = default_facts(
        config=default_config(deduplicate_cpe_collisions=True),
        fragments={
            "runtime-a": fragment(pkgs=[pkg(
                "runtime", "13", "ref-a", cpe=CPE,
                properties=[{"name": "yocto:cve:product", "value": "first"}])]),
            "runtime-b": fragment(pkgs=[pkg(
                "runtime", "13", "ref-b", cpe=CPE,
                properties=[{"name": "yocto:cve:product", "value": "second"}])]),
        },
        image_install_recipes=["runtime-a", "runtime-b"])

    sbom, _vex, logs = render_docs(facts)

    assert {component["bom-ref"] for component in sbom["components"]} == {
        "ref-a", "ref-b"}
    assert any("Unexplained component identity collision" in message
               and "ref-a" in message and "ref-b" in message
               for _, message in logs)


def test_profile_with_deduplication_is_rejected_at_configuration_gate():
    for spec_version in ("1.6", "1.7"):
        for enforcement in ("report", "strict"):
            assert "CYCLONEDX_DEDUPLICATE_CPE_COLLISIONS" in (
                meta_cyclonedx.config_errors(
                    spec_version, "firmware", profile="tr03183-2.1",
                    enforcement=enforcement, deduplicate_cpe_collisions=True) or "")
    assert meta_cyclonedx.config_errors(
        "1.7", "firmware", profile="", enforcement="report",
        deduplicate_cpe_collisions=True) is None


def test_profile_with_alias_expansion_is_rejected_at_configuration_gate():
    for spec_version in ("1.6", "1.7"):
        for enforcement in ("report", "strict"):
            assert "CYCLONEDX_EXPAND_CVE_PRODUCT_ALIASES" in (
                meta_cyclonedx.config_errors(
                    spec_version, "firmware", profile="tr03183-2.1",
                    enforcement=enforcement, expand_cve_product_aliases=True) or "")
    assert meta_cyclonedx.config_errors(
        "1.7", "firmware", profile="", enforcement="report",
        expand_cve_product_aliases=True) is None

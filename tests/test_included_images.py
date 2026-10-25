"""Embedded image composition: CYCLONEDX_EXTRA_RUNTIME_IMAGE_RECIPES merging."""

from helpers import (affect_refs, component_by_name, default_facts, document,
                     finding_by_id, fragment, pkg, profile_config, ref_of,
                     render_all, render_docs, root_entry, vuln, vex_document)

INC_SERIAL = "11111111-2222-3333-4444-555555555555"
CPE_Z = "cpe:2.3:*:*:zlib:1.3:*:*:*:*:*:*:*"


def parent_facts(**overrides):
    facts = default_facts(fragments={
        "zlib": fragment(pkgs=[pkg("zlib", "1.3", "ref-z", cpe=CPE_Z)]),
        "app": fragment(pkgs=[pkg("app", "1.0", "ref-app")]),
    }, runtime_recipes=["zlib", "app"], image_install_recipes=["app"])
    facts.update(overrides)
    return facts


def included_image(vex=..., **sbom_kwargs):
    sbom = document(
        INC_SERIAL,
        components=[
            pkg("zlib", "1.3", "inc-z", cpe=CPE_Z, scope="excluded"),
            pkg("busybox", "1.36", "inc-u", purl="pkg:yocto/busybox@1.36"),
        ],
        dependencies=[
            {"ref": "inc-z", "dependsOn": ["inc-u"]},
            {"ref": "inc-meta", "dependsOn": ["inc-z"]},
        ],
        metadata_component={"bom-ref": "inc-meta", "type": "firmware",
                            "name": "initramfs", "version": "2.0"},
        **sbom_kwargs)
    if vex is ...:
        vex = vex_document([{
            "id": "CVE-2024-5",
            "source": {"name": "NVD",
                       "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-5"},
            "analysis": {"state": "resolved", "detail": "STATE: fixed\n"},
            "affects": [
                {"ref": f"urn:cdx:{INC_SERIAL}/1#inc-u"},
                {"ref": f"urn:cdx:{INC_SERIAL}/1#inc-z"},
            ],
        }])
    return {"name": "initramfs", "sbom": sbom, "vex": vex, "vex_error": None}


def test_included_image_becomes_a_firmware_component_on_the_root():
    sbom, _vex, _logs = render_docs(parent_facts(included_images=[included_image()]))

    firmware = component_by_name(sbom, "initramfs")
    assert firmware["type"] == "firmware"
    assert firmware["version"] == "2.0"
    assert firmware["scope"] == "required"
    assert firmware["bom-ref"] in root_entry(sbom)["dependsOn"]


def test_same_identity_components_merge_onto_the_parent_instance():
    # Same name, version and package purl: the very same component
    # instance, so the included copy resolves to the parent's bom-ref.
    # A shared CPE alone would not merge anything.
    sbom, _vex, _logs = render_docs(parent_facts(included_images=[included_image()]))

    assert component_by_name(sbom, "zlib")["bom-ref"] == "ref-z"
    # parent "required" outranks the included "excluded"
    assert component_by_name(sbom, "zlib")["scope"] == "required"


def test_same_cpe_different_build_stays_separate_when_merged():
    other = document(
        INC_SERIAL,
        components=[pkg("zlib", "1.3", "inc-z2", cpe=CPE_Z,
                        purl="pkg:yocto/meta-independent/zlib@1.3")],
        dependencies=[],
        metadata_component={"bom-ref": "inc-meta", "type": "firmware",
                            "name": "initramfs", "version": "2.0"})
    sbom, _vex, _logs = render_docs(parent_facts(included_images=[
        {"name": "initramfs", "sbom": other, "vex": None, "vex_error": None}]))

    sharing = [c for c in sbom["components"] if c.get("cpe") == CPE_Z]
    assert sorted(c["bom-ref"] for c in sharing) == ["inc-z2", "ref-z"]


def test_unique_components_join_with_required_scope():
    sbom, _vex, _logs = render_docs(parent_facts(included_images=[included_image()]))

    assert component_by_name(sbom, "busybox")["scope"] == "required"
    assert component_by_name(sbom, "busybox")["bom-ref"] == "inc-u"


def test_included_dependency_edges_are_remapped_to_parent_refs():
    sbom, _vex, _logs = render_docs(parent_facts(included_images=[included_image()]))

    zlib_entry = next(e for e in sbom["dependencies"] if e["ref"] == "ref-z")
    assert zlib_entry["dependsOn"] == ["inc-u"]

    firmware_ref = component_by_name(sbom, "initramfs")["bom-ref"]
    firmware_entry = next(e for e in sbom["dependencies"] if e["ref"] == firmware_ref)
    assert firmware_entry["dependsOn"] == ["ref-z"]


def test_included_vex_references_rewrite_to_the_parent_serial():
    sbom, vex, _logs = render_docs(parent_facts(included_images=[included_image()]))

    serial = sbom["serialNumber"].split("urn:uuid:")[-1]
    statement = next(v for v in vex["vulnerabilities"] if v["id"] == "CVE-2024-5")
    assert sorted(affect_refs(statement)) == sorted([
        f"urn:cdx:{serial}/1#inc-u",   # unique component keeps its ref
        f"urn:cdx:{serial}/1#ref-z",   # shared component resolves to the parent ref
    ])
    assert INC_SERIAL not in str(vex)


def test_included_vex_merges_affects_into_an_existing_statement():
    parent_vuln = vuln("CVE-2024-5", "ref-app")
    facts = parent_facts(included_images=[included_image()])
    facts["fragments"]["app"]["cves"] = [parent_vuln]
    sbom, vex, _logs = render_docs(facts)

    statements = [v for v in vex["vulnerabilities"] if v["id"] == "CVE-2024-5"]
    assert len(statements) == 1
    serial = sbom["serialNumber"].split("urn:uuid:")[-1]
    assert sorted(affect_refs(statements[0])) == sorted([
        f"urn:cdx:{serial}/1#ref-app",
        f"urn:cdx:{serial}/1#inc-u",
        f"urn:cdx:{serial}/1#ref-z",
    ])


def test_spec_version_mismatch_is_reported_but_merges():
    entry = included_image()
    entry["sbom"]["specVersion"] = "1.6"
    sbom, _vex, logs = render_docs(parent_facts(included_images=[entry]))

    assert any(level == "warn" and "differs from parent" in message
               for level, message in logs)
    assert component_by_name(sbom, "initramfs")


def test_missing_included_vex_skips_only_the_vex_merge():
    entry = included_image()
    entry["vex"] = None
    sbom, vex, _logs = render_docs(parent_facts(included_images=[entry]))

    assert component_by_name(sbom, "initramfs")
    assert vex["vulnerabilities"] == []


def test_unparseable_included_vex_is_reported_not_silently_skipped():
    # The image's SBOM still merges and its VEX statements cannot be
    # salvaged, but the loss is an explicit composition finding now -
    # report enforcement publishes it, strict enforcement rejects it.
    entry = included_image()
    entry["vex"] = None
    entry["vex_error"] = "Expecting value: line 1 column 1 (char 0)"
    facts = parent_facts(config=profile_config(), included_images=[entry])
    docs, logs = render_all(facts)

    assert any(level == "warn" and "cannot parse VEX" in message
               for level, message in logs)
    assert docs["vex"]["vulnerabilities"] == []
    assert component_by_name(docs["sbom"], "busybox")
    finding = finding_by_id(docs["report"], "REQ-MERGE-001")
    assert finding["verdict"] == "unmet"


def test_included_component_with_conflicting_ref_and_other_instance_is_kept():
    # The image's openssl happens to reuse a bom-ref the parent minted
    # for its app component. It is a different component instance, so it
    # must not be dropped to tidy the merged document: both components
    # are published and the duplicate ref becomes a finding (ADR-0004).
    other = document(
        INC_SERIAL,
        components=[pkg("openssl", "3.0", "ref-app")],
        dependencies=[],
        metadata_component={"bom-ref": "inc-meta", "type": "firmware",
                            "name": "initramfs", "version": "2.0"})
    facts = parent_facts(config=profile_config(),
                         included_images=[{"name": "initramfs",
                                           "sbom": other, "vex": None,
                                           "vex_error": None}])
    docs, _logs = render_all(facts)

    colliding = [c for c in docs["sbom"]["components"]
                 if c["bom-ref"] == "ref-app"]
    assert sorted(c["name"] for c in colliding) == ["app", "openssl"]
    finding = finding_by_id(docs["report"], "REQ-REF-001")
    assert finding["verdict"] == "unmet"
    assert "ref-app" in finding["bomRefs"]


def test_reconciled_instance_keeps_licence_evidence_from_both_documents():
    # Same instance (name, version, purl) but the embedded document
    # carries licence evidence the parent's copy lacks. Reconciling the
    # instances must union the evidence, not discard the image's view.
    entry = included_image()
    entry["sbom"]["components"][0]["licenses"] = [{"license": {"id": "Zlib"}}]
    sbom, _vex, _logs = render_docs(parent_facts(included_images=[entry]))

    zlib = component_by_name(sbom, "zlib")
    assert zlib["bom-ref"] == "ref-z"
    assert {"license": {"id": "Zlib"}} in zlib["licenses"]


def test_included_vex_statement_with_a_different_analysis_stays_separate():
    # Parent and image analyse the same CVE differently for different
    # instances. Folding affects may only unify statements that analyse
    # identically; a distinct analysis is a distinct statement and must
    # survive the merge (no lost statements).
    parent_vuln = vuln("CVE-2024-9", "ref-app", state="resolved")
    entry = included_image(vex=vex_document([{
        "id": "CVE-2024-9",
        "source": {"name": "NVD",
                   "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-9"},
        "analysis": {"state": "unresolved", "detail": ""},
        "affects": [{"ref": f"urn:cdx:{INC_SERIAL}/1#inc-u"}],
    }]))
    facts = parent_facts(included_images=[entry], fragments={
        "zlib": fragment(pkgs=[pkg("zlib", "1.3", "ref-z", cpe=CPE_Z)]),
        "app": fragment(pkgs=[pkg("app", "1.0", "ref-app")],
                        cves=[parent_vuln]),
    }, runtime_recipes=["zlib", "app"], image_install_recipes=["app"])
    sbom, vex, _logs = render_docs(facts)

    statements = [v for v in vex["vulnerabilities"]
                  if v["id"] == "CVE-2024-9"]
    assert len(statements) == 2
    states = {v["analysis"]["state"] for v in statements}
    assert states == {"resolved", "unresolved"}
    unresolved = next(v for v in statements
                      if v["analysis"]["state"] == "unresolved")
    serial = sbom["serialNumber"].removeprefix("urn:uuid:")
    assert affect_refs(unresolved) == [f"urn:cdx:{serial}/1#inc-u"]


def test_included_image_without_metadata_root_is_found_and_dangling():
    # A parseable image SBOM whose metadata.component root is absent:
    # the graph cannot silently re-home its edges. The dangling root
    # reference and the composition finding make the malformed input
    # visible instead.
    other = document(
        INC_SERIAL,
        components=[pkg("busybox", "1.36", "inc-u")],
        dependencies=[{"ref": "inc-meta", "dependsOn": ["inc-u"]}],
        metadata_component=None)
    facts = parent_facts(config=profile_config(),
                         included_images=[{"name": "initramfs",
                                           "sbom": other, "vex": None,
                                           "vex_error": None}])
    docs, _logs = render_all(facts)

    assert component_by_name(docs["sbom"], "busybox")["bom-ref"] == "inc-u"
    entry_refs = [e["ref"] for e in docs["sbom"]["dependencies"]]
    assert "inc-meta" in entry_refs
    finding = finding_by_id(docs["report"], "REQ-MERGE-001")
    assert finding["verdict"] == "unmet"
    assert "inc-meta" in finding["diagnosticMessage"]

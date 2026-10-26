"""Imported ecosystem BOM composition: recursive graphs, instances, findings.

The renderer must validate and compose the graphs contributed through
CYCLONEDX_EXTRA_BOM_FILES fragments without flattening them, collapsing
independently assessable component instances, or silently truncating
malformed input (ticket #6, ADR-0004, ADR-0006).
"""

import ast
import json
import os
import sys
import types

import meta_cyclonedx
import pytest

from helpers import (component_by_name, default_facts, dep_entry,
                     finding_by_id, fragment, pkg, profile_config,
                     render_all, render_docs)


def contributed(pkg_list, dep_entries, roots, **extra):
    return {
        "extra_components": pkg_list,
        "extra_dependencies": dep_entries,
        "extra_roots": roots,
        **extra,
    }


def test_imported_component_with_colliding_ref_and_different_evidence_is_kept():
    # Two contributed modules share a bom-ref but are different component
    # instances. The graph keeps both — publishing an inconsistent document
    # with a finding beats silently dropping one instance (ADR-0004).
    facts = default_facts(config=profile_config(), fragments={
        "rust-app": fragment(
            pkgs=[pkg("rust-app", "1", "ref-r")],
            **contributed(
                [{"bom-ref": "cargo://shared", "type": "library",
                  "name": "serde", "version": "1.0",
                  "purl": "pkg:cargo/serde@1.0"}],
                [], [])),
        "go-app": fragment(
            pkgs=[pkg("go-app", "1", "ref-g")],
            **contributed(
                [{"bom-ref": "cargo://shared", "type": "library",
                  "name": "serde", "version": "0.9",
                  "purl": "pkg:cargo/serde@0.9"}],
                [], [])),
    })
    docs, _logs = render_all(facts)
    sbom = docs["sbom"]

    shared = [c for c in sbom["components"] if c["bom-ref"] == "cargo://shared"]
    assert sorted(c["version"] for c in shared) == ["0.9", "1.0"]
    finding = finding_by_id(docs["report"], "REQ-REF-001")
    assert finding["verdict"] == "unmet"
    assert "cargo://shared" in finding["bomRefs"]


def test_imported_instances_with_different_dependency_builds_stay_separate():
    # Equal package coordinates cannot collapse different resolved builds.
    serde_a = {"bom-ref": "cargo://a/serde", "type": "library",
               "name": "serde", "version": "1.0",
               "purl": "pkg:cargo/serde@1.0"}
    serde_b = {"bom-ref": "cargo://b/serde", "type": "library",
               "name": "serde", "version": "1.0",
               "purl": "pkg:cargo/serde@1.0"}
    libc_a = {"bom-ref": "cargo://a/libc", "type": "library", "name": "libc",
              "version": "0.2", "purl": "pkg:cargo/libc@0.2"}
    libc_b = {"bom-ref": "cargo://b/libc", "type": "library", "name": "libc",
              "version": "0.3", "purl": "pkg:cargo/libc@0.3"}
    facts = default_facts(fragments={
        "rust-app": fragment(
            pkgs=[pkg("rust-app", "1", "ref-r")],
            **contributed([serde_a, libc_a],
                          [{"ref": "cargo://a/serde",
                            "dependsOn": ["cargo://a/libc"]}],
                          ["cargo://a/serde"])),
        "other-app": fragment(
            pkgs=[pkg("other-app", "1", "ref-o")],
            **contributed([serde_b, libc_b],
                          [{"ref": "cargo://b/serde",
                            "dependsOn": ["cargo://b/libc"]}],
                          ["cargo://b/serde"])),
    })
    sbom, _vex, _logs = render_docs(facts)

    serdes = [c for c in sbom["components"] if c["name"] == "serde"]
    assert sorted(c["bom-ref"] for c in serdes) == [
        "cargo://a/serde", "cargo://b/serde"]
    assert dep_entry(sbom, "cargo://a/serde")["dependsOn"] == ["cargo://a/libc"]
    assert dep_entry(sbom, "cargo://b/serde")["dependsOn"] == ["cargo://b/libc"]
    assert dep_entry(sbom, "ref-r")["dependsOn"] == ["cargo://a/serde"]
    assert dep_entry(sbom, "ref-o")["dependsOn"] == ["cargo://b/serde"]


def test_missing_imported_root_produces_a_finding_not_truncated_output():
    # The contributed edges name a tree root that no component carries:
    # the imported document was malformed (e.g. its metadata.component
    # root was dropped). The graph still gets the attach edge — published
    # dangling and reported — instead of silently losing the attachment.
    child = {"bom-ref": "cargo://child", "type": "library", "name": "dep",
             "version": "1", "purl": "pkg:cargo/dep@1"}
    facts = default_facts(config=profile_config(), fragments={
        "rust-app": fragment(
            pkgs=[pkg("rust-app", "1", "ref-r")],
            **contributed([child],
                          [{"ref": "cargo://child",
                            "dependsOn": ["cargo://missing-root"]}],
                          ["cargo://missing-root"])),
    })
    docs, _logs = render_all(facts)
    sbom = docs["sbom"]

    assert dep_entry(sbom, "ref-r")["dependsOn"] == ["cargo://missing-root"]
    assert dep_entry(sbom, "cargo://child")["dependsOn"] == \
        ["cargo://missing-root"]
    finding = finding_by_id(docs["report"], "REQ-REF-001")
    assert finding["verdict"] == "unmet"
    assert "cargo://missing-root" in finding["bomRefs"]


def broken_bom_fragment():
    # What the adapter hands over when CYCLONEDX_EXTRA_BOM_FILES points at
    # a document that cannot be read in report enforcement: the evidence
    # is lost upstream, so the defect must not vanish downstream.
    return fragment(
        pkgs=[pkg("rust-app", "1", "ref-r")],
        extra_bom_errors=[{"file": "/build/cargo.bom.json",
                           "error": "Expecting value: line 1 column 1"}])


def test_unusable_imported_bom_reports_an_unmet_composition_finding():
    facts = default_facts(config=profile_config(),
                          fragments={"rust-app": broken_bom_fragment()})
    docs, logs = render_all(facts)

    assert any(level == "warn" and "unusable" in message
               for level, message in logs)
    finding = finding_by_id(docs["report"], "REQ-MERGE-001")
    assert finding["verdict"] == "unmet"
    assert "/build/cargo.bom.json" in finding["diagnosticMessage"]
    # Everything else still renders; report enforcement publishes.
    assert docs["sbom"]["components"]


def test_strict_enforcement_fails_on_the_unusable_imported_bom():
    facts = default_facts(config=profile_config(enforcement="strict"),
                          fragments={"rust-app": broken_bom_fragment()})
    docs, _logs = render_all(facts)

    assert "failure" in docs
    assert "REQ-MERGE-001" in docs["failure"]["unmetRequirementIds"]


# --- Embedded image composition defects -----------------------------------

def test_unusable_included_image_sbom_is_found_not_dropped():
    # An embedded image whose completed SBOM the adapter could not read
    # used to vanish between adapter and renderer. The image stays a
    # component of the delivery item and the loss is a finding.
    from test_included_images import parent_facts
    entry = {"name": "initramfs", "sbom": None, "vex": None,
             "vex_error": None,
             "sbom_error": "Expecting value: line 1 column 1 (char 0)"}
    facts = parent_facts(config=profile_config(), included_images=[entry])
    docs, logs = render_all(facts)

    assert any(level == "warn" and "initramfs" in message
               for level, message in logs)
    assert component_by_name(docs["sbom"], "initramfs")["version"] == \
        "unknown"
    finding = finding_by_id(docs["report"], "REQ-MERGE-001")
    assert finding["verdict"] == "unmet"
    assert "initramfs" in finding["diagnosticMessage"]


def test_strict_enforcement_fails_on_the_unusable_included_image():
    from test_included_images import parent_facts
    entry = {"name": "initramfs", "sbom": None, "vex": None,
             "vex_error": None, "sbom_error": "not json"}
    facts = parent_facts(config=profile_config(enforcement="strict"),
                         included_images=[entry])
    docs, _logs = render_all(facts)

    assert "failure" in docs
    assert "REQ-MERGE-001" in docs["failure"]["unmetRequirementIds"]


def composition_for(sbom, ref):
    matches = [c for c in sbom.get("compositions") or []
               if ref in c["assemblies"]]
    assert len(matches) == 1, f"expected exactly one composition for {ref}"
    return matches[0]


def three_module_graph():
    mods = [{"bom-ref": f"cargo://m{i}", "type": "library", "name": f"m{i}",
             "version": "1", "purl": f"pkg:cargo/m{i}@1"}
            for i in range(3)]
    edges = [{"ref": "cargo://m0", "dependsOn": ["cargo://m1"]},
             {"ref": "cargo://m1", "dependsOn": ["cargo://m2"]}]
    return default_facts(fragments={
        "rust-app": fragment(pkgs=[pkg("rust-app", "1", "ref-r")],
                             **contributed(mods, edges, ["cargo://m0"]))})


def test_recursive_imported_graph_survives_several_levels():
    # m0 -> m1 -> m2 stays a chain: the merge composes the imported
    # resolution, it never flattens it onto the owner's level.
    sbom, _vex, _logs = render_docs(three_module_graph())

    assert dep_entry(sbom, "ref-r")["dependsOn"] == ["cargo://m0"]
    assert dep_entry(sbom, "cargo://m0")["dependsOn"] == ["cargo://m1"]
    assert dep_entry(sbom, "cargo://m1")["dependsOn"] == ["cargo://m2"]
    assert dep_entry(sbom, "cargo://m2")["dependsOn"] == []


def test_imported_subtree_composition_is_unknown_not_complete():
    # The ecosystem BOM declares its own tree, but meta-cyclonedx cannot
    # claim that resolution saw everything: without Yocto static-link
    # evidence the aggregate stays unknown, never complete.
    sbom, _vex, _logs = render_docs(three_module_graph())

    assert composition_for(sbom, "cargo://m0")["aggregate"] == "unknown"
    assert composition_for(sbom, "cargo://m2")["aggregate"] == "unknown"


@pytest.mark.parametrize("inputs", [
    ("missing",),
    ("malformed",),
    ("valid", "missing", "malformed"),
])
def test_permissive_recipe_import_publishes_defects_without_reusing_a_bom(
        tmp_path, monkeypatch, inputs):
    from test_deploy_phase_facts import BBCLASS, _Data, class_function

    (tmp_path / "malformed").write_text("{")
    (tmp_path / "valid").write_text(json.dumps({
        "metadata": {"component": {
            "bom-ref": "imported-root", "name": "module",
            "version": "1", "type": "library"}},
        "dependencies": [{"ref": "imported-root", "dependsOn": []}],
    }))
    oe = types.ModuleType("oe")
    oe.purl = types.ModuleType("oe.purl")
    oe.purl.get_base_purl = lambda d: "pkg:yocto/app@1"
    oe.cve_check = types.ModuleType("oe.cve_check")
    oe.cve_check.get_patched_cves = lambda d: {}
    for name, module in (("oe", oe), ("oe.purl", oe.purl),
                         ("oe.cve_check", oe.cve_check)):
        monkeypatch.setitem(sys.modules, name, module)
    namespace = {
        "os": os,
        "bb": types.SimpleNamespace(
            debug=lambda *args: None, warn=lambda message: None),
        "_cyclonedx_renderer": lambda d: meta_cyclonedx,
        "get_custom_properties": lambda d: [],
        "get_recipe_dependencies": lambda d: [],
    }
    tree = ast.Module(body=[class_function(name) for name in
                           ("read_json", "write_json", "do_populate_cyclonedx")],
                      type_ignores=[])
    exec(compile(tree, BBCLASS, "exec"), namespace)
    namespace["do_populate_cyclonedx"](_Data({
        "PN": "app", "BPN": "app", "PV": "1",
        "CYCLONEDX_EXTRA_BOM_FILES":
            " ".join(str(tmp_path / name) for name in inputs),
        "CYCLONEDX_EXTRA_BOM_FILES_FAIL_ON_BROKEN_BOM_FILES": "0",
        "CYCLONEDX_PNDATA_WORKDIR": str(tmp_path),
    }))
    collected = json.loads((tmp_path / "app.json").read_text())
    assert collected.get("extra_roots", []) == (
        ["imported-root"] if "valid" in inputs else [])
    assert len(collected.get("extra_components", [])) == (
        1 if "valid" in inputs else 0)
    assert {os.path.basename(entry["file"])
            for entry in collected["extra_bom_errors"]} == set(inputs) - {"valid"}
    docs, _logs = render_all(default_facts(
        config=profile_config(), fragments={"app": collected},
        image_install_recipes=["app"]))
    assert finding_by_id(docs["report"], "REQ-MERGE-001")["verdict"] == "unmet"


@pytest.mark.parametrize("left,right", [
    ({"hashes": [{"alg": "SHA-512", "content": "a" * 128}]},
     {"hashes": [{"alg": "SHA-512", "content": "b" * 128}]}),
    ({"licenses": [{"license": {"id": "MIT"}}]},
     {"licenses": [{"license": {"id": "BSD-2-Clause"}}]}),
    ({"properties": [{"name": "build:variant", "value": "production"}]},
     {"properties": [{"name": "build:variant", "value": "recovery"}]}),
])
def test_imported_package_coordinates_do_not_override_instance_evidence(
        left, right):
    modules = [pkg("module", "1", "module-a", **left),
               pkg("module", "1", "module-b", **right)]
    docs, _logs = render_all(default_facts(
        config=profile_config(),
        fragments={"busybox": fragment(
            pkgs=[pkg("busybox", "1.36", "ref-busybox")],
            **contributed(modules, [], ["module-a", "module-b"]))}))
    represented = {c["bom-ref"]: c for c in docs["sbom"]["components"]}
    assert all(represented["module-a"][key] == value
               for key, value in left.items())
    assert all(represented["module-b"][key] == value
               for key, value in right.items())
    assert dep_entry(docs["sbom"], "ref-busybox")["dependsOn"] == [
        "module-a", "module-b"]
    assert finding_by_id(docs["report"], "REQ-IDEN-001")["verdict"] == "verified"


def test_equivalent_recursive_instances_reconcile_without_losing_edges():
    fragments = {}
    for owner in ("a", "b"):
        refs = [f"{owner}-{name}" for name in ("module", "dependency")]
        modules = [pkg("module", "1", refs[0]),
                   pkg("dependency", "2", refs[1])]
        fragments[owner] = fragment(
            pkgs=[pkg(f"app-{owner}", "1", f"app-{owner}")],
            **contributed(modules, [
                {"ref": refs[0], "dependsOn": [refs[1]]},
                {"ref": refs[1], "dependsOn": [refs[0]]},
            ], [refs[0]]))
    sbom, _vex, _logs = render_docs(default_facts(
        fragments=fragments, image_install_recipes=["a", "b"]))
    module = component_by_name(sbom, "module")["bom-ref"]
    dependency = component_by_name(sbom, "dependency")["bom-ref"]
    assert dep_entry(sbom, module)["dependsOn"] == [dependency]
    assert dep_entry(sbom, dependency)["dependsOn"] == [module]
    assert dep_entry(sbom, "app-a")["dependsOn"] == [module]
    assert dep_entry(sbom, "app-b")["dependsOn"] == [module]

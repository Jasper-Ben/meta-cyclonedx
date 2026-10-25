"""Imported ecosystem BOM composition: recursive graphs, instances, findings.

The renderer must validate and compose the graphs contributed through
CYCLONEDX_EXTRA_BOM_FILES fragments without flattening them, collapsing
independently assessable component instances, or silently truncating
malformed input (ticket #6, ADR-0004, ADR-0006).
"""

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


def test_one_imported_instance_reconciles_across_contributed_graphs():
    # Two recipes' ecosystem BOMs both link serde 1.0 (same name, version
    # and purl: the very same component instance) and each resolves it to
    # its own copy of the module graph. The instances reconcile onto one
    # node with both graphs' edges intact — no duplicate instance and no
    # flattened graph.
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
    assert len(serdes) == 1, "one serde instance, not one per contributing BOM"
    shared = serdes[0]["bom-ref"]
    assert sorted(dep_entry(sbom, shared)["dependsOn"]) == \
        ["cargo://a/libc", "cargo://b/libc"]
    # Both consuming recipes still reach the shared instance.
    assert dep_entry(sbom, "ref-r")["dependsOn"] == [shared]
    assert dep_entry(sbom, "ref-o")["dependsOn"] == [shared]

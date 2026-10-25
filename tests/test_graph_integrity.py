"""Core graph integrity at the renderer seam (TR-03183-2 ticket #5).

The primary component roots the dependency graph, every represented
component carries a unique bom-ref and a dependency entry, dependency
paths cross the scope-of-delivery boundary without vanishing, CycloneDX
composition data declares the truth about dependency completeness, and
inconsistent references surface as alignment findings instead of being
silently repaired.
"""

from helpers import (component_by_name, default_facts, dep, dep_entry,
                     document, finding_by_id, fragment, pkg, profile_config,
                     ref_of, render_all, render_docs, root_entry)


def test_every_component_has_a_dependency_entry_and_leaves_are_empty():
    sbom, _vex, _logs = render_docs(default_facts())

    assert root_entry(sbom)["ref"] == sbom["metadata"]["component"]["bom-ref"]
    assert dep_entry(sbom, ref_of(sbom, "busybox"))["dependsOn"] == []
    # The entry list starts with the root and lists every component once.
    assert [e["ref"] for e in sbom["dependencies"]] == [
        sbom["metadata"]["component"]["bom-ref"], "ref-busybox"]


def test_dependency_path_resolves_through_the_first_component_outside_the_scope():
    # A known dependency recipe that is not part of the delivery item does
    # not vanish: the path is followed to it, it is represented as an
    # identified component, and the graph stops there — no deeper edges are
    # claimed than the build facts support.
    sbom, _vex, _logs = render_docs(default_facts(fragments={
        "app": fragment(pkgs=[pkg("app", "1", "ref-app")],
                        dependencies=[dep("ref-app", ["busybox", "ghost"])]),
        "busybox": fragment(pkgs=[pkg("busybox", "1.36", "ref-b")]),
    }))

    ghost = component_by_name(sbom, "ghost")
    assert ghost["purl"] == "pkg:yocto/ghost"
    assert {"name": "yocto:delivery:scope", "value": "external"} in ghost["properties"]
    assert dep_entry(sbom, "ref-app")["dependsOn"] == ["ref-b", ghost["bom-ref"]]
    assert dep_entry(sbom, ghost["bom-ref"])["dependsOn"] == []


def test_one_identified_component_per_out_of_scope_recipe():
    sbom, _vex, _logs = render_docs(default_facts(fragments={
        "app": fragment(pkgs=[pkg("app", "1", "ref-app")],
                        dependencies=[dep("ref-app", ["ghost"])]),
        "tool": fragment(pkgs=[pkg("tool", "1", "ref-tool")],
                         dependencies=[dep("ref-tool", ["ghost"])]),
        "busybox": fragment(pkgs=[pkg("busybox", "1.36", "ref-b")]),
    }))

    ghosts = [c for c in sbom["components"] if c["name"] == "ghost"]
    assert len(ghosts) == 1
    assert dep_entry(sbom, "ref-app")["dependsOn"] == [ghosts[0]["bom-ref"]]
    assert dep_entry(sbom, "ref-tool")["dependsOn"] == [ghosts[0]["bom-ref"]]


def test_debug_source_records_make_static_links_dependency_edges():
    # pkgdata debug-source records written by BitBake's own do_package:
    # a debug-source prefix /usr/src/debug/<BPN>/<PV>/ of another recipe
    # identifies the recipe whose code was linked in.
    facts = default_facts(fragments={
        "app": fragment(pkgs=[pkg("app", "1", "ref-app")]),
        "libother": fragment(pkgs=[pkg("libother", "2", "ref-lib")]),
    }, image_install_recipes=["app"], debug_sources={
        "app": {"/usr/bin/app": [
            "/usr/src/debug/app/1.0-r0/src/main.c",
            "/usr/src/debug/libother/2.0-r1/libother.c",
        ]},
        "libother": {"/usr/lib/libother.so.2": [
            "/usr/src/debug/libother/2.0-r1/libother.c"]},
    })
    sbom, _vex, _logs = render_docs(facts)

    assert dep_entry(sbom, "ref-app")["dependsOn"] == ["ref-lib"]
    app = component_by_name(sbom, "app")
    assert {"name": "yocto:dependency:evidence", "value": "debugsrc"} in app["properties"]


def test_own_and_unrepresented_debug_prefixes_add_no_edges_or_evidence():
    # Own-prefix paths are the recipe compiling itself; a prefix belonging
    # to no represented recipe carries no claim. Binaries are never parsed.
    facts = default_facts(fragments={
        "app": fragment(pkgs=[pkg("app", "1", "ref-app")]),
    }, image_install_recipes=["app"], debug_sources={
        "app": {"/usr/bin/app": [
            "/usr/src/debug/app/1.0-r0/src/main.c",
            "/usr/src/debug/elsewhere/3.0-r0/foreign.c",
        ]},
    })
    sbom, _vex, _logs = render_docs(facts)

    assert dep_entry(sbom, "ref-app")["dependsOn"] == []
    app = component_by_name(sbom, "app")
    assert not [p for p in app.get("properties") or []
                if p["name"] == "yocto:dependency:evidence"]
    assert "elsewhere" not in [c["name"] for c in sbom["components"]]


def composition_for(sbom, ref):
    matches = [c for c in sbom.get("compositions") or [] if ref in c["assemblies"]]
    assert len(matches) == 1, f"expected exactly one composition for {ref}"
    return matches[0]


def test_compositions_declare_dependency_evidence_complete_from_debug_sources():
    facts = default_facts(fragments={
        "app": fragment(pkgs=[pkg("app", "1", "ref-app")],
                        dependencies=[dep("ref-app", ["libother"])]),
        "libother": fragment(pkgs=[pkg("libother", "2", "ref-lib")]),
    }, image_install_recipes=["app"], debug_sources={
        "app": {"/usr/bin/app": ["/usr/src/debug/app/1.0-r0/src/main.c"]},
        "libother": {"/usr/lib/libother.so.2":
                     ["/usr/src/debug/libother/2.0-r1/libother.c"]},
    })
    sbom, _vex, _logs = render_docs(facts)

    assert composition_for(sbom, "ref-app")["aggregate"] == "complete"
    assert composition_for(sbom, "ref-lib")["aggregate"] == "complete"


def test_unknown_dependency_evidence_is_never_declared_complete():
    # Without static-link evidence the graph structure alone says nothing
    # about completeness: the composition must say unknown, not complete.
    sbom, _vex, _logs = render_docs(default_facts())

    assert composition_for(sbom, "ref-busybox")["aggregate"] == "unknown"


def test_inhibited_debug_sources_declare_unknown_composition():
    # INHIBIT_PACKAGE_DEBUG_SPLIT leaves a package without debug sources:
    # honest unknown, never an absence-of-dependencies claim.
    facts = default_facts(debug_sources={"busybox": {}})
    sbom, _vex, _logs = render_docs(facts)

    assert composition_for(sbom, "ref-busybox")["aggregate"] == "unknown"


def test_compositions_mirror_the_dependency_entry_of_every_component():
    facts = default_facts(fragments={
        "app": fragment(pkgs=[pkg("app", "1", "ref-app")],
                        dependencies=[dep("ref-app", ["busybox", "ghost"])]),
        "busybox": fragment(pkgs=[pkg("busybox", "1.36", "ref-b")]),
    }, debug_sources={
        "app": {"/usr/bin/app": ["/usr/src/debug/app/1.0-r0/main.c"]},
        "busybox": {"/bin/busybox": ["/usr/src/debug/busybox/1.36/main.c"]},
    })
    sbom, _vex, _logs = render_docs(facts)

    ghost = component_by_name(sbom, "ghost")
    app_comp = composition_for(sbom, "ref-app")
    assert app_comp["dependencies"] == [{"ref": "ref-app",
                                         "dependsOn": ["ref-b", ghost["bom-ref"]]}]
    # The external component's own composition is honest about what the
    # build cannot see: unknown, never complete.
    assert composition_for(sbom, ghost["bom-ref"])["aggregate"] == "unknown"

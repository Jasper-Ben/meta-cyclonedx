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

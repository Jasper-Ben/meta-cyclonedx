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

"""Licence roles at the renderer seam.

Recipe LICENSE metadata is original licence evidence only. Distribution
licence rides exclusively on an explicitly identified, semantically
authoritative source, and effective licence is omitted unless the
product integration explicitly supplies it. The generator performs no
legal analysis and never converts one licence role into another.
"""

import meta_cyclonedx
from helpers import (default_facts, finding_by_id, fragment, pkg,
                     profile_config, render_all, render_docs)


def _all_licence_entries(sbom):
    holders = [sbom["metadata"]["component"], *sbom["components"]]
    return [entry for holder in holders for entry in holder.get("licenses") or []]


def test_recipe_licence_metadata_is_marked_as_original_licence_evidence():
    sbom, _vex, _logs = render_docs(default_facts(
        fragments={"busybox": fragment(pkgs=[pkg(
            "busybox", "1.36", "ref-busybox",
            licenses=[{"license": {"id": "GPL-2.0-only"}}])])},
    ))
    component = sbom["components"][0]
    assert component["licenses"] == [
        {"license": {"id": "GPL-2.0-only", "acknowledgement": "declared"}}]

def test_recipe_licence_never_surfaces_as_distribution_or_effective_licence():
    sbom, _vex, _logs = render_docs(default_facts(
        fragments={"busybox": fragment(pkgs=[pkg(
            "busybox", "1.36", "ref-busybox",
            licenses=[{"expression": "GPL-2.0-only OR MIT",
                       "acknowledgement": "declared"}])])},
    ))
    for entry in _all_licence_entries(sbom):
        assert entry.get("acknowledgement") == "declared"
    for holder in [sbom["metadata"]["component"], *sbom["components"]]:
        assert not [p for p in holder.get("properties") or []
                    if p["name"] == meta_cyclonedx.EFFECTIVE_LICENCE_PROPERTY]


def test_original_licence_evidence_is_verified_from_recipe_metadata():
    facts = default_facts(
        config=profile_config(),
        fragments={"busybox": fragment(pkgs=[pkg(
            "busybox", "1.36", "ref-busybox",
            licenses=[{"license": {"id": "MIT"}}])])},
        primary={"type": "firmware", "name": "core-image", "version": "1.0",
                 "licenses": [{"expression": "MIT",
                               "acknowledgement": "declared"}]},
    )
    docs, _logs = render_all(facts)
    finding = finding_by_id(docs["report"], "REQ-COMP-013")
    assert finding["verdict"] == "verified"
    assert finding["evidenceOrigin"] == "recipe-metadata"


def test_missing_original_licence_evidence_is_unmet_not_relabelled():
    facts = default_facts(
        config=profile_config(),
        primary={"type": "firmware", "name": "core-image", "version": "1.0",
                 "licenses": [{"expression": "MIT",
                               "acknowledgement": "declared"}]},
    )
    docs, _logs = render_all(facts)
    finding = finding_by_id(docs["report"], "REQ-COMP-013")
    assert finding["verdict"] == "unmet"
    assert finding["bomRefs"] == ["ref-busybox"]
    assert finding["evidenceOrigin"] == "recipe-metadata"

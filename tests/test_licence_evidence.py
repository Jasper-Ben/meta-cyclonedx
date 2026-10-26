"""Licence roles at the renderer seam.

Recipe LICENSE metadata is original licence evidence only. Distribution
licence rides exclusively on an explicitly identified, semantically
authoritative source, and effective licence is omitted unless the
product integration explicitly supplies it. The generator performs no
legal analysis and never converts one licence role into another.
"""

import pytest

import meta_cyclonedx
from helpers import (default_facts, finding_by_id, fragment, pkg,
                     profile_config, render_all, render_docs)


def _all_licence_entries(sbom):
    holders = [sbom["metadata"]["component"], *sbom["components"]]
    return [entry for holder in holders
            for entry in holder.get("licenses") or []]


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


def test_distribution_licence_rides_only_the_authoritative_fact_key():
    sbom, _vex, _logs = render_docs(default_facts(
        fragments={"zlib": fragment(
            distribution_licence="Zlib",
            pkgs=[pkg("zlib", "1.3", "ref-zlib",
                      licenses=[{"license": {"id": "Zlib"}}])])},
        runtime_recipes=["zlib"], image_install_recipes=["zlib"],
    ))
    assert sbom["components"][0]["licenses"] == [
        {"license": {"id": "Zlib", "acknowledgement": "declared"}},
        {"expression": "Zlib", "acknowledgement": "concluded"},
    ]


def test_distribution_licence_applies_to_the_primary_component():
    sbom, _vex, _logs = render_docs(default_facts(
        primary={"type": "firmware", "name": "core-image", "version": "1.0",
                 "distribution_licence": "MIT"},
    ))
    assert sbom["metadata"]["component"]["licenses"] == [
        {"expression": "MIT", "acknowledgement": "concluded"}]


def test_invalid_distribution_expression_is_omitted_with_a_warning():
    sbom, _vex, logs = render_docs(default_facts(
        fragments={"zlib": fragment(
            distribution_licence="MIT AND",
            pkgs=[pkg("zlib", "1.3", "ref-zlib")])},
        runtime_recipes=["zlib"], image_install_recipes=["zlib"],
    ))
    assert "licenses" not in sbom["components"][0]
    assert any("MIT AND" in message for _level, message in logs)


def distribution_finding(docs):
    return finding_by_id(docs["report"], "REQ-COMP-011")


def test_explicit_distribution_licence_is_asserted_never_verified():
    facts = default_facts(
        config=profile_config(),
        fragments={"busybox": fragment(
            distribution_licence="MIT",
            pkgs=[pkg("busybox", "1.36", "ref-busybox",
                      licenses=[{"license": {"id": "MIT"}}])])},
        primary={"type": "firmware", "name": "core-image", "version": "1.0",
                 "distribution_licence": "MIT",
                 "licenses": [{"expression": "MIT",
                               "acknowledgement": "declared"}]},
    )
    docs, _logs = render_all(facts)
    finding = distribution_finding(docs)
    assert finding["verdict"] == "asserted"
    assert finding["evidenceOrigin"] == "caller-assertion"


def test_missing_distribution_licence_is_unmet_never_relabelled():
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
    finding = distribution_finding(docs)
    assert finding["verdict"] == "unmet"
    assert finding["bomRefs"] == ["ref-busybox"]
    assert finding["evidenceOrigin"] == "caller-assertion"
    concluded = [entry for entry in
                 docs["sbom"]["components"][0].get("licenses") or []
                 if entry.get("acknowledgement") == "concluded"]
    assert concluded == []


def test_effective_licence_property_rides_only_explicit_supply():
    facts = default_facts(
        config=profile_config(),
        fragments={"busybox": fragment(
            effective_licence="MIT",
            pkgs=[pkg("busybox", "1.36", "ref-busybox")])},
        primary={"type": "firmware", "name": "core-image", "version": "1.0"},
    )
    docs, _logs = render_all(facts)
    component = docs["sbom"]["components"][0]
    properties = [p for p in component["properties"]
                  if p["name"] == meta_cyclonedx.EFFECTIVE_LICENCE_PROPERTY]
    assert properties == [{"name": "bsi:component:effectiveLicence",
                           "value": "MIT"}]
    finding = finding_by_id(docs["report"], "REQ-COMP-014")
    assert finding["verdict"] == "asserted"
    assert finding["evidenceOrigin"] == "caller-assertion"


def test_effective_licence_is_omitted_and_not_applicable_by_default():
    docs, _logs = render_all(default_facts(config=profile_config()))
    finding = finding_by_id(docs["report"], "REQ-COMP-014")
    assert finding["applicability"] == "not-applicable"
    for holder in [docs["sbom"]["metadata"]["component"],
                   *docs["sbom"]["components"]]:
        assert not [p for p in holder.get("properties") or []
                    if p["name"] == meta_cyclonedx.EFFECTIVE_LICENCE_PROPERTY]


def test_identified_boundary_components_are_exempt_from_licence_rows():
    facts = default_facts(
        config=profile_config(),
        fragments={"busybox": fragment(
            distribution_licence="MIT",
            dependencies=[{"ref": "ref-busybox", "dependsOn": ["zlib"]}],
            pkgs=[pkg("busybox", "1.36", "ref-busybox",
                      licenses=[{"license": {"id": "MIT",
                                             "acknowledgement": "declared"}}])])},
        primary={"type": "firmware", "name": "core-image", "version": "1.0",
                 "distribution_licence": "MIT",
                 "licenses": [{"expression": "MIT",
                               "acknowledgement": "declared"}]},
    )
    docs, _logs = render_all(facts)
    boundary = [c for c in docs["sbom"]["components"] if c["name"] == "zlib"]
    assert boundary
    for requirement_id in ("REQ-COMP-011", "REQ-COMP-013"):
        finding = finding_by_id(docs["report"], requirement_id)
        assert finding["verdict"] in ("verified", "asserted"), requirement_id
        assert "bomRefs" not in finding


@pytest.mark.parametrize("spec_version", ["1.6", "1.7"])
def test_strict_enforcement_passes_with_complete_licence_evidence(spec_version):
    facts = default_facts(
        config=profile_config(enforcement="strict", spec_version=spec_version),
        fragments={"busybox": fragment(
            distribution_licence="MIT",
            pkgs=[pkg("busybox", "1.36", "ref-busybox",
                      licenses=[{"license": {"id": "MIT",
                                             "acknowledgement": "declared"}}])])},
        primary={"type": "firmware", "name": "core-image", "version": "1.0",
                 "distribution_licence": "MIT",
                 "creator": "Acme GmbH <product@acme.example>",
                 "licenses": [{"expression": "MIT",
                               "acknowledgement": "declared"}]},
        sbom_creator="sbom@acme.example",
    )
    docs, _logs = render_all(facts)
    assert "failure" not in docs
    assert finding_by_id(docs["report"], "REQ-COMP-011")["verdict"] \
        == "asserted"
    assert finding_by_id(docs["report"], "REQ-COMP-013")["verdict"] \
        == "verified"
    import schema_validation
    if schema_validation.availability(spec_version) is None:
        assert schema_validation.check(docs["sbom"], spec_version) == ("valid", "")
    if spec_version == "1.6":
        component = docs["sbom"]["components"][0]
        assert component["licenses"] == [
            {"expression": "MIT", "acknowledgement": "concluded"}]
        assert component["evidence"]["licenses"] == [
            {"license": {"id": "MIT", "acknowledgement": "declared"}}]
        assert docs["sbom"]["metadata"]["component"]["evidence"]["licenses"] == [
            {"expression": "MIT", "acknowledgement": "declared"}]


def test_effective_licence_cardinality_is_enforced_per_component():
    facts = default_facts(
        config=profile_config(),
        fragments={"busybox": fragment(pkgs=[pkg(
            "busybox", "1.36", "ref-busybox",
            properties=[
                {"name": "bsi:component:effectiveLicence", "value": "MIT"},
                {"name": "bsi:component:effectiveLicence", "value": "MIT"},
            ])])},
    )
    docs, _logs = render_all(facts)
    finding = finding_by_id(docs["report"], "REQ-COMP-014")
    assert finding["verdict"] == "unmet"
    assert finding["bomRefs"] == ["ref-busybox"]


@pytest.mark.parametrize("spec_version", ["1.6", "1.7"])
@pytest.mark.parametrize("expression,normalized", [
    ("GPL-2.0-only WITH Linux-syscall-note",
     "GPL-2.0-only WITH Linux-syscall-note"),
    ("MIT&(BSD-2-Clause|Apache-2.0)",
     "MIT AND (BSD-2-Clause OR Apache-2.0)"),
    ("LicenseRef-Product", "LicenseRef-Product"),
])
def test_explicit_licence_roles_use_the_selected_spdx_vocabulary(
        spec_version, expression, normalized):
    docs, _logs = render_all(default_facts(
        config=profile_config(spec_version=spec_version),
        fragments={"busybox": fragment(
            pkgs=[pkg("busybox", "1.36", "ref-busybox")],
            distribution_licence=expression, effective_licence=expression)}))
    component = docs["sbom"]["components"][0]
    assert component["licenses"] == [
        {"expression": normalized, "acknowledgement": "concluded"}]
    assert {"name": "bsi:component:effectiveLicence",
            "value": normalized} in component["properties"]
    assert finding_by_id(docs["report"], "REQ-FMT-002")["verdict"] \
        in ("verified", "unverifiable")


@pytest.mark.parametrize("expression", [
    "Not-An-SPDX-License",
    "MIT WITH Not-An-SPDX-Exception",
    "MIT WITH BSD-2-Clause",
    "MIT WITH Linux-syscall-note WITH Linux-syscall-note",
    "(MIT OR BSD-2-Clause) WITH Linux-syscall-note",
    "MIT AND",
    "MIT OR ()",
])
def test_invalid_licence_assertions_are_not_emitted(expression):
    sbom, _vex, logs = render_docs(default_facts(
        fragments={"busybox": fragment(
            pkgs=[pkg("busybox", "1.36", "ref-busybox")],
            distribution_licence=expression, effective_licence=expression)}))
    component = sbom["components"][0]
    assert "licenses" not in component
    assert not any(p["name"] == "bsi:component:effectiveLicence"
                   for p in component.get("properties", []))
    assert any(expression in message for _level, message in logs)

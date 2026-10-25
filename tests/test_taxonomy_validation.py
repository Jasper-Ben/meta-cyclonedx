# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: Copyright (C) 2026 iris-GmbH infrared & intelligent sensors.

"""Official BSI property spelling, values and cardinality against the
pinned taxonomy v0.1.2 (ticket #11, user story 47).

The requirements matrix owns the verdicts, so the rules are observed
through the renderer seam as alignment findings and strict failures.
The registry itself is pinned in the matrix module and vendored
verbatim beside the code; a drift guard keeps the two in lockstep.
"""

import re

from pathlib import Path

import alignment_profile
from helpers import (default_facts, finding_by_id, file_entry, file_ref,
                     fragment, pkg, profile_config, render_all)


TAXONOMY_ROWS = ("REQ-TAX-001", "REQ-TAX-002", "REQ-TAX-003")


def taxonomized_facts(**overrides):
    """Default profile facts with one compliant inventoried file."""
    facts = default_facts(
        config=profile_config(),
        file_inventory={"busybox": [
            file_entry("/usr/bin/busybox", sha512="a" * 128)]},
    )
    facts.update(overrides)
    return facts


def test_registered_bsi_properties_satisfy_the_pinned_registry():
    docs, _logs = render_all(taxonomized_facts())
    for requirement in TAXONOMY_ROWS:
        finding = finding_by_id(docs["report"], requirement)
        assert finding["verdict"] == "verified", requirement
        assert finding["applicability"] == "applicable"


def test_misspelled_bsi_property_names_are_unmet():
    facts = taxonomized_facts(
        fragments={"busybox": fragment(pkgs=[pkg(
            "busybox", "1.36", "ref-busybox",
            properties=[{"name": "bsi:component:exectuable",
                         "value": "executable"}])])})
    docs, _logs = render_all(facts)
    finding = finding_by_id(docs["report"], "REQ-TAX-001")
    assert finding["verdict"] == "unmet"
    assert "bsi:component:exectuable" in finding["diagnosticMessage"]
    assert "ref-busybox" in finding["bomRefs"]


def test_properties_outside_the_registered_namespace_are_unmet():
    facts = taxonomized_facts(
        fragments={"busybox": fragment(pkgs=[pkg(
            "busybox", "1.36", "ref-busybox",
            properties=[{"name": "bsi:vendor:custom", "value": "x"}])])})
    docs, _logs = render_all(facts)
    finding = finding_by_id(docs["report"], "REQ-TAX-001")
    assert finding["verdict"] == "unmet"
    assert "bsi:vendor:custom" in finding["diagnosticMessage"]


def test_property_values_must_match_the_registry_enumerations():
    facts = taxonomized_facts(
        file_inventory={"busybox": [
            file_entry("/usr/bin/busybox", sha512="a" * 128,
                       executable="yes")]})
    docs, _logs = render_all(facts)
    finding = finding_by_id(docs["report"], "REQ-TAX-002")
    assert finding["verdict"] == "unmet"
    assert "executable" in finding["diagnosticMessage"]
    assert file_ref("busybox", "/usr/bin/busybox") in finding["bomRefs"]


def test_filename_values_must_be_bare_filenames():
    facts = taxonomized_facts(
        fragments={"busybox": fragment(pkgs=[pkg(
            "busybox", "1.36", "ref-busybox",
            properties=[{"name": "bsi:component:filename",
                         "value": "/bin/sh"}])])})
    docs, _logs = render_all(facts)
    finding = finding_by_id(docs["report"], "REQ-TAX-002")
    assert finding["verdict"] == "unmet"
    assert "ref-busybox" in finding["bomRefs"]


def test_the_classifiable_triple_must_be_complete_when_present():
    facts = taxonomized_facts(
        fragments={"busybox": fragment(pkgs=[pkg(
            "busybox", "1.36", "ref-busybox",
            properties=[{"name": "bsi:component:executable",
                         "value": "executable"}])])})
    docs, _logs = render_all(facts)
    finding = finding_by_id(docs["report"], "REQ-TAX-003")
    assert finding["verdict"] == "unmet"
    assert finding["bomRefs"] == ["ref-busybox"]


def test_duplicate_taxonomy_properties_are_unmet():
    facts = taxonomized_facts(
        fragments={"busybox": fragment(pkgs=[pkg(
            "busybox", "1.36", "ref-busybox",
            properties=[
                {"name": "bsi:component:filename", "value": "a"},
                {"name": "bsi:component:filename", "value": "b"},
            ])])})
    docs, _logs = render_all(facts)
    assert finding_by_id(docs["report"],
                         "REQ-TAX-003")["verdict"] == "unmet"


def test_effective_licence_must_not_repeat_per_component():
    facts = taxonomized_facts(
        fragments={"busybox": fragment(pkgs=[pkg(
            "busybox", "1.36", "ref-busybox",
            properties=[
                {"name": "bsi:component:effectiveLicence", "value": "MIT"},
                {"name": "bsi:component:effectiveLicence", "value": "MIT"},
            ])])})
    docs, _logs = render_all(facts)
    finding = finding_by_id(docs["report"], "REQ-TAX-003")
    assert finding["verdict"] == "unmet"
    assert finding["bomRefs"] == ["ref-busybox"]


def test_taxonomy_properties_outside_component_holders_are_unmet():
    """The registry allows these properties only in components[]/properties
    and metadata/component/properties; elsewhere they are unregistered."""
    sbom = {
        "bomFormat": "CycloneDX", "specVersion": "1.7", "version": 1,
        "metadata": {
            "component": {"type": "firmware", "name": "core-image",
                          "version": "1.0", "bom-ref": "ref-primary"},
            "properties": [{"name": "bsi:component:filename",
                            "value": "misplaced"}],
        },
        "components": [],
    }
    _baseline, findings = alignment_profile.evaluate(
        "tr03183-2.1", "1.7", sbom, {}, {})
    finding = finding_by_id({"findings": findings}, "REQ-TAX-001")
    assert finding["verdict"] == "unmet"


def test_strict_enforcement_rejects_taxonomy_violations():
    facts = taxonomized_facts(
        config=profile_config(enforcement="strict"),
        file_inventory={"busybox": [
            file_entry("/usr/bin/busybox", sha512="a" * 128,
                       structured="true")]})
    docs, _logs = render_all(facts)
    assert "failure" in docs
    assert "REQ-TAX-002" in docs["failure"]["unmetRequirementIds"]


def test_registered_names_match_the_vendored_taxonomy_document():
    """Pinned registry drift guard: the matrix constants and the vendored
    v0.1.2 registry must name exactly the same properties."""
    vendored = (Path(alignment_profile.__file__).resolve().parent
                / "data" / "bsi-property-taxonomy-0.1.2.md").read_text()
    assert "v0.1.2" in vendored
    registered_in_document = {
        line for line in _property_names_in_document(vendored)
    }
    assert registered_in_document == set(alignment_profile.BSI_TAXONOMY)


def _property_names_in_document(text):
    registry = text.split("## Contributing")[0]
    return set(re.findall(r"`(bsi:component:[A-Za-z0-9]+)`", registry))

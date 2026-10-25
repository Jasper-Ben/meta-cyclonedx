# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: Copyright (C) 2026 iris-GmbH infrared & intelligent sensors.

"""Dependency-evidence sources carry an explicit coverage state
(ticket #11, user stories 24/32).

The graph can be fed by three sources - Yocto runtime dependency
metadata, imported ecosystem BOMs and pkgdata debug-source records.
Each source reports its coverage state to the requirements matrix:
present sources verify the dependency picture, absent ones become
unverifiable rows, never silent assumptions that the graph is
complete.
"""

from helpers import (default_facts, finding_by_id, fragment, pkg,
                     profile_config, render_all)

COVERAGE_ROWS = ("REQ-DEPS-005", "REQ-DEPS-006", "REQ-DEPS-007")


def states(docs):
    return {requirement: finding_by_id(docs["report"], requirement)["verdict"]
            for requirement in COVERAGE_ROWS}


def test_every_present_source_verifies_its_coverage_lane():
    facts = default_facts(
        config=profile_config(),
        runtime_edges={"busybox": ["zlib"]},
        fragments={"busybox": fragment(
            pkgs=[pkg("busybox", "1.36", "ref-busybox")],
            extra_components=[pkg("serde", "1.0", "cargo-serde",
                                  purl="pkg:cargo/serde@1.0")],
            extra_dependencies=[{"ref": "cargo-serde", "dependsOn": []}]),
                   "zlib": fragment(
            pkgs=[pkg("zlib", "1.3", "ref-zlib")])},
        runtime_recipes=["busybox", "zlib"],
        debug_sources={"zlib": {"files": ["zlib.c"]}},
    )
    docs, _logs = render_all(facts)
    assert not docs.get("failure")
    verdicts = states(docs)
    assert verdicts["REQ-DEPS-006"] == "verified"
    assert verdicts["REQ-DEPS-007"] == "verified"
    assert verdicts["REQ-DEPS-005"] == "unverifiable"


def test_runtime_metadata_source_is_reported_per_build():
    observed = default_facts(config=profile_config(),
                             runtime_edges={"busybox": ["zlib"]})
    docs, _logs = render_all(observed)
    finding = finding_by_id(docs["report"], "REQ-DEPS-006")
    assert finding["verdict"] == "verified"

    absent = default_facts(config=profile_config())
    docs, _logs = render_all(absent)
    finding = finding_by_id(docs["report"], "REQ-DEPS-006")
    assert finding["verdict"] == "unverifiable"
    assert finding["evidenceOrigin"] == "recipe-metadata"
    # Unverifiable coverage never blocks strict enforcement.
    strict = default_facts(config=profile_config(enforcement="strict"),
                           runtime_edges={"busybox": ["zlib"]})
    docs, _logs = render_all(strict)
    failure = docs.get("failure")
    assert not failure or "REQ-DEPS-006" not in failure.get(
        "unmetRequirementIds", ())


def test_imported_ecosystem_graphs_report_used_or_unavailable():
    facts = default_facts(
        config=profile_config(),
        fragments={"busybox": fragment(
            pkgs=[pkg("busybox", "1.36", "ref-busybox")],
            extra_components=[pkg("serde", "1.0", "cargo-serde",
                                  purl="pkg:cargo/serde@1.0")],
            extra_dependencies=[{"ref": "cargo-serde", "dependsOn": []}])},
    )
    docs, _logs = render_all(facts)
    assert finding_by_id(
        docs["report"], "REQ-DEPS-007")["verdict"] == "verified"

    facts = default_facts(config=profile_config())
    docs, _logs = render_all(facts)
    finding = finding_by_id(docs["report"], "REQ-DEPS-007")
    assert finding["verdict"] == "unverifiable"
    assert finding["evidenceOrigin"] == "upstream-metadata"


def test_defective_imports_report_no_coverage_and_point_at_the_merge_finding():
    facts = default_facts(
        config=profile_config(),
        fragments={"busybox": fragment(
            pkgs=[pkg("busybox", "1.36", "ref-busybox")],
            extra_bom_errors=[{"file": "broken.cdx.json",
                               "error": "unparseable"}])},
    )
    docs, _logs = render_all(facts)
    finding = finding_by_id(docs["report"], "REQ-DEPS-007")
    assert finding["verdict"] == "unverifiable"
    assert "defect" in finding["diagnosticMessage"].lower()
    # The defect itself is judged by the composition row.
    assert finding_by_id(
        docs["report"], "REQ-MERGE-001")["verdict"] == "unmet"


def test_debug_source_coverage_is_stateful_not_absent_by_default():
    complete = default_facts(
        config=profile_config(),
        fragments={"busybox": fragment(
            pkgs=[pkg("busybox", "1.36", "ref-busybox")])},
        debug_sources={"busybox": {"files": ["busybox.c"]}},
    )
    docs, _logs = render_all(complete)
    assert finding_by_id(
        docs["report"], "REQ-DEPS-005")["verdict"] == "verified"

    partial = default_facts(
        config=profile_config(),
        fragments={"busybox": fragment(
            pkgs=[pkg("busybox", "1.36", "ref-busybox")]),
            "zlib": fragment(pkgs=[pkg("zlib", "1.3", "ref-zlib")])},
        runtime_recipes=["busybox", "zlib"],
        debug_sources={"busybox": {"files": ["busybox.c"]}},
    )
    docs, _logs = render_all(partial)

    assert finding_by_id(
        docs["report"], "REQ-DEPS-005")["verdict"] == "unverifiable"

    absent = default_facts(config=profile_config())
    docs, _logs = render_all(absent)
    finding = finding_by_id(docs["report"], "REQ-DEPS-005")
    assert finding["verdict"] == "unverifiable"
    assert finding["evidenceOrigin"] == "recipe-metadata"

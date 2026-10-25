"""The root-filesystem file inventory at the renderer seam.

With the alignment profile selected, every delivered executable and
archive arrives as a normalized artifact fact and must be composed into
an exact file component: delivered filename, SHA-512 artifact identity,
the pinned BSI file properties, and a traceable owning relationship -
without ever copying the owning logical component's identity. Ordinary
(non-profile) output stays a logical-component-only document (ADR-0005),
and artifact inspection never analyzes binary contents (ADR-0002).
"""

import copy
import re

import meta_cyclonedx
from helpers import (affect_refs, default_facts, dep_entry,
                     file_components, file_entry, file_component, file_ref,
                     finding_by_id, fragment, pkg, profile_config, ref_of,
                     render_all, render_docs, vuln, vuln_by_id)


def test_ordinary_output_omits_the_file_inventory_by_default():
    # ADR-0005: the mandatory file inventory belongs to the alignment
    # profile; without a selected profile the document is unchanged.
    facts = default_facts(
        file_inventory={"busybox": [file_entry("/bin/sh", sha512="a" * 128)]},
    )
    with_inventory, _vex, _logs = render_docs(copy.deepcopy(facts))
    without, _vex, _logs = render_docs(facts)
    assert file_components(with_inventory) == []
    assert with_inventory["components"] == without["components"]
    assert (
        [sorted(entry["dependsOn"]) for entry in with_inventory["dependencies"]]
        == [sorted(entry["dependsOn"]) for entry in without["dependencies"]]
    )


def test_file_components_participate_in_the_dependency_graph_of_their_owner():
    facts = default_facts(
        config=profile_config(),
        file_inventory={"busybox": [
            file_entry("/bin/sh", sha512="a" * 128),
            file_entry("/usr/lib/libutil.so.1", sha512="c" * 128),
        ]},
    )
    sbom, _vex, _logs = render_docs(facts)

    owner = dep_entry(sbom, ref_of(sbom, "busybox"))
    assert owner["dependsOn"] == [file_ref("busybox", "/usr/lib/libutil.so.1"),
                                  file_ref("busybox", "/bin/sh")]
    # The product root owns files through the delivering component only.
    assert file_ref("busybox", "/bin/sh") not in sbom["dependencies"][0]["dependsOn"]
    # Files are graph leaves: an entry exists with an empty list.
    for path in ("/bin/sh", "/usr/lib/libutil.so.1"):
        assert dep_entry(sbom, file_ref("busybox", path))["dependsOn"] == []
    # A file's own dependency evidence is unknown by design: no binary
    # analysis is performed (ADR-0002), never a fabricated "complete".
    compositions = {ref: composition["aggregate"]
                    for composition in sbom["compositions"]
                    for ref in composition["assemblies"]}
    assert compositions[file_ref("busybox", "/bin/sh")] == "unknown"


def test_delivered_files_become_file_components_with_artifact_identity():
    facts = default_facts(
        config=profile_config(),
        file_inventory={"busybox": [
            file_entry("/bin/sh", sha512="a" * 128),
            file_entry("/var/pkg/app.rpm", sha512="b" * 128,
                       executable="non-executable", archive="archive",
                       structured="structured"),
        ]},
    )
    sbom, _vex, _logs = render_docs(facts)

    sh = file_component(sbom, "busybox", "/bin/sh")
    assert sh["name"] == "sh"
    assert sh["hashes"] == [{"alg": "SHA-512", "content": "a" * 128}]
    assert sh["properties"] == [
        {"name": "bsi:component:filename", "value": "sh"},
        {"name": "bsi:component:executable", "value": "executable"},
        {"name": "bsi:component:archive", "value": "no archive"},
        {"name": "bsi:component:structured", "value": "unstructured"},
    ]

    rpm = file_component(sbom, "busybox", "/var/pkg/app.rpm")
    assert rpm["name"] == "app.rpm"
    assert rpm["properties"] == [
        {"name": "bsi:component:filename", "value": "app.rpm"},
        {"name": "bsi:component:executable", "value": "non-executable"},
        {"name": "bsi:component:archive", "value": "archive"},
        {"name": "bsi:component:structured", "value": "structured"},
    ]


def test_the_file_inventory_is_path_ordered_and_rerun_stable():
    entries = [file_entry(path, sha512=str(index) * 128)
               for index, path in enumerate(
                   ["/usr/sbin/zdaemon", "/etc/weekly.job", "/bin/ash"])]
    facts_a = default_facts(config=profile_config(),
                            file_inventory={"busybox": list(reversed(entries))})
    facts_b = default_facts(config=profile_config(),
                            file_inventory={"busybox": list(entries)})
    docs_a, _logs_a = render_all(facts_a)
    docs_b, _logs_b = render_all(facts_b)

    expected_refs = [file_ref("busybox", "/bin/ash"),
                     file_ref("busybox", "/etc/weekly.job"),
                     file_ref("busybox", "/usr/sbin/zdaemon")]
    for docs in (docs_a, docs_b):
        assert [component["bom-ref"]
                for component in file_components(docs["sbom"])] == expected_refs
        assert _stable_refs(docs["sbom"]) == _stable_refs(docs_b["sbom"])
    assert meta_cyclonedx.serialize_report(docs_a["report"]) == \
        meta_cyclonedx.serialize_report(docs_b["report"])


def _stable_refs(sbom):
    """Dependency-entry refs with the documented per-render uuids removed."""
    return [entry["ref"] for entry in sbom["dependencies"]
            if not re.fullmatch(r"[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}",
                                entry["ref"])]


def test_unreadable_mandatory_artifact_produces_an_alignment_finding():
    facts = default_facts(
        config=profile_config(),
        file_inventory={"busybox": [
            file_entry("/bin/sh", sha512="a" * 128),
            file_entry("/usr/bin/broken", error="unreadable"),
        ]},
    )
    docs, _logs = render_all(facts)

    finding = finding_by_id(docs["report"], "REQ-FILE-002")
    assert finding["verdict"] == "unmet"
    assert finding["applicability"] == "applicable"
    assert finding["bomRefs"] == [file_ref("busybox", "/usr/bin/broken")]
    assert "/usr/bin/broken" in finding["diagnosticMessage"]
    assert "unreadable" in finding["diagnosticMessage"]
    # Report enforcement never drops the rest of the output.
    assert docs["sbom"]["bomFormat"] == "CycloneDX"
    assert [component["bom-ref"]
            for component in file_components(docs["sbom"])] == \
        [file_ref("busybox", "/bin/sh")]
    assert finding_by_id(docs["report"], "REQ-FILE-001")["verdict"] == "verified"
    assert finding_by_id(docs["report"], "REQ-FILE-003")["verdict"] == "verified"


def test_strict_enforcement_fails_on_defective_mandatory_artifacts():
    facts = default_facts(
        config=profile_config(enforcement="strict"),
        file_inventory={"busybox": [
            file_entry("/bin/sh", sha512="a" * 128),
            file_entry("/var/db/ghost.pkg", error="missing"),
            file_entry("/usr/bin/truncated.zip", error="ambiguous-classification"),
        ]},
    )
    docs, _logs = render_all(facts)

    assert "sbom" not in docs
    failure = docs["failure"]
    assert "REQ-FILE-002" in failure["unmetRequirementIds"]
    finding = finding_by_id(failure["report"], "REQ-FILE-002")
    assert finding["bomRefs"] == [file_ref("busybox", "/usr/bin/truncated.zip"),
                                  file_ref("busybox", "/var/db/ghost.pkg")]
    assert "missing" in finding["diagnosticMessage"]
    assert "ambiguous-classification" in finding["diagnosticMessage"]
    # The usable file still reached the report evaluation; nothing vanished.
    assert finding_by_id(failure["report"],
                         "REQ-FILE-001")["verdict"] == "verified"


def test_file_inventory_requirements_are_not_applicable_without_inventory():
    docs, _logs = render_all(default_facts(config=profile_config()))
    for requirement_id in ("REQ-FILE-001", "REQ-FILE-002", "REQ-FILE-003"):
        finding = finding_by_id(docs["report"], requirement_id)
        assert finding["applicability"] == "not-applicable", requirement_id
        assert finding["verdict"] == "unverifiable", requirement_id
    # Without inventory data the file rows add nothing to strict output.
    strict, _logs = render_all(default_facts(
        config=profile_config(enforcement="strict")))
    report = strict.get("report") or strict.get("failure", {}).get("report")
    assert all(finding["applicability"] == "not-applicable"
               for finding in report["findings"]
               if finding["requirementId"].startswith("REQ-FILE"))


def test_file_components_never_borrow_logical_component_identity_evidence():
    # ADR-0006: the file component carries artifact identity only. The
    # owning logical component keeps purl, CPE, licences, creator and the
    # vulnerability findings; nothing is copied onto the artifact (and
    # requirements apply per component category, never indiscriminately).
    facts = default_facts(
        config=profile_config(),
        fragments={"busybox": fragment(
            pkgs=[pkg("busybox", "1.36", "ref-busybox")],
            cves=[vuln("CVE-2026-0001", "ref-busybox")],
        )},
        file_inventory={"busybox": [file_entry("/bin/sh", sha512="a" * 128)]},
    )
    docs, _logs = render_all(facts)
    sbom, vex = docs["sbom"], docs["vex"]
    sh = file_component(sbom, "busybox", "/bin/sh")

    assert set(sh) == {"type", "name", "version", "bom-ref", "hashes",
                       "properties"}
    statement = vuln_by_id(vex, "CVE-2026-0001")
    assert not any(sh["bom-ref"] in ref for ref in affect_refs(statement))

    for requirement_id in ("REQ-COMP-010", "REQ-COMP-011", "REQ-COMP-013"):
        finding = finding_by_id(docs["report"], requirement_id)
        assert sh["bom-ref"] not in finding.get("bomRefs", []), requirement_id
    assert file_components(sbom)[0]["bom-ref"] == sh["bom-ref"]


def test_file_components_without_artifact_facts_are_unmet():
    # A file component with no delivered-file fact behind it is an
    # unverified claim; the fidelity row names it (REQ-FILE-001).
    ghost = pkg("ghost.bin", "1.0", "ref-ghost", type="file",
                hashes=[{"alg": "SHA-512", "content": "f" * 128}],
                properties=[
                    {"name": "bsi:component:filename", "value": "ghost.bin"},
                    {"name": "bsi:component:executable", "value": "executable"},
                    {"name": "bsi:component:archive", "value": "no archive"},
                    {"name": "bsi:component:structured", "value": "unstructured"},
                ])
    facts = default_facts(
        config=profile_config(),
        fragments={"busybox": fragment(
            pkgs=[pkg("busybox", "1.36", "ref-busybox"), ghost])},
        file_inventory={"busybox": [file_entry("/bin/sh", sha512="a" * 128)]},
    )
    docs, _logs = render_all(facts)
    finding = finding_by_id(docs["report"], "REQ-FILE-001")
    assert finding["verdict"] == "unmet"
    assert "ref-ghost" in finding["bomRefs"]
    assert file_ref("busybox", "/bin/sh") not in finding["bomRefs"]


def test_file_versions_follow_the_delivering_recipe_identity():
    # Convention: an inventoried file carries the version of the logical
    # component (creator-assigned identity) of the recipe that delivered
    # it; artifact facts carry no separate version of their own.
    facts = default_facts(
        config=profile_config(),
        fragments={"busybox": fragment(
            pkgs=[pkg("busybox", "1.42.1", "ref-busybox")])},
        file_inventory={"busybox": [file_entry("/bin/sh", sha512="a" * 128)]},
    )
    sbom, _vex, _logs = render_docs(facts)
    assert file_component(sbom, "busybox", "/bin/sh")["version"] == "1.42.1"


def test_files_of_recipes_without_a_logical_component_have_no_owner():
    # Inventory facts for an unrepresented recipe cannot form an owning
    # relationship: the file is still published and stays a finding.
    facts = default_facts(
        config=profile_config(),
        file_inventory={"ghostly": [file_entry("/usr/bin/phantom",
                                               sha512="a" * 128)]},
    )
    docs, _logs = render_all(facts)
    sbom = docs["sbom"]
    phantom = file_component(sbom, "ghostly", "/usr/bin/phantom")
    assert phantom["version"] == "unknown"
    finding = finding_by_id(docs["report"], "REQ-FILE-003")
    assert finding["verdict"] == "unmet"
    assert finding["bomRefs"] == [file_ref("ghostly", "/usr/bin/phantom")]
    assert finding_by_id(docs["report"], "REQ-FILE-001")["verdict"] == "verified"

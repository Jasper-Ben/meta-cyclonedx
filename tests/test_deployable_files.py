"""The primary deployable artifact and selected additional files.

Ticket #10 extends the ticket #9 file-inventory path beyond the
root-filesystem package evidence: the image's own deployable artifact is
mandatory inventory (TR-03183-2 v2.1.0 §5.2.2) even though no package
manifest names it, and the product integration can explicitly select
further delivered payloads (kernel, bootloader, firmware, TEE,
initramfs, embedded images) without broadening the default inventory to
every delivered data file (ADR-0005).

Evidence arrives through the same file_inventory facts key under the
recipe-less owner (""): those entries are owned by the primary
component and use the identical classification, SHA-512 identity, BSI
property and graph rules as root-filesystem file components.
"""
from helpers import (default_facts, dep_entry, file_component,
                     file_components, file_ref, finding_by_id,
                     profile_config, render_all, render_docs, root_entry)


def deploy_entry(path, source, sha512=None, executable="non-executable",
                 archive="no archive", structured="unstructured",
                 error=None):
    """One deploy-directory artifact fact (recipe-less, primary-owned)."""
    entry = {"path": path, "source": source}
    if error:
        entry["error"] = error
    else:
        entry["sha512"] = sha512
        entry["executable"] = executable
        entry["archive"] = archive
        entry["structured"] = structured
    return entry


PRIMARY = "core-image-minimal-qemux86-64.ext4"


def test_primary_deployable_becomes_a_file_component_owned_by_the_product():
    # TR-03183-2 §5.2.2 makes the primary deployable artifact mandatory
    # inventory even though no root-filesystem package manifest covers it.
    facts = default_facts(
        config=profile_config(),
        file_inventory={"": [deploy_entry(
            PRIMARY, "deployable", sha512="f" * 128,
            archive="archive", structured="structured")]},
    )
    sbom, _vex, _logs = render_docs(facts)

    artifact = file_component(sbom, "", PRIMARY)
    assert artifact["type"] == "file"
    assert artifact["name"] == PRIMARY
    # Recipe-less artifacts carry the primary component's version.
    assert artifact["version"] == "1.0"
    assert artifact["hashes"] == [{"alg": "SHA-512", "content": "f" * 128}]
    assert {p["name"]: p["value"] for p in artifact["properties"]} == {
        "bsi:component:filename": PRIMARY,
        "bsi:component:executable": "non-executable",
        "bsi:component:archive": "archive",
        "bsi:component:structured": "structured",
    }
    # The primary component owns the artifact: it hangs off the graph root.
    assert artifact["bom-ref"] in root_entry(sbom)["dependsOn"]
    assert dep_entry(sbom, artifact["bom-ref"])["dependsOn"] == []


def test_deployable_coverage_is_verified_by_primary_artifact_evidence():
    docs, _logs = render_all(default_facts(
        config=profile_config(),
        file_inventory={"": [deploy_entry(PRIMARY, "deployable",
                                          sha512="f" * 128)]},
    ))
    finding = finding_by_id(docs["report"], "REQ-FILE-004")
    assert finding["verdict"] == "verified"
    assert finding["applicability"] == "applicable"
    # Nothing was explicitly selected: that row does not apply.
    assert finding_by_id(docs["report"], "REQ-FILE-005")[
        "applicability"] == "not-applicable"


def test_explicitly_selected_files_are_verified_and_findings_stay_reported():
    docs, _logs = render_all(default_facts(
        config=profile_config(),
        file_inventory={"": [
            deploy_entry(PRIMARY, "deployable", sha512="f" * 128),
            deploy_entry("bzImage-qemux86-64.bin", "selected",
                         sha512="a" * 128, executable="executable"),
            deploy_entry("firmware/*.missing", "selected", error="missing"),
        ]},
    ))
    finding = finding_by_id(docs["report"], "REQ-FILE-005")
    assert finding["verdict"] == "unmet"
    assert file_ref("", "firmware/*.missing") in finding["bomRefs"]
    assert finding_by_id(docs["report"], "REQ-FILE-002")["verdict"] == "unmet"
    assert any("firmware/*.missing" in message and "missing" in message
               for _level, message in _logs)


def test_missing_primary_deployable_is_an_unmet_requirement_not_a_gap():
    # The primary deployable artifact is mandatory under the profile:
    # absent evidence is an explicit finding, never a silent omission.
    docs, _logs = render_all(default_facts(
        config=profile_config(),
        file_inventory={"": [deploy_entry(PRIMARY, "deployable",
                                          error="missing")]},
    ))
    finding = finding_by_id(docs["report"], "REQ-FILE-004")
    assert finding["verdict"] == "unmet"
    assert finding["bomRefs"] == [file_ref("", PRIMARY)]


def test_strict_enforcement_fails_on_defective_deployable_evidence():
    docs, _logs = render_all(default_facts(
        config=profile_config(enforcement="strict"),
        file_inventory={"": [
            deploy_entry("bl31.bin", "selected", error="unreadable"),
        ]},
    ))
    assert "failure" in docs
    assert "REQ-FILE-005" in docs["failure"]["unmetRequirementIds"]
    assert "REQ-FILE-002" in docs["failure"]["unmetRequirementIds"]


def test_one_artifact_instance_never_becomes_two_file_components():
    # The same deployed artifact discovered through several evidences -
    # primary-deployable and explicit-selection here - is ONE artifact
    # instance: the artifact ref (recipe namespace + delivered path) is
    # the dedup key, keeping a single component, a single graph edge and
    # a single composition declaration.
    artifact = deploy_entry("initramfs.cpio.gz", "deployable",
                            sha512="d" * 128, archive="archive",
                            structured="structured")
    selected = deploy_entry("initramfs.cpio.gz", "selected",
                            sha512="d" * 128, archive="archive",
                            structured="structured")
    facts = default_facts(config=profile_config(),
                          file_inventory={"": [artifact, selected]})
    docs, _logs = render_all(facts)
    sbom = docs["sbom"]

    refs = [component["bom-ref"] for component in file_components(sbom)]
    assert refs.count(file_ref("", "initramfs.cpio.gz")) == 1
    root = root_entry(sbom)
    assert root["dependsOn"].count(file_ref("", "initramfs.cpio.gz")) == 1
    assert len([entry for entry in sbom["compositions"]
                if file_ref("", "initramfs.cpio.gz")
                in entry["assemblies"]]) == 1
    assert finding_by_id(docs["report"], "REQ-FILE-004")["verdict"] == "verified"
    assert finding_by_id(docs["report"], "REQ-FILE-005")["verdict"] == "verified"


def test_identical_content_at_different_delivered_paths_stays_separate():
    # Artifact identity is filename plus hash: the same bytes delivered
    # at two different paths are two artifact instances, exactly as
    # ticket #9 keeps busybox aliases separate inside the rootfs.
    facts = default_facts(
        config=profile_config(),
        file_inventory={
            "": [deploy_entry("bzImage-qemux86-64.bin", "selected",
                              sha512="k" * 128)],
            "linux-yocto": [{"path": "/boot/vmlinuz", "sha512": "k" * 128,
                             "executable": "executable",
                             "archive": "no archive",
                             "structured": "unstructured"}],
        },
    )
    sbom, _vex, _logs = render_docs(facts)
    refs = {component["bom-ref"] for component in file_components(sbom)}
    assert file_ref("", "bzImage-qemux86-64.bin") in refs
    assert file_ref("linux-yocto", "/boot/vmlinuz") in refs


def test_the_deploy_inventory_is_rerun_stable():
    import meta_cyclonedx

    entries = [deploy_entry(PRIMARY, "deployable", sha512="f" * 128),
               deploy_entry("bzImage-qemux86-64.bin", "selected",
                            sha512="b" * 128, executable="executable"),
               deploy_entry("firmware/tee.bin", "selected", sha512="t" * 128)]
    facts_a = default_facts(config=profile_config(),
                            file_inventory={"": list(reversed(entries))})
    facts_b = default_facts(config=profile_config(),
                            file_inventory={"": list(entries)})
    docs_a, _logs_a = render_all(facts_a)
    docs_b, _logs_b = render_all(facts_b)

    def artifacts(doc):
        return [(c["name"], c["bom-ref"], c["hashes"][0]["content"])
                for c in file_components(doc["sbom"])]
    assert artifacts(docs_a) == artifacts(docs_b)
    assert docs_a["sbom"]["components"] == docs_b["sbom"]["components"]
    assert (meta_cyclonedx.serialize_report(docs_a["report"])
            == meta_cyclonedx.serialize_report(docs_b["report"]))


def test_deploy_evidence_never_widens_output_without_a_profile():
    # ADR-0005: the whole file inventory belongs to the alignment
    # profile. Without one, deployable and selected evidence has no
    # effect: the document is the ordinary logical-component SBOM.
    import copy

    with_inventory = default_facts(
        file_inventory={"": [deploy_entry(PRIMARY, "deployable",
                                          sha512="f" * 128)]},
    )
    sbom, _vex, _logs = render_docs(copy.deepcopy(with_inventory))
    assert file_components(sbom) == []
    sbom, _vex, _logs = render_docs(with_inventory)
    assert file_components(sbom) == []


def test_deploy_requirements_do_not_apply_without_deploy_evidence():
    # A profile-selected build with only root-filesystem evidence (or
    # none) keeps ticket #9 output: the new rows are not-applicable and
    # no file component appears.
    docs, _logs = render_all(default_facts(config=profile_config()))
    assert file_components(docs["sbom"]) == []
    for requirement_id in ("REQ-FILE-004", "REQ-FILE-005"):
        finding = finding_by_id(docs["report"], requirement_id)
        assert finding["applicability"] == "not-applicable"
        assert finding["verdict"] == "unverifiable"


# The adapter-side selection grammar, tested as the pure helper the
# BitBake adapter calls with an enumeration of the deploy directory:
# plan_deploy_file_selection(patterns, deploy_files, primary_candidates).

def files(*specs):
    """Deploy-directory enumeration: ("path", "file"|"symlink", target)."""
    result = {}
    for spec in specs:
        path, kind, target = spec if len(spec) == 3 else (spec[0], spec[1], None)
        result[path] = {"kind": kind, "target": target}
    return result


def plan(patterns, deploy, primaries=()):
    import meta_cyclonedx
    return meta_cyclonedx.plan_deploy_file_selection(patterns, deploy,
                                                     primaries)


def test_the_primary_artifact_is_planned_even_without_selections():
    deploy = files(("core-image-minimal-qemux86-64.ext4", "symlink",
                    "core-image-minimal-qemux86-64-20261013T120000.ext4"),
                   ("core-image-minimal-qemux86-64-20261013T120000.ext4",
                    "file"),
                   ("bzImage-qemux86-64.bin", "file"))
    assert plan("", deploy, ("core-image-minimal-qemux86-64.ext4",)) == [
        {"path": "core-image-minimal-qemux86-64.ext4",
         "source": "deployable"},
    ]


def test_absent_primary_candidate_stays_a_missing_finding():
    deploy = files(("core-image-minimal.manifest", "file"))
    assert plan("", deploy, ("core-image-minimal-qemux86-64.wic",)) == [
        {"path": "core-image-minimal-qemux86-64.wic",
         "source": "deployable", "error": "missing"},
    ]


def test_patterns_select_deployed_payloads_by_glob():
    deploy = files(("bzImage-qemux86-64.bin", "file"),
                   ("core-image-minimal-qemux86-64.ext4", "file"),
                   ("firmware/qualcomm/adx.bin", "file"),
                   ("licenses/license.manifest", "file"))
    selected = plan("bzImage* firmware/*.bin", deploy)
    assert selected == [
        {"path": "bzImage-qemux86-64.bin", "source": "selected"},
        {"path": "firmware/qualcomm/adx.bin", "source": "selected"},
    ]


def test_unmatched_pattern_produces_a_missing_entry_not_silence():
    deploy = files(("bzImage-qemux86-64.bin", "file"))
    assert plan("bzImage* tee/bl31.elf", deploy) == [
        {"path": "bzImage-qemux86-64.bin", "source": "selected"},
        {"path": "tee/bl31.elf", "source": "selected", "error": "missing"},
    ]


def test_the_stable_link_name_wins_over_its_timestamped_target():
    # Deterministic reruns: a symlink records the artifact under its
    # stable name; the timestamped target is the same instance.
    deploy = files(("core-image-minimal-qemux86-64-20261013T120000.ext4",
                    "file"),
                   ("core-image-minimal-qemux86-64.ext4", "symlink",
                    "core-image-minimal-qemux86-64-20261013T120000.ext4"))
    assert plan("core-image-minimal-qemux86-64*.ext4", deploy) == [
        {"path": "core-image-minimal-qemux86-64.ext4", "source": "selected"},
    ]


def test_selection_never_duplicates_the_primary_artifact():
    primary = "core-image-minimal-qemux86-64.ext4"
    timestamped = "core-image-minimal-qemux86-64-20261013T120000.ext4"
    deploy = files((timestamped, "file"),
                   (primary, "symlink", timestamped))
    planned = plan("*.ext4", deploy, (primary,))
    assert planned == [
        {"path": primary, "source": "deployable"},
    ]


def test_broken_symlink_evidence_is_unreadable():
    deploy = files(("u-boot.bin", "symlink", None))
    assert plan("u-boot.bin", deploy) == [
        {"path": "u-boot.bin", "source": "selected", "error": "unreadable"},
    ]


def test_absolute_patterns_are_deploy_dir_anchored():
    deploy = files(("images/initramfs.cpio.gz", "file"))
    assert plan("/images/initramfs*", deploy) == [
        {"path": "images/initramfs.cpio.gz", "source": "selected"},
    ]


# The adapter's deploy-directory collector, unit-tested by exec'ing
# just that function from the class under a stubbed BitBake
# environment (the full adapter seam is the BitBake acceptance build).

def run_collect_deploy_files(tmp_path, variables):
    import ast
    import os
    import types

    import meta_cyclonedx

    source = os.path.join(os.path.dirname(meta_cyclonedx.__file__),
                          "..", "classes", "cyclonedx-export.bbclass")
    # A .bbclass mixes BitBake and Python syntax, so the whole file
    # cannot be parsed as Python: take exactly this function's lines,
    # stopping at the next top-level statement.
    with open(source) as class_file:
        lines = class_file.read().splitlines(keepends=True)
    body = []
    wanted = "def collect_deploy_files("
    for index, line in enumerate(lines):
        if line.startswith(wanted):
            body.append(line)
            for following in lines[index + 1:]:
                if following.strip() and not following[0].isspace():
                    break
                body.append(following)
            break
    function = next(node for node in ast.parse("".join(body)).body
                    if isinstance(node, ast.FunctionDef))
    module = types.ModuleType("adapter_under_test")
    events = []

    class _BB:
        @staticmethod
        def warn(message):
            events.append(("warn", str(message)))

        @staticmethod
        def note(message):
            events.append(("note", str(message)))

    vars = {"IMGDEPLOYDIR": str(tmp_path), **variables}

    class _Data:
        def getVar(self, name):
            return vars.get(name, "")

        def getVarFlag(self, flag, name):
            return ""

    module.bb = _BB
    module._cyclonedx_renderer = lambda d: meta_cyclonedx
    exec(compile(ast.Module(body=[function], type_ignores=[]), source,
                 "exec"), module.__dict__)
    return module.collect_deploy_files(_Data()), events


def test_the_adapter_inventories_the_final_deploy_directory(tmp_path):
    import hashlib

    stamped = "core-image-minimal-qemux86-64-20261013T120000.ext4"
    image_bytes = b"rootfs-image-bytes"
    (tmp_path / stamped).write_bytes(image_bytes)
    (tmp_path / "core-image-minimal-qemux86-64.ext4").symlink_to(stamped)
    (tmp_path / "bzImage-qemux86-64.bin").write_bytes(b"\x7fELF" + b"\x00" * 96)
    (tmp_path / "core-image-minimal.cyclonedx.bom.json").write_text("{}")
    entries, events = run_collect_deploy_files(
        tmp_path,
        {"IMAGE_LINK_NAME": "core-image-minimal-qemux86-64",
         "IMAGE_FSTYPES": "ext4",
         "CYCLONEDX_ADDITIONAL_FILES": "bzImage* tee/bl31.elf",
         "CYCLONEDX_EXPORT_DIR": str(tmp_path),
         "CYCLONEDX_EXPORT_SBOM": "core-image-minimal.cyclonedx.bom.json"},
    )
    assert entries == [
        {"path": "core-image-minimal-qemux86-64.ext4",
         "source": "deployable", "executable": "non-executable",
         "archive": "no archive", "structured": "unstructured",
         "sha512": hashlib.sha512(image_bytes).hexdigest()},
        {"path": "bzImage-qemux86-64.bin", "source": "selected",
         "executable": "executable", "archive": "no archive",
         "structured": "unstructured",
         "sha512": hashlib.sha512(b"\x7fELF" + b"\x00" * 96).hexdigest()},
        {"path": "tee/bl31.elf", "source": "selected", "error": "missing"},
    ]
    assert not any("bom.json" in message for _level, message in events)

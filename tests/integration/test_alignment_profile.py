# SPDX-License-Identifier: MIT
"""The alignment-profile acceptance seam: one real image, public config.

One minimal completed ``core-image-minimal`` build, configured only
through the documented public surface (the recorder's ``extra_env``
channel forwarding the ``CYCLONEDX_*`` variables declared in kas.yml —
never a tracked-file edit), proves what the thin BitBake adapter owns:
metadata handoff into the renderer, task ordering (the final generation
and the artifact hashing run in ``do_deploy_cyclonedx``, after image
assembly), mandatory delivered-file discovery and SHA-512 hashing, and
deployment of all three evidence documents to the documented output
location. The renderer's full behavioral matrix lives in the unit tier;
this seam spot-checks representative identity, dependency, file,
creator, licence and report outcomes instead of repeating it.

Scenario runs (all re-invocations of the one shared workspace):

- ``alignment-report`` — report enforcement publishes SBOM, VEX and
  alignment report despite the baseline's honest gaps.
- ``alignment-report-again`` — an identical re-invocation deploys
  byte-identical artifacts (the determinism claim, cache-served).
- ``alignment-violation-report`` / ``alignment-strict`` — one controlled
  machine-detectable violation (a creator without a machine-actionable
  contact, REQ-COMP-012) through both enforcements: report publishes it,
  strict rejects the build at the documented task surface without
  deploying anything new.
- ``alignment-reverted`` — the teardown invocation without profile
  variables restores the baseline deployment byte-for-byte, and the
  deployed report files the profile runs introduced are removed: an
  sstate install never deletes, and the rest of the matrix compares
  whole deploy-directory checksum maps (R2).

Tests run in definition order; the revert is also guaranteed in fixture
teardown. This scenario is development-branch evidence: any other
supported branch must run an equivalent scenario there to support the
profile (the branch-support guide is ticket #13's deliverable).
"""

import hashlib
import re
from types import SimpleNamespace

import pytest

from tests.integration import deploy_compare, kas_env

pytestmark = pytest.mark.integration

#: A BitBake per-task failure line for one of the CycloneDX generation
#: tasks named in README's integration section. Under strict enforcement
#: the rejection fires in the first generation that reran: inside
#: do_rootfs for a fresh image assembly, or do_deploy_cyclonedx when the
#: rootfs phase was cache-served — both are the documented task surface;
#: the claim is the task fails and the *diagnostics* name the violations.
_TASK_FAILURE_LINE = re.compile(
    r"ERROR: Task \S*do_(?:rootfs|deploy_cyclonedx)\)? failed with exit code"
)

#: SHA-512 as the profile requires it: lowercase hex of 512 bits.
SHA512 = re.compile(r"[0-9a-f]{128}\Z")

#: A CycloneDX cross-document bom-ref reference (see the R1 oracle).
CDX_REFERENCE = re.compile(
    r"urn:cdx:(?P<serial>[^/]+)/(?P<version>\d+)#(?P<ref>.+)\Z"
)

#: The deployed name of the primary deployable artifact's file component:
#: the image's stable (non-DATETIME) ext4 rootfs artifact name.
DEPLOYABLE_NAME = re.compile(r"\.ext4(\.zst)?\Z")

#: The four-valued report verdict vocabulary.
VERDICTS = {"verified", "asserted", "unmet", "unverifiable"}

#: Pinned property-taxonomy v0.1.2 value domains for the classifier triple.
BSI_TRIPLE_DOMAINS = {
    "bsi:component:executable": {"executable", "non-executable"},
    "bsi:component:archive": {"archive", "no archive"},
    "bsi:component:structured": {"structured", "unstructured"},
}

#: A rootfs package whose delivered executable is certain to appear as a
#: mandatory file component (the R1 oracle cross-checks it against the
#: deployed manifest).
ROOTFS_PACKAGE = "busybox"

#: Report-enforcement findings never gate the output; these rows carry
#: the baseline's honest gaps for the public configuration exercised
#: here (no creator, SBOM creator or distribution licence supplied).
HONEST_GAP_ROWS = ("REQ-SBOM-001", "REQ-COMP-011", "REQ-COMP-012")


@pytest.fixture(autouse=True)
def build_succeeded(kas_build):
    """No evidence observation is made over a failed or aborted build."""
    assert kas_build.returncode == 0, (
        f"the cold run it would report on failed via {kas_build.engine} "
        f"(exit {kas_build.returncode}); build-log tail:\n"
        f"{kas_build.output_tail}"
    )


@pytest.fixture(scope="module")
def profile_run(kas_runs, kas_build):
    """The report-enforcement invocation, plus the baseline guarantee.

    Teardown re-invokes the plain configuration (no profile variables),
    mirroring R3's revert: the profile variables move the generation
    tasks' signatures, so only an invocation without them restores the
    baseline sstate objects onto the deploy paths. The deployed report
    files are removed there — the baseline deploy directory must be
    byte-comparable to the cold run for every later matrix module.
    """
    record = kas_runs.invoke(
        "alignment-report", extra_env=kas_env.ALIGNMENT_REPORT_ENV
    )
    try:
        yield record
    finally:
        if "alignment-reverted" not in kas_runs.results:
            kas_runs.invoke("alignment-reverted")
        kas_env.remove_deployed_alignment_reports(kas_env.deploy_dir())


@pytest.fixture(scope="module")
def violation_runs(kas_runs, profile_run):
    """One controlled violation through both enforcements, in that order.

    report first: the violation must pass with a finding. strict second:
    the same configuration must reject the build — recorded as an
    expected failure, so the baseline-restoring invocation stays
    unaffected by the deliberate rejection.
    """
    report = kas_runs.invoke(
        "alignment-violation-report",
        extra_env=kas_env.ALIGNMENT_VIOLATION_REPORT_ENV,
    )
    strict = (
        kas_runs.invoke(
            "alignment-strict",
            extra_env=kas_env.ALIGNMENT_STRICT_ENV,
            expect_failure=True,
        )
        if report.returncode == 0
        else None
    )
    return SimpleNamespace(report=report, strict=strict)


@pytest.fixture(scope="module")
def baseline_restored(kas_runs, violation_runs):
    """The plain re-invocation restoring the baseline deployment bytes."""
    record = kas_runs.invoke("alignment-reverted")
    kas_env.remove_deployed_alignment_reports(record.build.deploy_dir)
    return record


def _record_guard(record, label):
    assert record is not None, (
        f"the {label} run was never invoked (its prerequisite failed)"
    )


def _succeeded(record, label):
    assert record.returncode == 0, (
        f"the {label} run failed via {record.build.engine} "
        f"(exit {record.returncode}); build-log tail:\n{record.output_tail}"
    )


def _findings(report):
    return {finding["requirementId"]: finding for finding in report["findings"]}


def _finding(profile_run_record, requirement_id):
    report = profile_run_record.documents.alignment_report
    findings = _findings(report)
    assert requirement_id in findings, (
        f"requirement {requirement_id} is not reported; reported rows: "
        f"{sorted(findings)}; build-log tail:\n{profile_run_record.output_tail}"
    )
    return findings[requirement_id]


def _component_refs(sbom):
    refs = set()
    for component in [sbom.get("metadata", {}).get("component", {}),
                      *sbom.get("components", [])]:
        ref = component.get("bom-ref")
        if ref:
            refs.add(ref)
    return refs


def _property_value(component, name):
    for prop in component.get("properties") or ():
        if prop.get("name") == name:
            return prop.get("value")
    return None


def _file_components(sbom, predicate=lambda component: True):
    return [
        component
        for component in sbom.get("components") or []
        if component.get("type") == "file" and predicate(component)
    ]


def _sha512(component):
    return [
        entry.get("content")
        for entry in component.get("hashes") or []
        if entry.get("alg") == "SHA-512"
    ]


def _walk_keys(value):
    if isinstance(value, dict):
        for key, nested in value.items():
            yield key
            yield from _walk_keys(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from _walk_keys(nested)


# --- report-enforcement evidence ---------------------------------------------


def test_profile_report_run_deploys_all_three_documents(profile_run):
    """SBOM, separate VEX and the alignment report land together, in the
    documented output location (TMPDIR/deploy/images/<machine>)."""
    _succeeded(profile_run, "alignment-report")
    for name in (
        kas_env.SBOM_NAME,
        kas_env.VEX_NAME,
        kas_env.ALIGNMENT_REPORT_NAME,
    ):
        assert name in profile_run.checksums, (
            f"{name} was not deployed under {profile_run.build.deploy_dir}; "
            f"deployed entries: {sorted(profile_run.checksums)}; build-log "
            f"tail:\n{profile_run.output_tail}"
        )
        profile_run.documents.deployed(name, "deployed artifact")


def test_deploy_generation_ran_after_image_assembly(profile_run):
    """Task ordering, observed in the run's log: the deployment
    generation (the one carrying the deploy-artifact inventory) landed
    in this invocation — run as the post-image do_deploy_cyclonedx or
    served from the cache it wrote, never skipped."""
    _succeeded(profile_run, "alignment-report")
    assert any(
        name.endswith(":do_deploy_cyclonedx")
        for name in profile_run.reran_tasks
    ) or any(
        name.endswith(":do_deploy_cyclonedx")
        for name in kas_env.setscene_restored_tasks(profile_run.log)
    ), (
        "do_deploy_cyclonedx neither reran nor was served in the "
        f"alignment-report run; reran tasks: {sorted(profile_run.reran_tasks)};"
        f" build-log tail:\n{profile_run.output_tail}"
    )


def test_alignment_report_records_the_pinned_profile_baseline(profile_run):
    """The report names its exact normative baseline, so results stay
    reproducible after standards change."""
    report = profile_run.documents.alignment_report
    assert report["alignmentProfile"] == kas_env.ALIGNMENT_PROFILE
    assert report["alignmentEnforcement"] == "report"
    baseline = report["profileBaseline"]
    assert baseline["guideline"] == "BSI TR-03183-2"
    assert baseline["guidelineVersion"] == "2.1.0"
    assert baseline["propertyTaxonomyVersion"] == "0.1.2"
    assert baseline["cyclonedxSchemaVersion"] == "1.7"
    assert isinstance(baseline["requirementsMatrixVersion"], str)
    assert baseline["requirementsMatrixVersion"], (
        "the report records no requirements-matrix version"
    )
    assert "conformance" in report["conformanceDetermination"].lower(), (
        "the report must carry the conformance-determination statement; "
        f"got {report['conformanceDetermination']!r}"
    )
    ids = [finding["requirementId"] for finding in report["findings"]]
    assert ids and ids == sorted(ids) and len(ids) == len(set(ids)), (
        f"findings must be unique and ordered by requirement id: {ids}"
    )


def test_report_verdicts_stay_within_the_four_valued_vocabulary(profile_run):
    """Every matrix row is reported with a verdict from exactly
    {verified, asserted, unmet, unverifiable} and full provenance."""
    report = profile_run.documents.alignment_report
    for finding in report["findings"]:
        for key in (
            "requirementId",
            "normativeSource",
            "cyclonedxRepresentation",
            "applicability",
            "verdict",
            "evidenceOrigin",
            "diagnosticMessage",
        ):
            assert key in finding, f"finding {finding} lacks {key!r}"
        assert finding["verdict"] in VERDICTS, (
            f"{finding['requirementId']} carries verdict "
            f"{finding['verdict']!r}, outside {sorted(VERDICTS)}"
        )
        assert finding["applicability"] in {"applicable", "not-applicable"}


def test_static_link_coverage_row_reports_debugsrc_evidence(profile_run):
    """The pkgdata debug-source (debugsrc) coverage lane reports itself
    in the alignment report — with an honest verdict, never silently
    absent (REQ-DEPS-005)."""
    row = _finding(profile_run, "REQ-DEPS-005")
    assert row["verdict"] in VERDICTS
    assert row["diagnosticMessage"]


def test_deployed_documents_validate_against_the_pinned_schema(
    profile_run, schema_validation
):
    """REQ-FMT-002/003 are not just reported verified — the deployed
    bytes re-validate host-side against the vendored CycloneDX 1.7
    schemas."""
    for document, what in (
        (profile_run.documents.sbom, "SBOM"),
        (profile_run.documents.vex, "VEX"),
    ):
        status, diagnostics = schema_validation.check(document, "1.7")
        assert status == "valid", (
            f"the deployed profile-run {what} violates the vendored "
            f"CycloneDX 1.7 schema:\n{diagnostics}\nbuild-log tail:\n"
            f"{profile_run.output_tail}"
        )
    for requirement_id in ("REQ-FMT-002", "REQ-FMT-003"):
        assert _finding(profile_run, requirement_id)["verdict"] == "verified"


def test_sbom_carries_file_components_with_bsi_sha512_identity(profile_run):
    """Mandatory delivered-file discovery: the rootfs executable is a
    file component with a SHA-512 artifact identity and the pinned
    taxonomy's classifier triple, not a copy of the logical record.

    File components carry the delivered basename, and busybox installs
    through update-alternatives as busybox.nosuid/busybox.suid (the
    bare busybox entry is a symlink, which the inventory attributes to
    its target, so it never names a component of its own).
    """
    sbom = profile_run.documents.sbom
    delivered = re.compile(
        rf"^{ROOTFS_PACKAGE}(\.[A-Za-z0-9_-]+)?$", re.IGNORECASE
    )
    files = _file_components(
        sbom, lambda c: delivered.match(c.get("name") or "")
    )
    assert files, (
        f"no file component names a delivered {ROOTFS_PACKAGE} binary; "
        f"file components: "
        f"{sorted(c.get('name', '') for c in _file_components(sbom))[:20]}"
    )
    for component in files:
        digests = _sha512(component)
        assert digests and all(SHA512.match(d or "") for d in digests), (
            f"file component {component.get('name')!r} lacks a lowercase "
            f"hex SHA-512 artifact hash: {component.get('hashes')}"
        )
        assert _property_value(component, "bsi:component:filename") == (
            component.get("name")
        )
    binary = files[0]
    assert _property_value(binary, "bsi:component:executable") == "executable"
    assert _property_value(binary, "bsi:component:archive") == "no archive"
    for name, domain in BSI_TRIPLE_DOMAINS.items():
        value = _property_value(binary, name)
        assert value in domain, (
            f"bsi property {name} value {value!r} outside the pinned "
            f"domain {sorted(domain)}"
        )


def test_primary_deployable_artifact_is_discovered_and_hashed(profile_run):
    """The delivered image itself is inventoried under the profile
    regardless of package manifests (REQ-FILE-004 verified), as a file
    component carrying SHA-512; where the named artifact is present in
    the deploy directory, the recorded digest is re-computed host-side.
    That match is the hashing claim — and only the post-image
    generation could carry the final bytes."""
    sbom = profile_run.documents.sbom
    deployables = _file_components(
        sbom, lambda c: DEPLOYABLE_NAME.search(c.get("name") or "")
    )
    assert deployables, (
        "no file component represents the primary deployable artifact; "
        f"file components: "
        f"{sorted(c.get('name', '') for c in _file_components(sbom))[:20]}"
    )
    assert _finding(profile_run, "REQ-FILE-004")["verdict"] == "verified"
    for component in deployables:
        digests = _sha512(component)
        assert digests and all(SHA512.match(d or "") for d in digests), (
            f"deployable-artifact component {component.get('name')!r} "
            f"lacks a lowercase hex SHA-512: {component.get('hashes')}"
        )
        artifact = profile_run.build.deploy_dir / component["name"]
        if artifact.is_file():
            digest = hashlib.sha512()
            with artifact.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1 << 20), b""):
                    digest.update(chunk)
            assert digest.hexdigest() in digests, (
                f"the recorded SHA-512 of {component['name']} does not "
                f"match the deployed artifact's bytes; recorded "
                f"{sorted(digests)}, computed {digest.hexdigest()}, "
                f"resolved to {artifact.resolve()!r} (mtime "
                f"{artifact.stat().st_mtime_ns})"
            )


def test_file_components_hang_in_the_dependency_graph(profile_run):
    """Every file component — the executable and the primary deployable
    artifact alike — participates in the dependency graph (leaf entries
    or owner edges), the graph-completeness claim of REQ-DEPS-003 and
    REQ-FILE-003."""
    sbom = profile_run.documents.sbom
    graph = sbom.get("dependencies") or []
    assert graph, "the deployed SBOM carries no dependency graph"
    listed = {entry.get("ref") for entry in graph}
    referenced = {
        ref for entry in graph for ref in entry.get("dependsOn") or ()
    }
    for component in _file_components(sbom):
        ref = component.get("bom-ref")
        assert ref in listed or ref in referenced, (
            f"file component {component.get('name')!r} ({ref}) is absent "
            "from the dependency graph"
        )


def test_sbom_hides_no_vulnerability_data_and_vex_references_resolve(
    profile_run,
):
    """The SBOM/VEX split survives the profile: no vulnerabilities key
    anywhere in the SBOM, and every VEX affects-reference resolves
    against this run's SBOM component instances."""
    sbom, vex = profile_run.documents.sbom, profile_run.documents.vex
    assert "vulnerabilities" not in set(_walk_keys(sbom)), (
        "the profile SBOM carries vulnerability data somewhere"
    )
    for requirement_id in ("REQ-VULN-001", "REQ-VULN-002"):
        assert _finding(profile_run, requirement_id)["verdict"] == "verified"

    serial = (sbom.get("serialNumber") or "").removeprefix("urn:uuid:")
    version = str(sbom.get("version", 1))
    refs = _component_refs(sbom)

    def resolves(ref):
        match = CDX_REFERENCE.fullmatch(ref)
        return (
            match is not None
            and match["serial"] == serial
            and match["version"] == version
            and match["ref"] in refs
        )

    dangling = [
        (vulnerability.get("id"), affect.get("ref"))
        for vulnerability in vex.get("vulnerabilities", [])
        for affect in vulnerability.get("affects", [])
        if not resolves(affect.get("ref", ""))
    ]
    assert not dangling, (
        f"VEX affects-references do not resolve against the profile-run "
        f"SBOM: {dangling[:5]}; build-log tail:\n{profile_run.output_tail}"
    )


def test_identity_dependency_and_creator_outcomes_are_reported(profile_run):
    """Representative outcomes without the renderer's matrix: the
    primary component identifies the delivered image, the known package
    rides the graph as a dependency of the root, an unasserted primary
    creator is an honest unmet row (never an invented one), and licence
    roles keep their truthful separation."""
    sbom = profile_run.documents.sbom
    primary = sbom.get("metadata", {}).get("component", {})
    assert primary.get("name") == kas_env.TARGET
    assert primary.get("type") == "firmware"

    packages = {
        component.get("name"): component
        for component in sbom.get("components") or []
        if component.get("type") != "file"
    }
    assert ROOTFS_PACKAGE in packages, (
        f"{ROOTFS_PACKAGE} is missing from the logical components: "
        f"{sorted(packages)[:20]}"
    )
    graph = sbom.get("dependencies") or []
    root = next(
        (
            entry
            for entry in graph
            if entry.get("ref") == primary.get("bom-ref")
        ),
        None,
    )
    assert root is not None, "the dependency graph is not rooted at the primary"
    assert packages[ROOTFS_PACKAGE].get("bom-ref") in (
        root.get("dependsOn") or ()
    ), f"{ROOTFS_PACKAGE} is not a dependency of the delivered product"

    creator = _finding(profile_run, "REQ-COMP-012")
    assert creator["verdict"] == "unmet", (
        "a product integration that asserts no primary creator must report "
        f"it unmet, not {creator['verdict']!r}"
    )
    assert not primary.get("author") and not primary.get("authors"), (
        "the renderer invented creator evidence the config never supplied"
    )
    _finding(profile_run, "REQ-SBOM-001")["verdict"] in VERDICTS

    assert _finding(profile_run, "REQ-COMP-013")["verdict"] == "verified", (
        "recipe LICENSE must reach the document as original (declared) "
        "licence evidence"
    )

    def carries_declared(entry):
        if entry.get("acknowledgement") == "declared":
            return True
        field = entry.get("license")
        return (
            isinstance(field, dict)
            and field.get("acknowledgement") == "declared"
        )

    declared = [
        entry for entry in primary.get("licenses") or []
        if carries_declared(entry)
    ]
    assert primary.get("licenses") and declared, (
        f"the primary component carries no declared original licence: "
        f"{primary.get('licenses')}"
    )
    distribution = _finding(profile_run, "REQ-COMP-011")
    assert distribution["verdict"] == "unmet", (
        "an unsupplied distribution licence must stay unmet, never be "
        f"inferred from recipe LICENSE; verdict: {distribution['verdict']!r}"
    )


def test_honest_baseline_gaps_publish_instead_of_blocking(profile_run):
    """Report enforcement is what makes the honest gaps visible: every
    row that this configuration leaves without evidence still rides the
    published report — and the documents deployed anyway."""
    for requirement_id in HONEST_GAP_ROWS:
        finding = _finding(profile_run, requirement_id)
        assert finding["verdict"] in VERDICTS
        assert finding["diagnosticMessage"]
    _succeeded(profile_run, "alignment-report")


# --- determinism --------------------------------------------------------------


def test_identical_profile_reinvocation_is_byte_identical(
    kas_runs, profile_run
):
    """The second identical invocation is cache-served (only the noexec
    rm_work bookkeeping reruns) and deploys byte-identical evidence; the
    report itself serializes deterministically regardless."""
    again = kas_runs.invoke(
        "alignment-report-again", extra_env=kas_env.ALIGNMENT_REPORT_ENV
    )
    _succeeded(again, "alignment-report-again")
    for name, first_bytes in profile_run.document_captures.items():
        assert again.document_captures.get(name) == first_bytes, (
            f"{name} is not byte-identical between two identical profile "
            f"invocations; build-log tail:\n{again.output_tail}"
        )
    unexpected = sorted(
        task
        for task in again.reran_tasks
        if not task.endswith(":do_rm_work")
    )
    assert not unexpected, (
        f"work tasks reran on the identical profile re-invocation: "
        f"{unexpected}; build-log tail:\n{again.output_tail}"
    )


# --- the strict pair -----------------------------------------------------------


def test_the_violation_passes_in_report_mode(violation_runs):
    """One controlled machine-detectable defect, introduced through
    nothing but public configuration: report enforcement still builds,
    the renderer loudly rejects the unusable creator contact, and the
    report carries the unmet REQ-COMP-012 row the same config would
    fail strict enforcement over."""
    record = violation_runs.report
    _succeeded(record, "alignment-violation-report")
    assert "no usable email address or URL" in record.log, (
        "the rejected creator contact was not surfaced in the build log; "
        f"the config would have vanished silently; build-log tail:\n"
        f"{record.output_tail}"
    )
    finding = _finding(record, "REQ-COMP-012")
    assert finding["verdict"] == "unmet", (
        "the injected violation must report unmet under report "
        f"enforcement, got {finding['verdict']!r}"
    )
    primary = record.documents.sbom.get("metadata", {}).get("component", {})
    assert not primary.get("author") and not primary.get("authors"), (
        "the unusable creator was emitted as contact data"
    )


def test_strict_enforcement_fails_the_build_at_the_task_surface(
    violation_runs,
):
    """The same configuration under strict enforcement fails the build:
    BitBake reports the generation task's failure, the aggregated
    rejection names every machine-detectable violation exactly once, and
    the injected defect is one of them."""
    strict = violation_runs.strict
    _record_guard(strict, "alignment-strict")
    assert strict.returncode != 0, (
        "strict enforcement accepted the machine-detectable violation; "
        f"build-log tail:\n{strict.output_tail}"
    )
    assert any(
        _TASK_FAILURE_LINE.search(line) for line in strict.log.splitlines()
    ), (
        "no CycloneDX generation task failed at the task surface; build-log "
        f"tail:\n{strict.output_tail}"
    )
    assert "strict enforcement rejects the output" in strict.log, (
        "the build log carries no aggregated strict rejection; build-log "
        f"tail:\n{strict.output_tail}"
    )
    assert "REQ-COMP-012" in strict.log, (
        "the aggregated rejection does not name the injected violation; "
        f"build-log tail:\n{strict.output_tail}"
    )


def test_strict_rejection_deploys_nothing_new(violation_runs, kas_runs):
    """Strict refuses publication: every CycloneDX byte present in the
    deploy directory after the rejected run belongs to an earlier run.

    The claim is provenance, not immutability. BitBake winds the
    rejected invocation down by cancelling, and unrelated tasks' sstate
    restores legitimately re-stage whichever configured objects their
    signatures name (unmet-only enforcement keeps the report and strict
    documents' bytes identical for the same content). Nothing the
    strict invocation computed may appear: every live CycloneDX entry
    must match a checksum some completed recorded run deployed.
    """
    strict, twin = violation_runs.strict, violation_runs.report
    _record_guard(strict, "alignment-strict")
    _succeeded(twin, "alignment-violation-report")
    known = set()
    for record in kas_runs.results.values():
        if record.returncode == 0 and record.checksums:
            known.update(
                deploy_compare.cyclonedx_checksums(record.checksums).values()
            )
    live = kas_env.artifact_checksums(strict.build.deploy_dir)
    strays = {
        name: digest
        for name, digest in deploy_compare.cyclonedx_checksums(live).items()
        if digest not in known
    }
    assert not strays, (
        "the strict run deployed CycloneDX bytes no completed run ever "
        f"produced: {sorted(strays)}\n"
        f"build-log tail:\n{strict.output_tail}"
    )


# --- baseline isolation ---------------------------------------------------------


def test_baseline_reinvocation_restores_deployed_bytes(
    kas_runs, baseline_restored
):
    """Scenario isolation, proven: the plain re-invocation restores the
    cold run's deployed SBOM and VEX byte-for-byte (the sstate objects
    its signatures name again) and removes the profile's report
    artifacts from the deploy directory. Image artifacts fall under the
    cache module's own claim: DATETIME-named hardlinks rotate whenever
    any config flip replays the image tasks, so the profile scenario
    chain stays CycloneDX-scoped."""
    _record_guard(baseline_restored, "alignment-reverted")
    _succeeded(baseline_restored, "alignment-reverted")
    cold = kas_runs["cold"]
    for name in (kas_env.SBOM_NAME, kas_env.VEX_NAME):
        assert baseline_restored.document_captures[name] == (
            cold.document_captures[name]
        ), (
            f"{name} was not restored byte-for-byte by the revert "
            f"invocation; {deploy_compare.identity_report(baseline_restored, cold)}"
        )
        assert baseline_restored.checksums[name] == cold.checksums[name]
    leftovers = sorted(
        path.name
        for path in kas_env.deploy_dir().glob(kas_env.ALIGNMENT_REPORT_GLOB)
    )
    assert not leftovers, (
        f"profile report artifacts survived in {kas_env.deploy_dir()}: "
        f"{leftovers}"
    )

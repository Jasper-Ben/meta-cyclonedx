# SPDX-License-Identifier: MIT
"""Unit tests for the alignment-profile acceptance harness (no build).

The seams are the integration harness's public configuration channel:
the profile-selection environment dicts, their mode-appropriate launch
construction, and the kas.yml `env:` block that decides which container
variables reach the BitBake datastore. The alignment-profile scenario
configures BitBake through exactly this channel — never through a
tracked file — so the channel's contract is the scenario's contract.
"""

from tests.integration import kas_env

PROFILE_ENVS = (
    kas_env.ALIGNMENT_REPORT_ENV,
    kas_env.ALIGNMENT_VIOLATION_REPORT_ENV,
    kas_env.ALIGNMENT_STRICT_ENV,
)


def test_container_mode_profile_rides_the_runtime_args_channel():
    command, env = kas_env.kas_invocation(
        "podman", extra_env=kas_env.ALIGNMENT_STRICT_ENV
    )
    assert command == [
        str(kas_env.KAS_CONTAINER),
        "--runtime-args",
        "-e CYCLONEDX_PRIMARY_COMPONENT_CREATOR=AcmeGmbH",
        "--runtime-args",
        "-e CYCLONEDX_PROFILE=tr03183-2.1",
        "--runtime-args",
        "-e CYCLONEDX_PROFILE_ENFORCEMENT=strict",
        "build",
        "kas.yml",
    ]
    assert env == {}


def test_direct_mode_profile_rides_the_process_environment():
    """The profile scenario's claim is mode-independent, like R5's."""
    command, env = kas_env.kas_invocation(
        kas_env.KAS_DIRECT,
        extra_env=kas_env.ALIGNMENT_STRICT_ENV,
    )
    assert command == ["kas", "build", "kas.yml"]
    assert "--runtime-args" not in command
    assert env == {**kas_env.ALIGNMENT_STRICT_ENV}


def test_profile_scenario_values_survive_the_word_split_channel():
    """kas-container word-splits --runtime-args; no whitespace may ride."""
    for env in PROFILE_ENVS:
        for key, value in env.items():
            assert key and not any(c.isspace() for c in key + str(value)), (
                f"profile env {key!s}={value!r} must not contain whitespace"
            )


def test_kas_yml_declares_forwarding_for_every_profile_variable():
    """An undeclared `env:` key would silently drop the scenario's config.

    The scenario passes only variables declared in kas.yml's env block —
    the same channel R5's CORE_IMAGE_EXTRA_INSTALL rides, so the check
    covers every extra_env the integration layer may ever forward.
    """
    text = (kas_env.REPO_ROOT / "kas.yml").read_text()
    declared = set()
    in_block = False
    for line in text.splitlines():
        if line.startswith("env:"):
            in_block = True
            continue
        if in_block:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if not line.startswith(" "):
                break
            declared.add(line.split(":", 1)[0].strip())

    needed = set()
    for env in PROFILE_ENVS:
        needed.update(env)
    needed.update(kas_env.IMAGE_EXTRA_INSTALL_ENV)
    missing = sorted(needed - declared)
    assert not missing, f"kas.yml env: block does not declare {missing}"



def test_deployed_reports_are_removed_documents_stay(tmp_path):
    """Profile cleanup is surgical: reports (and their links) only.

    The rest of the matrix compares whole deploy-dir checksum maps for
    byte identity, so a leftover report file after the profile scenario
    would poison R2's claim; the baseline documents themselves are the
    revert invocation's sstate business, not the harness's.
    """
    deploy = tmp_path / "images"
    deploy.mkdir()
    documents = {
        kas_env.SBOM_NAME: "sbom",
        kas_env.VEX_NAME: "vex",
    }
    for name, text in documents.items():
        (deploy / name).write_text(text)
    report = deploy / kas_env.ALIGNMENT_REPORT_NAME
    report.write_text("report")
    link = deploy / "core-image-minimal-qemux86-64.cyclonedx.alignment-report.json"
    link.symlink_to(kas_env.ALIGNMENT_REPORT_NAME)

    removed = kas_env.remove_deployed_alignment_reports(deploy)

    assert sorted(path.name for path in removed) == sorted(
        [report.name, link.name]
    )
    assert all(
        (deploy / name).read_text() == text for name, text in documents.items()
    )
    assert not report.exists() and not link.is_symlink()


def test_removing_deployed_reports_is_idempotent(tmp_path):
    """No reports (or none left): nothing to remove, nothing raised."""
    deploy = tmp_path / "images"
    deploy.mkdir()
    assert kas_env.remove_deployed_alignment_reports(deploy) == []
    assert kas_env.remove_deployed_alignment_reports(deploy) == []


def test_deployed_alignment_report_follows_the_document_basename():
    """The report's deployed name is the class default under the harness
    basename: <image>.cyclonedx.alignment-report.json."""
    assert kas_env.ALIGNMENT_REPORT_NAME == (
        "core-image-minimal.cyclonedx.alignment-report.json"
    )

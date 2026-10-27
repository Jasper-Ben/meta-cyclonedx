# SPDX-License-Identifier: MIT
"""Unit tests for the matrix stage gate in the run recorder (no build)."""

import pytest

from tests.integration import kas_env
from tests.integration.conftest import (
    KasBuildResult,
    KasRunRecorder,
    RunRecord,
)

FAILURE_LINES = [
    "NOTE: Tasks Summary: Attempted 3914 tasks.\n",
    "ERROR: Task (/build/meta/recipes-kernel/linux/linux-yocto_6.6.bb:"
    "do_compile) failed with exit code '1'\n",
]


def recorder_with(name, returncode, build_dir):
    """A recorder whose single recorded invocation exited with *returncode*."""
    recorder = KasRunRecorder("podman")
    recorder.results[name] = RunRecord(
        name,
        KasBuildResult("podman", returncode, FAILURE_LINES, build_dir),
        FAILURE_LINES,
    )
    recorder._pinned = True
    return recorder


def deploy_dir(tmp_path):
    """Make the build dir look like one that deployed artifacts."""
    (tmp_path / "tmp" / "deploy" / "images" / kas_env.MACHINE).mkdir(
        parents=True, exist_ok=True
    )
    return tmp_path


def launch_attempt(*args, **kwargs):
    raise AssertionError("bitbake must not launch after a failed invocation")


def patch_stage_environment(monkeypatch, recorder, tmp_path, stream=None):
    monkeypatch.setattr(recorder, "_stream", stream or launch_attempt)
    monkeypatch.setattr(kas_env, "ensure_fixture_layer", lambda: None)
    monkeypatch.setattr(kas_env, "workspace_env", dict)
    monkeypatch.setattr(kas_env, "build_dir", lambda: deploy_dir(tmp_path))


def test_failed_invocation_skips_later_stages(monkeypatch, tmp_path):
    recorder = recorder_with("cold", 2, deploy_dir(tmp_path))
    patch_stage_environment(monkeypatch, recorder, tmp_path)

    with pytest.raises(pytest.skip.Exception) as excinfo:
        recorder.invoke("mutation")

    reason = str(excinfo.value)
    assert "cold" in reason
    assert "exit 2" in reason
    # The skip carries the build-log tail, so CI shows the actual error.
    assert "do_compile" in reason


def test_zero_exit_invocation_leaves_later_stages_unaffected(monkeypatch, tmp_path):
    recorder = recorder_with("cold", 0, deploy_dir(tmp_path))
    launched = []

    def stream(command, env, **stream_kwargs):
        launched.append(stream_kwargs)
        return 0, FAILURE_LINES

    patch_stage_environment(monkeypatch, recorder, tmp_path, stream=stream)
    record = recorder.invoke("warm")

    assert launched, "the warm stage must still launch"
    assert record.returncode == 0


def test_deliberate_failure_runs_are_not_harness_aborted(monkeypatch, tmp_path):
    """An expected-failure invocation winds BitBake down itself.

    A harness-side interrupt would kill in-flight sstate restores
    mid-manifest and leave the deploy directory transitional, so the
    recorder must disable first-failure aborting exactly for
    expect_failure invocations and keep it everywhere else.
    """
    seen = []

    def stream(command, env, *, abort_on_failure=True):
        seen.append(abort_on_failure)
        return 0, FAILURE_LINES

    recorder = recorder_streaming(stream, tmp_path, monkeypatch)
    recorder.invoke("alignment-report")
    recorder.invoke("alignment-strict", expect_failure=True)

    assert seen == [True, False], (
        f"aborting must be on for ordinary runs and off for deliberate "
        f"rejections, saw {seen}"
    )


def test_recorded_failure_is_not_relunched_under_its_own_name(monkeypatch, tmp_path):
    recorder = recorder_with("cold", 2, deploy_dir(tmp_path))
    patch_stage_environment(monkeypatch, recorder, tmp_path)

    record = recorder.invoke("cold")

    assert record.returncode == 2


def recorder_streaming(stream, tmp_path, monkeypatch):
    """A pinned recorder whose launches answer through *stream*."""
    recorder = KasRunRecorder("podman")
    patch_stage_environment(monkeypatch, recorder, tmp_path, stream=stream)
    recorder._pinned = True
    return recorder


def test_expected_failure_invocation_does_not_gate_later_stages(
    monkeypatch, tmp_path
):
    """A deliberately failing strict run must not skip the follow-up stages.

    The stage gate assumes a failure leaves no stamp advanced and the next
    invocation replays the identical failure. A strict-enforcement rejection
    is different by construction: the violation rides the invocation's own
    environment, so the next invocation — without it — cannot replay it and
    must run.
    """
    launched = []

    def stream(command, env, **stream_kwargs):
        launched.append(stream_kwargs)
        return (1 if len(launched) == 1 else 0), FAILURE_LINES

    recorder = recorder_streaming(stream, tmp_path, monkeypatch)
    failing = recorder.invoke("strict-violation", expect_failure=True)
    assert failing.returncode == 1

    follow_up = recorder.invoke("baseline-restored")
    assert follow_up.returncode == 0
    assert len(launched) == 2, (
        "the follow-up stage must launch after an expected failure"
    )


def test_unexpected_failure_gates_later_stages_despite_an_expected_one(
    monkeypatch, tmp_path
):
    """The exemption is per-record: accidental failures still gate."""
    recorder = recorder_streaming(
        lambda command, env, **kw: (1, FAILURE_LINES), tmp_path, monkeypatch
    )
    recorder.invoke("strict-violation", expect_failure=True)
    recorder.invoke("cold")

    with pytest.raises(pytest.skip.Exception) as excinfo:
        recorder.invoke("anything-else")
    assert "cold" in str(excinfo.value)


def test_expected_failure_that_unexpectedly_succeeds_gates_nothing(
    monkeypatch, tmp_path
):
    """A zero-exit expected-failure run is just a successful run to the gate."""
    recorder = recorder_streaming(
        lambda command, env, **kw: (0, FAILURE_LINES), tmp_path, monkeypatch
    )
    assert recorder.invoke("strict-violation", expect_failure=True).returncode == 0
    assert recorder.invoke("next-stage").returncode == 0


def deployed_documents(build_dir, texts):
    """Plant deployed document *texts* under the build dir's deploy area."""
    deploy = build_dir / "tmp" / "deploy" / "images" / kas_env.MACHINE
    deploy.mkdir(parents=True, exist_ok=True)
    for name, text in texts.items():
        (deploy / name).write_text(text)
    return deploy


def test_profile_invocation_captures_the_alignment_report(monkeypatch, tmp_path):
    """A profile invocation's evidence is three documents, not two.

    The recorder sees the profile selector in the invocation's environment,
    so exactly those runs also capture the deployed alignment report —
    later invocations overwrite the bom/vex paths, and reports never get
    deleted from the shared deploy directory.
    """
    build = deploy_dir(tmp_path)
    deployed_documents(
        build,
        {
            kas_env.SBOM_NAME: "sbom",
            kas_env.VEX_NAME: "vex",
            kas_env.ALIGNMENT_REPORT_NAME: "report",
        },
    )
    recorder = recorder_streaming(
        lambda command, env, **kw: (0, FAILURE_LINES), tmp_path, monkeypatch
    )
    record = recorder.invoke(
        "alignment-report", extra_env=kas_env.ALIGNMENT_REPORT_ENV
    )

    assert record.document_captures == {
        kas_env.SBOM_NAME: "sbom",
        kas_env.VEX_NAME: "vex",
        kas_env.ALIGNMENT_REPORT_NAME: "report",
    }


def test_plain_invocation_never_captures_a_stale_alignment_report(
    monkeypatch, tmp_path
):
    """Without a profile selector the report stays someone else's evidence."""
    build = deploy_dir(tmp_path)
    deployed_documents(
        build,
        {
            kas_env.SBOM_NAME: "sbom",
            kas_env.VEX_NAME: "vex",
            kas_env.ALIGNMENT_REPORT_NAME: "stale-report",
        },
    )
    recorder = recorder_streaming(
        lambda command, env, **kw: (0, FAILURE_LINES), tmp_path, monkeypatch
    )
    record = recorder.invoke("warm")

    assert record.document_captures == {
        kas_env.SBOM_NAME: "sbom",
        kas_env.VEX_NAME: "vex",
    }

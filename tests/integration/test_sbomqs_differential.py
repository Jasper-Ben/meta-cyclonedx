# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: Copyright (C) 2026 iris-GmbH infrared & intelligent sensors.

"""Differential check of the requirements matrix against `sbomqs`.

Maintainer-only tooling: the test skips automatically when the
external `sbomqs` binary is not on PATH. The requirements matrix owns
our verdicts (ticket #11); sbomqs serves as an independent second
opinion on representative documents. A disagreement fails only this
differential-marked test, prompting a review of the affected matrix
rows - never silently moves a verdict.

The v2 JSON structural features are explicit checks, not the aggregate
quality score. Unsupported output or tool failures fail the job rather
than silently skipping the comparison.

Run explicitly with:
    pytest -m integration tests/integration/test_sbomqs_differential.py
"""

import json
import shutil
import subprocess

import alignment_profile
import pytest
from helpers import default_facts, file_entry, profile_config, render_docs

pytestmark = pytest.mark.integration

SBOMQS = shutil.which("sbomqs")

STRUCTURAL_ROWS = ("REQ-REF-001", "REQ-FMT-002", "REQ-IDEN-002",
                   "REQ-IDEN-003", "REQ-IDEN-004", "REQ-TAX-001",
                   "REQ-TAX-002", "REQ-TAX-003")


def _profile_document(**facts_overrides):
    facts = default_facts(
        config=profile_config(),
        file_inventory={"busybox": [
            file_entry("/usr/bin/busybox", sha512="a" * 128)]},
    )
    facts.update(facts_overrides)
    sbom, _vex, _logs = render_docs(facts)
    return sbom


def _structural_verdicts(sbom):
    _baseline, findings = alignment_profile.evaluate(
        "tr03183-2.1", sbom.get("specVersion", "1.7"), sbom, {}, {})
    return {finding["requirementId"]: finding["verdict"]
            for finding in findings
            if finding["requirementId"] in STRUCTURAL_ROWS}


def _sbomqs_passes(tmp_path, sbom):
    document = tmp_path / "sbom.json"
    document.write_text(json.dumps(sbom))
    result = subprocess.run([SBOMQS, "score", "--json", str(document)],
                            capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, (
        f"sbomqs failed (exit {result.returncode}):\n"
        f"{result.stderr}\n{result.stdout}"
    )
    try:
        report = json.loads(result.stdout)
        files = report["files"]
        assert len(files) == 1, "expected one scored SBOM"
        structural = next(category for category in files[0]["comprehenssive"]
                          if category["category"] == "Structural")
        features = {feature["key"]: feature
                    for feature in structural["features"]}
        required = {"sbom_spec_declared", "sbom_spec_version",
                    "sbom_file_format", "sbom_schema_valid"}
        assert required <= features.keys(), "structural features are missing"
        assert not any(features[key]["ignored"] for key in required), (
            "structural checks were not evaluated"
        )
        return all(features[key]["score"] == 10 for key in required)
    except (ValueError, KeyError, IndexError, TypeError, StopIteration,
            AssertionError) as defect:
        pytest.fail(f"sbomqs v2 output not interpretable: {defect}\n"
                    f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}")


@pytest.mark.skipif(SBOMQS is None, reason="sbomqs binary not on PATH")
def test_matrix_and_sbomqs_agree_on_a_clean_representative_document(tmp_path):
    sbom = _profile_document()
    unmet = sorted(rid for rid, verdict in _structural_verdicts(sbom).items()
                   if verdict == "unmet")
    passes = _sbomqs_passes(tmp_path, sbom)
    if unmet and not passes:
        return  # both see structural defects
    if not unmet and passes:
        return  # both see a well-formed document
    pytest.fail("differential disagreement: matrix structural unmet rows "
                f"{unmet} vs sbomqs pass={passes}; review the affected "
                "matrix rows against the current sbomqs ruleset")


@pytest.mark.skipif(SBOMQS is None, reason="sbomqs binary not on PATH")
def test_matrix_and_sbomqs_both_reject_a_structurally_defective_document(tmp_path):
    facts = default_facts(
        config=profile_config(),
        fragments={"busybox": fragment_defective()},
    )
    sbom, _vex, _logs = render_docs(facts)
    verdicts = _structural_verdicts(sbom)
    unmet = sorted(rid for rid, verdict in verdicts.items()
                   if verdict == "unmet")
    assert unmet, "fixture must produce a matrix-detected defect"
    passes = _sbomqs_passes(tmp_path, sbom)
    if passes:
        pytest.fail("differential disagreement: matrix flags "
                    f"{unmet} but sbomqs' structural checks all pass; review "
                    "the affected matrix rows")


def fragment_defective():
    from helpers import fragment, pkg
    return fragment(pkgs=[pkg("busybox", "1.36", "ref-busybox",
                               purl="not-a-purl")])

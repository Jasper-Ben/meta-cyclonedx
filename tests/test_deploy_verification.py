"""Post-image artifact-digest correction at the adapter seam.

Image payload bytes are not reproducible and BitBake's signature chain
cannot see deploy content, so a cache-restored document can record an
older build's SHA-512 digests after `do_image_complete` republished the
artifact bytes in the same invocation. `do_cyclonedx_verify` compares
the recorded digests of the deployable-artifact file components against
the deployed bytes and rewrites just those hash entries, in place: the
document's identity (serials, references, timestamp, every other
component) belongs to its generation and stays untouched, and a
consistent document is not rewritten at all.
"""
import ast
import copy
import hashlib
import json
import os
import types

import meta_cyclonedx

BBCLASS = os.path.join(os.path.dirname(meta_cyclonedx.__file__),
                       "..", "classes", "cyclonedx-export.bbclass")

ARTIFACT = "core-image-minimal-qemux86-64.rootfs.ext4.zst"
FINAL_BYTES = b"the bytes do_image_complete deployed last"
STALE_DIGEST = "b" * 128


def class_function(name):
    """One top-level function's AST from the class file (mixed syntax)."""
    with open(BBCLASS) as class_file:
        lines = class_file.read().splitlines(keepends=True)
    body = []
    wanted = f"def {name}("
    task_header = f"python {name}() {{"
    for index, line in enumerate(lines):
        if line.startswith(wanted) or line.rstrip() == task_header:
            body.append(f"def {name}(d):\n" if line.rstrip() == task_header
                        else line)
            for following in lines[index + 1:]:
                if following.strip() and not following[0].isspace():
                    break
                body.append(following)
            break
    if not body:
        raise AssertionError(f"{name} not found in {BBCLASS}")
    return next(node for node in ast.parse("".join(body)).body
                if isinstance(node, ast.FunctionDef))


def a_document(artifact_digest=STALE_DIGEST):
    return {
        "metadata": {
            "serialNumber": "urn:uuid:the-generation-identity",
            "timestamp": "2026-10-26T00:47:03+00:00",
            "component": {"type": "firmware", "name": "core-image-minimal",
                          "version": "1.0-r0", "bom-ref": "root-ref"},
        },
        "components": [
            {"type": "file", "name": ARTIFACT, "version": "1.0-r0",
             "bom-ref": f"yocto-file::{ARTIFACT}",
             "hashes": [{"alg": "SHA-512", "content": artifact_digest}],
             "properties": [{"name": "bsi:component:filename",
                             "value": ARTIFACT}]},
            # Rootfs file components also use basenames for display.
            # A deploy file with that basename must not change their hash.
            {"type": "file", "name": "busybox", "version": "1.36.1",
             "bom-ref": "yocto-file:busybox:/bin/busybox",
             "hashes": [{"alg": "SHA-512", "content": "f" * 128}]},
            # A selected artifact that is absent from disk: missing
            # artifacts stay inventory evidence, not corrections.
            {"type": "file", "name": "firmware.bin", "version": "unknown",
             "bom-ref": "missing-ref",
             "hashes": [{"alg": "SHA-512", "content": "a" * 128}]},
        ],
    }


def prepare(tmp_path, document, artifact_bytes=FINAL_BYTES,
            nested_artifact=None):
    deploy = tmp_path / "deploy"
    deploy.mkdir()
    if artifact_bytes is not None:
        (deploy / ARTIFACT).write_bytes(artifact_bytes)
    (deploy / "busybox").write_bytes(b"an unrelated deployed file")
    if nested_artifact is not None:
        nested_path = deploy / "payloads" / "firmware.bin"
        nested_path.parent.mkdir()
        nested_path.write_bytes(nested_artifact)
    sbom_path = deploy / "core-image.cyclonedx.bom.json"
    sbom_path.write_text(json.dumps(document, indent=2))
    imagedata = tmp_path / "imagedata" / "core2-64" / "core-image-minimal"
    imagedata.mkdir(parents=True)
    (imagedata / "bom.json").write_text(json.dumps(document, indent=2))
    return sbom_path, imagedata / "bom.json"


def run_verify(tmp_path, document, artifact_bytes=FINAL_BYTES,
               variables=None, nested_artifact=None):
    sbom_path, imagedata_bom = prepare(
        tmp_path, document, artifact_bytes, nested_artifact)
    vars = {
        "PN": "core-image-minimal",
        "DEPLOY_DIR_IMAGE": str(tmp_path / "deploy"),
        "CYCLONEDX_EXPORT_DIR": str(tmp_path / "deploy"),
        "CYCLONEDX_EXPORT_SBOM": "core-image.cyclonedx.bom.json",
        "CYCLONEDX_IMAGEDATA": str(tmp_path / "imagedata"),
        "SSTATE_PKGARCH": "core2-64",
        "CYCLONEDX_PROFILE": "tr03183-2.1",
        **(variables or {}),
    }
    events = []

    class _BBData:
        @staticmethod
        def inherits_class(klass, d):
            return klass == "image"

    class _BB:
        data = _BBData

        @staticmethod
        def debug(level, message):
            events.append(("debug", str(message)))

        @staticmethod
        def note(message):
            events.append(("note", str(message)))

        @staticmethod
        def warn(message):
            events.append(("warn", str(message)))

    class _Data:
        def getVar(self, name):
            return vars.get(name, "")

        def getVarFlag(self, flag, name):
            return ""

    module = types.ModuleType("verify_under_test")
    module.bb = _BB
    tree = ast.Module(body=[class_function("do_cyclonedx_verify"),
                            class_function("write_json")], type_ignores=[])
    exec(compile(tree, BBCLASS, "exec"), module.__dict__)
    module.do_cyclonedx_verify(_Data())
    return events, sbom_path, imagedata_bom


def test_a_drifted_digest_is_corrected_and_everything_else_is_preserved(
        tmp_path):
    document = a_document()
    events, sbom_path, imagedata_bom = run_verify(tmp_path, document)
    expected = copy.deepcopy(document)
    expected["components"][0]["hashes"][0]["content"] = \
        hashlib.sha512(FINAL_BYTES).hexdigest()
    assert json.loads(sbom_path.read_text()) == expected
    assert json.loads(imagedata_bom.read_text()) == expected
    assert any(ARTIFACT in message
               for level, message in events if level == "note")
    # Only the one hash entry moved between the original bytes and the
    # corrected ones; the document identity is intact verbatim.
    saved = json.loads(sbom_path.read_text())
    assert saved["metadata"] == document["metadata"]
    assert saved["components"][1:] == document["components"][1:]


def test_selected_artifact_in_subdirectory_uses_its_inventory_path(tmp_path):
    document = a_document(artifact_digest=hashlib.sha512(
        FINAL_BYTES).hexdigest())
    document["components"].append({
        "type": "file", "name": "firmware.bin",
        "bom-ref": "yocto-file::payloads/firmware.bin",
        "hashes": [{"alg": "SHA-512", "content": STALE_DIGEST}],
    })
    payload = b"the selected deploy artifact"
    _events, sbom_path, imagedata_bom = run_verify(
        tmp_path, document, nested_artifact=payload)
    for path in (sbom_path, imagedata_bom):
        components = json.loads(path.read_text())["components"]
        assert components[2] == document["components"][2]
        assert components[3]["hashes"] == [
            {"alg": "SHA-512", "content": hashlib.sha512(payload).hexdigest()}]


def test_a_consistent_document_is_not_rewritten(tmp_path):
    document = a_document(artifact_digest=hashlib.sha512(
        FINAL_BYTES).hexdigest())
    _events, sbom_path, _imagedata = run_verify(tmp_path, document)
    assert sbom_path.read_text() == json.dumps(document, indent=2)
    assert not [event for event in _events if event[0] in ("note", "warn")]


def test_verification_is_inert_without_a_profile(tmp_path):
    document = a_document()
    text = json.dumps(document, indent=2)
    _events, sbom_path, _imagedata = run_verify(
        tmp_path, document, variables={"CYCLONEDX_PROFILE": ""})
    assert sbom_path.read_text() == text

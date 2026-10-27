# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: Copyright (C) 2026 iris-GmbH infrared & intelligent sensors.

"""Feature-detected CycloneDX JSON schema validation.

One validation module serves both consumers: the renderer evaluates
every emitted SBOM and VEX against its selected official schema through
the requirements matrix, and the integration layer validates deployed
documents with the same vendored schema set.

The official schemas are vendored unmodified under ``data/cyclonedx/``;
their provenance and Apache-2.0 attribution live in the README there.
Validation uses no network access and no third-party schema defaults.

`jsonschema` is an optional dependency: the import is deferred and a
failure surfaces as an honest ``unavailable`` status with its reason,
never as a silent pass. Importing this module never requires the
library, so the renderer stays importable on a build host without it.
"""

import json
from pathlib import Path

#: Vendored schema directory (see the README there for the pin).
SCHEMA_DIR = Path(__file__).resolve().parent / "data" / "cyclonedx"

#: CycloneDX specification versions with a vendored official schema.
SCHEMA_VERSIONS = ("1.6", "1.7")

#: Transitive $ref schemas shared by the vendored bom schemas. The 1.7
#: bom schema additionally references the cryptography definitions.
_SHARED_REFS = ("spdx.schema.json", "jsf-0.82.schema.json")


def _load_jsonschema():
    """The jsonschema stack, or None when it is not importable."""
    try:
        import jsonschema
        import referencing
        import referencing.jsonschema
        return jsonschema, referencing
    except ImportError:
        return None


def _schema_files(spec_version):
    return [f"bom-{spec_version}.schema.json"] + [
        *(_SHARED_REFS if spec_version != "1.7"
          else (*_SHARED_REFS, "cryptography-defs.schema.json"))]


def availability(spec_version):
    """None when schema validation can run, else the reason it cannot."""
    if spec_version not in SCHEMA_VERSIONS:
        return (f"no official CycloneDX {spec_version} schema is vendored "
                f"(supported: {', '.join(SCHEMA_VERSIONS)})")
    if _load_jsonschema() is None:
        return "the jsonschema Python package is not installed"
    missing = [name for name in _schema_files(spec_version)
               if not (SCHEMA_DIR / name).is_file()]
    if missing:
        return "vendored schema files are missing: " + ", ".join(missing)
    return None


#: Built validators, keyed by specification version.
_validators = {}


def validator(spec_version):
    """Draft-7 validator over the vendored schema set, or None."""
    cached = _validators.get(spec_version)
    if cached is not None:
        return cached
    if availability(spec_version) is not None:
        return None
    jsonschema, referencing = _load_jsonschema()
    documents = {
        path.resolve().as_uri(): json.loads(path.read_text())
        for path in (SCHEMA_DIR / name for name in _schema_files(spec_version))
    }
    registry = referencing.Registry().with_resources(
        (uri, referencing.Resource.from_contents(
            contents,
            default_specification=referencing.jsonschema.DRAFT7))
        for uri, contents in documents.items()
    )
    bom_uri = (SCHEMA_DIR / f"bom-{spec_version}.schema.json").resolve().as_uri()
    validator_instance = jsonschema.Draft7Validator(
        documents[bom_uri], registry=registry)
    _validators[spec_version] = validator_instance
    return validator_instance


def describe_errors(errors, limit=5):
    """First *limit* violations as compact, deterministically ordered
    `json-pointer: message` lines."""
    ordered = sorted(errors, key=lambda error: (list(error.absolute_path),
                                                error.message))
    lines = []
    for index, error in enumerate(ordered):
        if index >= limit:
            lines.append(f"... {len(ordered) - index} more")
            break
        pointer = "/".join(str(part) for part in error.absolute_path)
        lines.append(f"/{pointer}: {error.message[:200]}")
    return "\n".join(lines) if lines else "(none)"


def check(document, spec_version):
    """
    Validate *document* against the official schema of *spec_version*.

    Returns ``(status, diagnostics)`` where status is ``"valid"``,
    ``"invalid"`` (diagnostics lists the violations) or ``"unavailable"``
    (diagnostics names why validation did not run). A validator that
    cannot run never reports a verdict about the document.
    """
    reason = availability(spec_version)
    if reason is not None:
        return "unavailable", reason
    try:
        errors = list(validator(spec_version).iter_errors(document))
    except Exception as error:  # broken schema resolution: degrade honestly
        return "unavailable", f"schema validation failed to run: {error}"
    if not errors:
        return "valid", ""
    return "invalid", describe_errors(errors)

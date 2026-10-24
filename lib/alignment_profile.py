# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: Copyright (C) 2026 iris-GmbH infrared & intelligent sensors.

"""Versioned BSI TR-03183-2 alignment profiles and requirements matrix.

This module owns the project-owned alignment profile data: every supported
alignment profile names its exact profile baseline (the TR-03183-2 guideline
version, the BSI CycloneDX property taxonomy version and the supported
CycloneDX schema versions) and carries the versioned requirements matrix
that maps each normative requirement of that baseline to its CycloneDX
representation and evaluation rule.

The matrix is data, not control flow scattered through the renderer:
findings are produced by evaluating the rows against a rendered document.
Adding a requirement means adding a row here and bumping the matrix
version; a profile never floats to a later guideline, taxonomy or CycloneDX
schema.

meta-cyclonedx uses this to produce an alignment report; it never labels an
SBOM, product or manufacturer conformant with TR-03183-2 or the CRA.
"""

# Evaluation rules return a verdict for one requirement against one
# rendered document set; they live next to the rows they evaluate.


def _check_cyclonedx_format(context):
    sbom = context["sbom"]
    version = sbom.get("specVersion")
    if sbom.get("bomFormat") == "CycloneDX" and version in ("1.6", "1.7"):
        return "verified", (f"the SBOM is a CycloneDX JSON document at "
                            f"spec version {version}")
    return "unmet", (f"the SBOM is not a CycloneDX JSON document at spec "
                     f"version 1.6 or later (bomFormat {sbom.get('bomFormat')!r}, "
                     f"specVersion {version!r})")


def _check_sbom_creator(context):
    metadata = context["sbom"].get("metadata") or {}
    if metadata.get("authors"):
        return "verified", "the SBOM names its creator through metadata.authors"
    return "unmet", ("the SBOM does not identify an SBOM creator with an "
                     "email address or URL")


def _file_components(context):
    return [component for component in context["sbom"].get("components") or []
            if component.get("type") == "file"]


def _applies_file_components(context):
    if _file_components(context):
        return True, ""
    return False, ("the SBOM represents no file component, so the "
                   "file-component data field does not apply")


def _applies_always(context):
    return True, ""


def _property_presence(property_name):
    def check(context):
        missing = [component["bom-ref"] for component in _file_components(context)
                   if not any(p.get("name") == property_name
                              for p in component.get("properties") or [])]
        if not missing:
            return "verified", (f"every file component carries the "
                                f"{property_name} property")
        return "unmet", (f"file components lack the {property_name} property"), missing
    return check


def _check_file_hashes(context):
    missing = [component["bom-ref"] for component in _file_components(context)
               if not any(h.get("alg") == "SHA-512"
                          for h in component.get("hashes") or [])]
    if not missing:
        return "verified", "every file component carries a SHA-512 artifact hash"
    return "unmet", ("file components lack the required SHA-512 hash of the "
                     "deployable artifact"), missing


def _check_dependency_coverage(context):
    return "unverifiable", ("Yocto metadata and imported BOMs cannot establish "
                            "that every delivered or dynamically loaded "
                            "component has been discovered")


def _external_references(context, reference_types):
    sbom = context["sbom"]
    holders = [sbom.get("metadata", {}).get("component") or {}]
    holders.extend(sbom.get("components") or [])
    refs = []
    for holder in holders:
        for ref in holder.get("externalReferences") or []:
            if ref.get("type") in reference_types:
                refs.append(ref)
    return refs


def _applies_sbom_uri(context):
    if context["sbom"].get("uri") or _external_references(context, {"bom"}):
        return True, ""
    return False, ("the SBOM declares no canonical SBOM-URI, so the "
                   "conditional SBOM-URI field does not apply")


def _check_sbom_uri(context):
    return "verified", "the declared SBOM-URI is present"


def _uri_field(reference_types, label):
    def applies(context):
        if _external_references(context, reference_types):
            return True, ""
        return False, f"the SBOM carries no {label} URIs, so the field does not apply"

    def check(context):
        refs = _external_references(context, reference_types)
        if all(ref.get("url") for ref in refs):
            return "verified", f"every {label} URI carries a usable URL"
        return "unmet", f"{label} URIs lack a usable URL"
    return applies, check


_applies_source_uris, _check_source_uris = _uri_field({"vcs", "source-distribution"}, "source code")
_applies_deployable_uris, _check_deployable_uris = _uri_field({"distribution"}, "deployable form")


def _check_primary_component_assertion(context):
    primary = context["facts"].get("primary") or {}
    if primary.get("name") and primary.get("version") and primary.get("type"):
        return "asserted", ("the product integration asserts the primary "
                            "component type, name and version; creator-assigned "
                            "identity cannot be independently checked by "
                            "meta-cyclonedx")
    return "unmet", ("the product integration did not assert the primary "
                     "component type, name and version")


TR03183_2_REQUIREMENTS = [
    {
        "id": "REQ-FMT-001",
        "source": "BSI TR-03183-2 v2.1.0 §4 (format requirements)",
        "representation": "bomFormat CycloneDX with specVersion 1.6 or later",
        "origin": "generated-document",
        "check": _check_cyclonedx_format,
    },
    {
        "id": "REQ-SBOM-001",
        "source": ("BSI TR-03183-2 v2.1.0 §5.2.1 (SBOM-level data fields: "
                   "creator of SBOM)"),
        "representation": "metadata.authors entry with an email address or URL",
        "origin": "generated-document",
        "check": _check_sbom_creator,
    },
    {
        "id": "REQ-COMP-003",
        "source": ("BSI TR-03183-2 v2.1.0 \u00a75.2.2 (component-level data "
                   "fields: primary component name and version)"),
        "representation": ("metadata.component type, name and version "
                           "identifying the delivered product"),
        "origin": "caller-assertion",
        "check": _check_primary_component_assertion,
    },
    {
        "id": "REQ-DEPS-001",
        "source": ("BSI TR-03183-2 v2.1.0 §5.2.2 (component-level data "
                   "fields: dependencies)"),
        "representation": ("dependencies graph covering every delivered or "
                           "dynamically loaded component"),
        "origin": "external-evidence",
        "check": _check_dependency_coverage,
    },
    {
        "id": "REQ-COMP-004",
        "source": ("BSI TR-03183-2 v2.1.0 §5.2.2 (actual filename) and "
                   "§8.1 (bsi:component:filename)"),
        "representation": ("bsi:component:filename property on file "
                           "components"),
        "origin": "generated-document",
        "applies": _applies_file_components,
        "check": _property_presence("bsi:component:filename"),
    },
    {
        "id": "REQ-COMP-005",
        "source": ("BSI TR-03183-2 v2.1.0 §5.2.2 (executable property) and "
                   "§8.1 (bsi:component:executable)"),
        "representation": ("bsi:component:executable property on file "
                           "components"),
        "origin": "generated-document",
        "applies": _applies_file_components,
        "check": _property_presence("bsi:component:executable"),
    },
    {
        "id": "REQ-COMP-006",
        "source": ("BSI TR-03183-2 v2.1.0 §5.2.2 (archive property) and "
                   "§8.1 (bsi:component:archive)"),
        "representation": ("bsi:component:archive property on file components"),
        "origin": "generated-document",
        "applies": _applies_file_components,
        "check": _property_presence("bsi:component:archive"),
    },
    {
        "id": "REQ-COMP-007",
        "source": ("BSI TR-03183-2 v2.1.0 §5.2.2 (structured property) and "
                   "§8.1 (bsi:component:structured)"),
        "representation": ("bsi:component:structured property on file "
                           "components"),
        "origin": "generated-document",
        "applies": _applies_file_components,
        "check": _property_presence("bsi:component:structured"),
    },
    {
        "id": "REQ-COMP-008",
        "source": ("BSI TR-03183-2 v2.1.0 §5.2.2 (hash of the deployable "
                   "artifact)"),
        "representation": ("SHA-512 entry in file component hashes"),
        "origin": "generated-document",
        "applies": _applies_file_components,
        "check": _check_file_hashes,
    },
    {
        "id": "REQ-URI-001",
        "source": "BSI TR-03183-2 v2.1.0 §5.2.3 (SBOM-URI, conditional)",
        "representation": "declared canonical URI of the SBOM document",
        "origin": "generated-document",
        "applies": _applies_sbom_uri,
        "check": _check_sbom_uri,
    },
    {
        "id": "REQ-URI-002",
        "source": "BSI TR-03183-2 v2.1.0 §5.2.4 (source code URI, conditional)",
        "representation": ("vcs externalReferences of the primary and logical "
                           "components"),
        "origin": "generated-document",
        "applies": _applies_source_uris,
        "check": _check_source_uris,
    },
    {
        "id": "REQ-URI-003",
        "source": ("BSI TR-03183-2 v2.1.0 §5.2.4 (URI of the deployable "
                   "form, conditional)"),
        "representation": "distribution externalReferences of the components",
        "origin": "generated-document",
        "applies": _applies_deployable_uris,
        "check": _check_deployable_uris,
    },
]

PROFILES = {
    # The versioned TR-03183-2 alignment profile. The name carries the
    # exact baseline: an existing profile never moves to a newer guideline,
    # property taxonomy or CycloneDX schema.
    "tr03183-2.1": {
        "alignmentProfile": "tr03183-2.1",
        "guideline": "BSI TR-03183-2",
        "guidelineVersion": "2.1.0",
        "propertyTaxonomyVersion": "0.1.2",
        "requirementsMatrixVersion": "2.1.0-r1",
        "specVersions": ["1.6", "1.7"],
        "requirements": TR03183_2_REQUIREMENTS,
    },
}

# Supported alignment enforcement values: "report" publishes the documents
# and the alignment report despite known gaps; "strict" fails the build on
# every machine-detectable violation or missing required assertion.
ENFORCEMENT_VALUES = ["report", "strict"]


def evaluate(profile_id, spec_version, sbom, vex, facts):
    """
    Evaluate the requirements matrix of one alignment profile against the
    rendered documents and their facts.

    Returns (profile baseline, findings): the exact guideline, property
    taxonomy, CycloneDX schema and matrix versions used, and one finding
    per matrix row, ordered by requirement identifier.
    """
    profile = PROFILES[profile_id]
    baseline = {
        "guideline": profile["guideline"],
        "guidelineVersion": profile["guidelineVersion"],
        "propertyTaxonomyVersion": profile["propertyTaxonomyVersion"],
        "cyclonedxSchemaVersion": spec_version,
        "requirementsMatrixVersion": profile["requirementsMatrixVersion"],
    }
    findings = [_evaluate_requirement(row, spec_version, sbom, vex, facts)
                for row in profile["requirements"]]
    findings.sort(key=lambda finding: finding["requirementId"])
    return baseline, findings


def _evaluate_requirement(row, spec_version, sbom, vex, facts):
    """Turn one requirements-matrix row into one alignment report finding."""
    context = {"spec_version": spec_version, "sbom": sbom, "vex": vex,
               "facts": facts}
    applicability = "applicable"
    if row.get("applies"):
        applies, reason = row["applies"](context)
        if not applies:
            applicability = "not-applicable"
            result = ("unverifiable", reason)

    if applicability == "applicable":
        result = row["check"](context)

    verdict, message = result[0], result[1]
    finding = {
        "requirementId": row["id"],
        "normativeSource": row["source"],
        "cyclonedxRepresentation": row["representation"],
        "applicability": applicability,
        "verdict": verdict,
        "evidenceOrigin": row["origin"],
        "diagnosticMessage": message,
    }
    if len(result) > 2 and result[2]:
        finding["bomRefs"] = sorted(result[2])
    return finding

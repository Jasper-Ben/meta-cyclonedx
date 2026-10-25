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

import importlib
import importlib.util
import os
import re
import sys
import urllib.parse

# Identifier syntax rules, generous per ecosystem but strict about the
# envelopes downstream vulnerability tooling parses:
# - Package URL: pkg:<type>/[<namespace>/]<name>[@<version>][?<quals>][#<subpath>]
#   with percent-encoded segments (purl-spec).
_PURL = re.compile(
    r"^pkg:[A-Za-z][A-Za-z0-9.+-]*"
    r"(?:/(?:[A-Za-z0-9._~+-]|%[0-9A-Fa-f]{2})+)+"
    r"(?:@[^/?#]*)?(?:\?[^#]*)?(?:#.*)?$")
# - CPE 2.3 formatted binding: cpe:2.3: followed by exactly eleven
#   colon-separated fields, escapes allowed, no whitespace.
_CPE_23 = re.compile(r"^cpe:2\.3(?::[^:\s]*){11}$")
# - SHA-512: 512 bits of lowercase hexadecimal.
_SHA512_HEX = re.compile(r"^[0-9a-f]{128}$")
ALIAS_CPE_PROPERTY = "yocto:cve:cpe"
SHA512_ALGORITHM = "SHA-512"


def _hash_occurrences(sbom):
    """(holder ref or None, hash dict, misplaced) for every hash object
    naming SHA-512; misplaced means outside component/properties-holding
    components, i.e. not riding components[].hashes[]."""
    holders = {id(component): ref
               for ref, component in _taxonomy_property_holders(sbom)}
    occurrences = []

    def walk(node, holder_ref):
        if isinstance(node, dict):
            own_ref = holders.get(id(node))
            if own_ref is not None:
                holder_ref = own_ref
            if node.get("alg") == SHA512_ALGORITHM:
                occurrences.append((holder_ref, node, holder_ref is None))
            for value in node.values():
                walk(value, holder_ref)
        elif isinstance(node, list):
            for item in node:
                walk(item, holder_ref)

    walk(sbom, None)
    return occurrences


def _check_purl_syntax(context):
    invalid = sorted({
        ref for ref, component in _taxonomy_property_holders(
            context["sbom"])
        if component.get("purl")
        and not _PURL.match(str(component["purl"]))})
    if invalid:
        return ("unmet", "component purls are not valid Package URLs "
                         "(pkg:<type>/[<namespace>/]<name>[@<version>])",
                invalid)
    return ("verified", "every emitted purl parses as a Package URL")


def _check_cpe_syntax(context):
    invalid = set()
    for ref, component in _taxonomy_property_holders(context["sbom"]):
        cpe = component.get("cpe")
        if cpe and not _CPE_23.match(str(cpe)):
            invalid.add(ref)
        for prop in component.get("properties") or []:
            if (prop.get("name") == ALIAS_CPE_PROPERTY
                    and not _CPE_23.match(str(prop.get("value") or ""))):
                invalid.add(ref)
    named = sorted(ref for ref in invalid if ref)
    if invalid:
        return ("unmet", "CPE identifiers are not formatted CPE 2.3 "
                         "strings (cpe:2.3: with eleven fields)", named)
    return ("verified", "every emitted CPE is a formatted CPE 2.3 string")


def _check_sha512_syntax(context):
    misplaced = set()
    malformed = set()
    for ref, entry, is_misplaced in _hash_occurrences(context["sbom"]):
        if is_misplaced:
            misplaced.add(ref)
        elif not _SHA512_HEX.match(str(entry.get("content") or "")):
            malformed.add(ref)
    if misplaced or malformed:
        message = ("SHA-512 artifacts are not lowercase hex of 512 bits "
                   "riding components[].hashes[] under the SHA-512 "
                   "algorithm")
        if misplaced:
            message += ("; some occur outside components[]/hashes[] where "
                        "the TR places them")
        refs = sorted({ref for ref in (misplaced | malformed) if ref})
        return "unmet", message, refs
    return ("verified", "every SHA-512 is lowercase hex of 512 bits in "
                        "components[].hashes[] under the SHA-512 "
                        "algorithm")
import importlib.util
import os
import sys
import urllib.parse


def _schema_validation():
    """
    Load the shared CycloneDX schema-validation module that sits next to
    this file. Under BitBake the layer's lib directory is not on the
    worker's module search path, so fall back to loading by path, the way
    this module itself is loaded. That module feature-detects the optional
    jsonschema dependency and the vendored schemas: a validator that
    cannot run yields `unverifiable` verdicts, never a silent pass.
    """
    module = sys.modules.get("cyclonedx_schema_validation")
    if module is not None:
        return module
    try:
        return importlib.import_module("schema_validation")
    except ImportError:
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "schema_validation.py")
        spec = importlib.util.spec_from_file_location(
            "cyclonedx_schema_validation", path)
        module = importlib.util.module_from_spec(spec)
        sys.modules["cyclonedx_schema_validation"] = module
        spec.loader.exec_module(module)
        return module


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


# Every emitted SBOM and VEX is validated against the official schema of
# the selected CycloneDX version before publication.
def _document_schema_check(kind_label, document_key):
    def check(context):
        status, diagnostics = _schema_validation().check(
            context[document_key], context["spec_version"])
        if status == "valid":
            return ("verified",
                    f"the emitted {kind_label} validates against the "
                    f"official CycloneDX {context['spec_version']} JSON "
                    "schema")
        if status == "unavailable":
            return ("unverifiable",
                    f"schema validation of the {kind_label} cannot run "
                    f"({diagnostics}); the document is not assumed valid")
        return ("unmet",
                f"the emitted {kind_label} violates the official "
                f"CycloneDX {context['spec_version']} JSON schema: "
                f"{diagnostics}")
    return check


def _check_sbom_schema(context):
    return _document_schema_check("SBOM", "sbom")(context)


def _check_vex_schema(context):
    return _document_schema_check("VEX", "vex")(context)


# The pinned BSI CycloneDX property taxonomy registry (v0.1.2,
# https://github.com/tr-03183/tr-03183-cyclonedx-property-taxonomy tag
# 0.1.2), vendored verbatim under lib/data/ for provenance; the drift
# guard in tests/test_taxonomy_validation.py keeps this registry and
# that document naming exactly the same properties. The registry only
# allows these properties in components[]/properties and
# metadata/component/properties; per-component presence rules are the
# registry's own wording ("MUST occur exactly once per component" when
# the property is used, filename "at most once").
BSI_TAXONOMY_VERSION = "0.1.2"
BSI_TAXONOMY_NAMESPACE = "bsi:"
BSI_TAXONOMY = {
    "bsi:component:executable":
        {"values": ("executable", "non-executable")},
    "bsi:component:archive":
        {"values": ("archive", "no archive")},
    "bsi:component:structured":
        {"values": ("structured", "unstructured")},
    "bsi:component:filename":
        {"values": None, "atMostOnce": True, "bareFilename": True},
    "bsi:component:effectiveLicence":
        {"values": None, "atMostOnce": True},
    # Registered in v0.1.2 but deprecated (spelled for TR v2.0.0).
    "bsi:component:associatedLicences":
        {"values": None, "atMostOnce": True},
}
# The classifiable-file triple: when one of these applies to a
# component, the registry expects all three, exactly once each.
BSI_TAXONOMY_CLASSIFIABLE_TRIPLE = ("bsi:component:executable",
                                    "bsi:component:archive",
                                    "bsi:component:structured")


def _taxonomy_property_holders(sbom):
    """Every component property holder the registry allows: the primary
    component and every components[] entry (recursively). The primary
    component's bom-ref is document-random and never named in findings."""
    holders = [(None, (sbom.get("metadata") or {}).get("component") or {})]
    stack = list(sbom.get("components") or [])
    while stack:
        component = stack.pop()
        if not isinstance(component, dict):
            continue
        holders.append((component.get("bom-ref"), component))
        stack.extend(entry for entry in component.get("components") or []
                     if isinstance(entry, dict))
    return holders


def _taxonomy_property_occurrences(sbom):
    """(holder ref or None, property dict, misplaced) for every bsi:
    property entry in the document, misplaced ones named by their
    containing location instead of a component."""
    occurrences = []
    holders = {id(component): ref
               for ref, component in _taxonomy_property_holders(sbom)}

    def walk(node, holder_ref):
        if isinstance(node, dict):
            own_ref = holders.get(id(node))
            if own_ref is not None:
                holder_ref = own_ref
            for key, value in node.items():
                if key == "properties" and isinstance(value, list):
                    for prop in value:
                        if (isinstance(prop, dict) and str(
                                prop.get("name") or "").startswith(
                                    BSI_TAXONOMY_NAMESPACE)):
                            occurrences.append(
                                (holder_ref, prop, holder_ref is None))
                else:
                    walk(value, holder_ref)
        elif isinstance(node, list):
            for item in node:
                walk(item, holder_ref)

    walk(sbom, None)
    return occurrences


def _check_taxonomy_registry(context):
    occurrences = _taxonomy_property_occurrences(context["sbom"])
    offending = [(ref, str(prop.get("name")), misplaced)
                 for ref, prop, misplaced in occurrences
                 if misplaced or prop.get("name") not in BSI_TAXONOMY]
    if offending:
        names = sorted({name for _ref, name, _misplaced in offending})
        message = ("the document carries bsi: properties the pinned "
                   f"v{BSI_TAXONOMY_VERSION} taxonomy does not register "
                   "here: " + ", ".join(names))
        if any(misplaced for _ref, _name, misplaced in offending):
            message += ("; registered properties may only appear in "
                        "components[]/properties or "
                        "metadata/component/properties")
        refs = sorted({ref for ref, _name, _misplaced in offending if ref})
        return "unmet", message, refs
    return ("verified",
            f"every bsi: property in the document is registered in the "
            f"pinned v{BSI_TAXONOMY_VERSION} taxonomy and placed where "
            "the registry allows")


def _check_taxonomy_values(context):
    violations = []
    for ref, prop, misplaced in _taxonomy_property_occurrences(
            context["sbom"]):
        if misplaced:
            continue  # placement is REQ-TAX-001's verdict
        spec = BSI_TAXONOMY.get(prop.get("name"))
        if spec is None:
            continue  # unknown properties are REQ-TAX-001's verdict
        value = prop.get("value")
        bad = not isinstance(value, str) or not value.strip()
        if not bad and spec["values"] and value not in spec["values"]:
            bad = True
        if (not bad and spec.get("bareFilename")
                and ("/" in value or "\\" in value)):
            bad = True
        if bad:
            violations.append((ref, prop.get("name"), value))
    if violations:
        detail = sorted({f"{name}={value!r}"
                         for _ref, name, value in violations})
        refs = sorted({ref for ref, _name, _value in violations if ref})
        return ("unmet", "the document carries taxonomy property values "
                         "outside the pinned registry's value domains: "
                         + ", ".join(detail), refs)
    return ("verified", "every registered taxonomy property value is a "
                        "non-empty string inside the registry's value "
                        "domain")


def _check_taxonomy_cardinality(context):
    violations = []
    for ref, component in _taxonomy_property_holders(context["sbom"]):
        names = [prop.get("name")
                 for prop in component.get("properties") or []
                 if prop.get("name") in BSI_TAXONOMY]
        if not names:
            continue
        counts = {name: names.count(name) for name in set(names)}
        violated = any(count > 1 for name, count in counts.items()
                       if BSI_TAXONOMY[name].get("atMostOnce"))
        triple_present = [name for name in BSI_TAXONOMY_CLASSIFIABLE_TRIPLE
                          if counts.get(name, 0)]
        if triple_present:
            violated = violated or any(counts.get(name, 0) != 1
                                       for name
                                       in BSI_TAXONOMY_CLASSIFIABLE_TRIPLE)
        if violated:
            violations.append(ref)
    if violations:
        named = sorted({ref for ref in violations if ref})
        message = ("taxonomy properties violate the pinned registry's "
                   "cardinality: properties that must occur at most once "
                   "per component repeat, or a partial executable/archive/"
                   "structured triple occurs where one of them applies")
        return "unmet", message, named
    return ("verified", "every component's registered taxonomy properties "
                        "obey the pinned registry's cardinality: the "
                        "classifiable triple occurs complete exactly once, "
                        "filename and licence properties at most once")


def _check_sbom_creator(context):
    metadata = context["sbom"].get("metadata") or {}
    if metadata.get("authors"):
        return "asserted", ("the product integration asserts the SBOM "
                            "creator through metadata.authors; the contact "
                            "of the asserting party cannot be independently "
                            "checked by meta-cyclonedx")
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


# Mandatory file inventory (TR-03183-2 v2.1.0 §3.2.1 and §5.2.2): the
# delivered executables and archives must reach the document as exact
# file components, defective artifacts must be reported instead of
# vanishing, and every file component must sit traceably in the graph.
def _file_inventory_entries(context):
    return ((context.get("graph") or {}).get("fileInventory")
            or {}).get("entries") or []


def _applies_file_inventory(context):
    if _file_inventory_entries(context) or _file_components(context):
        return True, None
    return False, ("the build recorded no delivered-file artifact facts "
                   "and the document contains no file components; the "
                   "mandatory file inventory does not apply")


def _check_file_inventory_coverage(context):
    entries = _file_inventory_entries(context)
    entry_refs = {entry["ref"] for entry in entries}
    component_refs = {component["bom-ref"]
                      for component in _file_components(context)}
    delivered = {entry["ref"] for entry in entries if not entry.get("error")}
    unrepresented = sorted(delivered - component_refs)
    unattributed = sorted(component_refs - entry_refs)
    if not unrepresented and not unattributed:
        return "verified", ("every delivered mandatory artifact is "
                            "represented by exactly one file component")
    paths = {entry["ref"]: entry["path"] for entry in entries}
    parts = []
    if unrepresented:
        parts.append("mandatory delivered artifacts are not represented as "
                     "file components: "
                     + ", ".join(paths.get(ref, ref) for ref in unrepresented))
    if unattributed:
        parts.append("file components have no delivered-file artifact "
                     "fact: " + ", ".join(unattributed))
    return "unmet", "; ".join(parts), unrepresented + unattributed


def _check_file_artifact_inspection(context):
    defective = [entry for entry in _file_inventory_entries(context)
                 if entry.get("error")]
    if not defective:
        return "verified", ("every inventoried mandatory artifact was "
                            "readable and classified deterministically")
    return ("unmet",
            "mandatory delivered artifacts lack a verifiable artifact "
            "identity: "
            + ", ".join(f"{entry['path']} ({entry['error']})"
                        for entry in defective),
            [entry["ref"] for entry in defective],
            "artifact-inspection")


# Deploy-directory evidence (ticket #10): the primary deployable
# artifact is mandatory inventory under the profile even though no
# package manifest names it, and the product integration can explicitly
# select additional delivered payloads. A selection or artifact that
# resolves to nothing stays an affected-file finding (ADR-0004).
def _deploy_evidence_entries(context, source):
    return [entry for entry in _file_inventory_entries(context)
            if entry.get("source") == source]


def _applies_deployable_inventory(context):
    if _deploy_evidence_entries(context, "deployable"):
        return True, None
    return False, ("this export recorded no primary deployable artifact "
                   "evidence; there is no deploy-directory delivery to "
                   "represent")


def _check_deployable_coverage(context):
    entries = _deploy_evidence_entries(context, "deployable")
    defective = [entry for entry in entries if entry.get("error")]
    if not defective:
        return "verified", ("the primary deployable artifact is "
                            "represented as an exact file component of "
                            "the delivery")
    return ("unmet",
            "the primary deployable artifact lacks a verifiable artifact "
            "identity: "
            + ", ".join(f"{entry['path']} ({entry['error']})"
                        for entry in defective),
            [entry["ref"] for entry in defective],
            "artifact-inspection")


def _applies_selected_files(context):
    if _deploy_evidence_entries(context, "selected"):
        return True, None
    return False, ("the product integration selected no additional "
                   "deployed files; the selection requirement does not "
                   "apply")


def _check_selected_files(context):
    entries = _deploy_evidence_entries(context, "selected")
    defective = [entry for entry in entries if entry.get("error")]
    if not defective:
        return "verified", ("every explicitly selected additional file "
                            "is represented as an exact file component")
    return ("unmet",
            "selected additional files are not inventoried: "
            + ", ".join(f"{entry['path']} ({entry['error']})"
                        for entry in defective),
            [entry["ref"] for entry in defective],
            "artifact-inspection")


def _check_file_component_graph(context):
    refs = [component["bom-ref"]
            for component in _file_components(context)]
    counts = {}
    referenced = set()
    for entry in context["sbom"].get("dependencies") or []:
        if entry.get("ref"):
            counts[entry["ref"]] = counts.get(entry["ref"], 0) + 1
        referenced.update(entry.get("dependsOn") or [])
    violations = sorted(
        {ref for ref in refs
         if not ref or counts.get(ref) != 1 or ref not in referenced}
        | {ref for ref in refs if ref and refs.count(ref) > 1})
    if violations:
        return ("unmet",
                "file components lack a unique bom-ref, exactly one "
                "dependency entry or a traceable owning component",
                violations)
    return "verified", ("every file component has a unique bom-ref, exactly "
                        "one dependency entry and a traceable owning "
                        "component")


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


def _uri_is_valid(uri):
    """Independent document-side validation of an emitted URI's syntax."""
    if not isinstance(uri, str) or not uri.strip():
        return False
    try:
        parsed = urllib.parse.urlparse(uri.strip())
    except ValueError:
        return False
    if parsed.scheme.lower() == "mailto":
        return bool(parsed.path or parsed.netloc)
    return bool(parsed.scheme and parsed.netloc)


def _emitted_uri_references(context, reference_types):
    sbom = context["sbom"]
    metadata_component = ((sbom.get("metadata") or {}).get("component") or {})
    holders = [(metadata_component.get("bom-ref"), metadata_component)]
    holders.extend((component.get("bom-ref"), component)
                   for component in sbom.get("components") or [])
    return [(reference, holder_ref)
            for holder_ref, holder in holders
            for reference in holder.get("externalReferences") or ()
            if reference.get("type") in reference_types]


def _recorded_uri_candidates(context, reference_types, fact_keys):
    """Every URI of the category the build facts recorded, per holder."""
    facts = context["facts"]
    sbom = context["sbom"]
    primary = facts.get("primary") or {}
    primary_ref = ((sbom.get("metadata") or {}).get("component") or {}) \
        .get("bom-ref")
    candidates = [(primary.get(key), primary_ref) for key in fact_keys
                  if primary.get(key)]
    candidates += [(reference.get("url"), primary_ref)
                   for reference in primary.get("external_references") or ()
                   if reference.get("type") in reference_types]
    for fragment in (facts.get("fragments") or {}).values():
        contributors = (list(fragment.get("pkgs") or [])
                        + list(fragment.get("extra_components") or []))
        first_ref = contributors[0].get("bom-ref") if contributors else None
        candidates += [(fragment.get(key), first_ref) for key in fact_keys
                       if fragment.get(key)]
        for component in contributors:
            candidates += [(reference.get("url"), component.get("bom-ref"))
                           for reference
                           in component.get("externalReferences") or ()
                           if reference.get("type") in reference_types]
    for image in facts.get("included_images") or ():
        document = image.get("sbom") or {}
        components = [((document.get("metadata") or {}).get("component")
                       or {})]
        components += list(document.get("components") or [])
        for component in components:
            candidates += [(reference.get("url"), component.get("bom-ref"))
                           for reference
                           in component.get("externalReferences") or ()
                           if reference.get("type") in reference_types]
    return candidates


def _uri_field(reference_types, fact_keys, label):
    def applies(context):
        emitted = {reference.get("url")
                   for reference, _ref
                   in _emitted_uri_references(context, reference_types)}
        rejected = [holder_ref for url, holder_ref
                    in _recorded_uri_candidates(context, reference_types,
                                                fact_keys)
                    if url and url not in emitted]
        if emitted or rejected:
            return True, ""
        return False, (f"the SBOM carries no {label} URIs, so the field "
                       f"does not apply")

    def check(context):
        emitted = _emitted_uri_references(context, reference_types)
        emitted_urls = {reference.get("url") for reference, _ref in emitted}
        rejected = [holder_ref for url, holder_ref
                    in _recorded_uri_candidates(context, reference_types,
                                                fact_keys)
                    if url and url not in emitted_urls]
        invalid = [holder_ref for reference, holder_ref in emitted
                   if not _uri_is_valid(reference.get("url"))]
        affected = sorted({holder for holder in rejected + invalid
                           if holder})
        if affected:
            return ("unmet", (f"{label} URIs were recorded as evidence but "
                              f"not emitted, or carry a syntactically "
                              f"invalid URL; URIs are emitted only from "
                              f"trustworthy metadata and are validated "
                              f"when present"), affected)
        return "verified", f"every {label} URI carries a usable URL"
    return applies, check


_applies_source_uris, _check_source_uris = _uri_field(
    {"vcs", "source-distribution"}, ("source_uri",), "source code")
_applies_deployable_uris, _check_deployable_uris = _uri_field(
    {"distribution"}, ("deployable_uri",), "deployable form")


def _check_primary_component_creator(context):
    primary = (context["sbom"].get("metadata") or {}).get("component") or {}
    if primary.get("author") or primary.get("authors"):
        return "asserted", ("the product integration asserts the primary "
                            "component creator; meta-cyclonedx cannot "
                            "independently verify the manufacturer's "
                            "identity")
    return "unmet", ("the product integration did not assert a creator for "
                     "the primary component")


def _check_component_names(context):
    missing = [component["bom-ref"]
               for component in context["sbom"].get("components") or []
               if not component.get("name")]
    if not missing:
        return "verified", "every component carries a component name"
    return "unmet", "components lack a component name", missing


def _check_component_versions(context):
    missing = [component["bom-ref"]
               for component in context["sbom"].get("components") or []
               if not component.get("version")
               or component.get("version") == "unknown"]
    if not missing:
        return "verified", ("every component carries a usable component "
                            "version")
    return "unmet", ("components carry no usable component version (empty or "
                     "the unknown placeholder)"), missing


def _check_sbom_timestamp(context):
    if (context["sbom"].get("metadata") or {}).get("timestamp"):
        return "verified", "the SBOM records the generation timestamp"
    return "unmet", "the SBOM carries no generation timestamp"


def _check_dependency_completeness_declaration(context):
    sbom = context["sbom"]
    if "dependencies" not in sbom:
        return "unmet", "the SBOM carries no dependency graph"
    counts = {"complete": 0, "incomplete": 0, "unknown": 0}
    declared = set()
    undeclared = []
    for composition in sbom.get("compositions") or []:
        aggregate = composition.get("aggregate")
        assemblies = composition.get("assemblies") or []
        if aggregate not in counts:
            undeclared.extend(assemblies)
            continue
        counts[aggregate] += len(assemblies)
        declared.update(assemblies)
    missing = sorted({component["bom-ref"]
                      for component in sbom.get("components") or []
                      if component.get("bom-ref")
                      and component["bom-ref"] not in declared}
                     | set(undeclared))
    if missing:
        return "unmet", ("dependency completeness is undeclared, or declared "
                         "with an aggregate outside complete/incomplete/"
                         "unknown, for these components"), missing
    summary = ", ".join(f"{counts[aggregate]} {aggregate}"
                        for aggregate in ("complete", "incomplete", "unknown"))
    return "verified", ("the dependency graph declares its completeness "
                        f"through CycloneDX composition data ({summary})")


def _check_component_creators(context):
    override_refs = {component.get("bom-ref")
                     for fragment in (context["facts"].get("fragments")
                                      or {}).values()
                     if fragment.get("creator")
                     for component in fragment.get("pkgs") or ()}
    # Applicability is component-category aware (TR-03183-2 v2.1.0 §5.2.2):
    # file components carry artifact identity, not a creator of their own.
    components = [component
                  for component in context["sbom"].get("components") or []
                  if component.get("type") != "file"]
    missing = [component["bom-ref"] for component in components
               if not component.get("author") and not component.get("authors")]
    if missing:
        return ("unverifiable",
                ("components carry no creator identifiable by email address "
                 "or URL; upstream metadata records none and no explicit "
                 "override was supplied; the product manufacturer is never "
                 "assumed as the creator of third-party software"), missing)
    if override_refs & {component["bom-ref"] for component in components}:
        return ("asserted",
                ("every component carries a creator, at least one of them "
                 "asserted through an explicit override, which "
                 "meta-cyclonedx cannot verify independently"),
                None, "caller-assertion")
    return ("verified",
            ("every component carries a creator derived from trustworthy "
             "upstream identity metadata"), None, "upstream-metadata")


# Components the licence-role requirements evaluate: the delivered
# logical components and the primary component. Identified boundary
# components outside the scope of delivery only carry creator, name,
# version and identifiers (TR-03183-2 v2.1.0 §3.2.4), and file
# components carry artifact identity without licence claims of their
# own (TR-03183-2 v2.1.0 §3.2.1); neither category is a licence
# subject. The primary component is evaluated too, but its bom-ref is
# generated per document and never named in findings.
DELIVERY_SCOPE_MARKER = "yocto:delivery:scope"


def _licence_components(context):
    return [(component.get("bom-ref"), component)
            for component in context["sbom"].get("components") or []
            if component.get("type") != "file"
            and not any(p.get("name") == DELIVERY_SCOPE_MARKER
                        for p in component.get("properties") or [])]


def _primary_component(context):
    return (context["sbom"].get("metadata") or {}).get("component") or {}


def _licences_with_acknowledgement(component, acknowledgement):
    def has_acknowledgement(entry):
        if entry.get("acknowledgement") == acknowledgement:
            return True
        license_field = entry.get("license")
        return (isinstance(license_field, dict)
                and license_field.get("acknowledgement") == acknowledgement)

    return any(has_acknowledgement(entry)
               for entry in component.get("licenses") or [])


def _check_original_licences(context):
    missing = [ref for ref, component in _licence_components(context)
               if not _licences_with_acknowledgement(component, "declared")]
    primary_gap = not _licences_with_acknowledgement(
        _primary_component(context), "declared")
    if not missing and not primary_gap:
        return ("verified", "every delivered component and the primary "
                            "component carry creator-assigned (declared) "
                            "original licence evidence")
    message = ("components lack original licence evidence: no "
               "creator-assigned (declared) licence entry from recipe "
               "metadata")
    if primary_gap:
        message += ", including the primary component"
    return "unmet", message, missing



# The effective licence property name from the pinned property taxonomy
# v0.1.2 (registry spelling; the TR-03183-2 v2.1.0 PDF carries a
# "License" spelling variant of the same property).
EFFECTIVE_LICENCE_PROPERTY = "bsi:component:effectiveLicence"


def _check_distribution_licences(context):
    missing = [ref for ref, component in _licence_components(context)
               if not _licences_with_acknowledgement(component, "concluded")]
    primary_gap = not _licences_with_acknowledgement(
        _primary_component(context), "concluded")
    if not missing and not primary_gap:
        return ("asserted", "every delivered component carries an explicitly "
                            "supplied distribution licence; caller "
                            "assertions are never upgraded to verified")
    message = ("no semantically authoritative distribution licence source "
               "supplied; recipe LICENSE is original licence evidence only "
               "and is never relabelled as a distribution licence")
    if primary_gap:
        message += ", including the primary component"
    return "unmet", message, missing


def _effective_licence_matches(component):
    return [p for p in component.get("properties") or []
            if p.get("name") == EFFECTIVE_LICENCE_PROPERTY]


def _applies_effective_licences(context):
    supplied = any(_effective_licence_matches(component)
                   for _ref, component in _licence_components(context))
    supplied = supplied or _effective_licence_matches(
        _primary_component(context))
    if supplied:
        return True, ""
    return False, ("the optional effective-licence field was not supplied "
                   "by the product integration; the generator infers none")


def _check_effective_licences(context):
    violations = []
    for ref, component in _licence_components(context):
        matches = _effective_licence_matches(component)
        if len(matches) > 1 or (matches
                                and not all(p.get("value") for p in matches)):
            violations.append(ref)
    if violations:
        return ("unmet", "the effective licence must occur exactly once per "
                         "component with a licence expression", violations)
    return ("asserted", "the effective licences recorded on the components "
                        "were explicitly supplied by the SBOM creator; "
                        "caller assertions are never upgraded to verified")


def _check_no_vulnerability_data_in_sbom(context):
    """Vulnerability data may hide at any depth: a top-level key, an
    embedded image subtree copied verbatim into a component, a nested
    components[] entry. The renderer copies foreign subtrees verbatim
    (never repairs them), so the scan is document-wide."""
    occurrences = _vulnerability_nodes(context["sbom"])
    offenders = sorted({ref for ref, _node in occurrences if ref})
    if offenders or any(ref is None for ref, _node in occurrences):
        message = ("the SBOM embeds vulnerability records at one or more "
                   "places; vulnerability status belongs in the separate "
                   "VEX document")
        if offenders:
            message += " - within components " + ", ".join(offenders)
        return "unmet", message, offenders
    return ("verified", "the SBOM carries no vulnerability data at any "
                        "depth; status lives in the separate VEX document")


def _vulnerability_nodes(node, current_ref=None, seen=None):
    """(owning bom-ref, value) for every `vulnerabilities` subtree in
    the document, at any depth."""
    if seen is None:
        seen = set()
    found = []
    if id(node) in seen:
        return found
    seen.add(id(node))
    if isinstance(node, dict):
        ref = node.get("bom-ref") or current_ref
        if "vulnerabilities" in node:
            found.append((ref, node["vulnerabilities"]))
        for value in node.values():
            found.extend(_vulnerability_nodes(value, ref, seen))
    elif isinstance(node, list):
        for item in node:
            found.extend(_vulnerability_nodes(item, current_ref, seen))
    return found


def _check_vex_targets_logical_components(context):
    """Every VEX assertion must resolve to a logical component of the
    product SBOM; files are delivery detail, never vulnerability
    subjects."""
    components = {ref: component
                  for ref, component in _taxonomy_property_holders(
                      context["sbom"]) if ref}
    dangling = set()
    file_targets = set()
    for statement in (context.get("vex") or {}).get(
            "vulnerabilities") or []:
        for affect in statement.get("affects") or []:
            ref = affect.get("ref")
            if not isinstance(ref, str) or not ref:
                continue
            ref = ref.rpartition("#")[2] or ref
            component = components.get(ref)
            if component is None:
                dangling.add(ref)
            elif component.get("type") == "file":
                file_targets.add(ref)
    if dangling or file_targets:
        problems = []
        if dangling:
            problems.append("reference(s) that the SBOM does not define")
        if file_targets:
            problems.append("assertion(s) against file components, which "
                            "are delivery detail and not vulnerability "
                            "subjects")
        return ("unmet", "the VEX carries " + " and ".join(problems),
                sorted(dangling | file_targets))
    return ("verified", "every VEX assertion resolves to a logical "
                        "component of the product SBOM")


def _check_logical_identity_collisions(context):
    collisions = context.get("collisions") or []
    unexplained = [collision for collision in collisions
                   if not collision["explained"]]
    if unexplained:
        refs = sorted({ref for collision in unexplained
                       for ref in collision["bomRefs"]})
        return "unmet", ("component instances share CPE correlation "
                         "identifiers with identical artifact, build, "
                         "dependency, licence and vulnerability evidence; "
                         "CPE equality never deduplicates components, so "
                         "each collision must be resolved"), refs
    if collisions:
        return "verified", (f"{len(collisions)} CPE collision group(s) are "
                            "distinct component instances on differing "
                            "artifact, build, dependency, licence or "
                            "vulnerability evidence")
    return "verified", ("no component instance shares a CPE correlation "
                        "identifier with another")


def _check_graph_root(context):
    sbom = context["sbom"]
    root_ref = ((sbom.get("metadata") or {}).get("component") or {}) \
        .get("bom-ref")
    entry_refs = [entry.get("ref")
                  for entry in sbom.get("dependencies") or []]
    if (root_ref and entry_refs and entry_refs[0] == root_ref
            and entry_refs.count(root_ref) == 1):
        return "verified", ("the delivered primary component is the unique "
                            "root of the dependency graph")
    return "unmet", ("the dependency graph does not declare the primary "
                     "component as its unique root"), \
        ([root_ref] if root_ref else [])


def _check_dependency_entries(context):
    components = context["sbom"].get("components") or []
    counts = {}
    for entry in context["sbom"].get("dependencies") or []:
        ref = entry.get("ref")
        if ref:
            counts[ref] = counts.get(ref, 0) + 1
    without_ref = [component for component in components
                   if not component.get("bom-ref")]
    without_entry = sorted({component["bom-ref"] for component in components
                            if component.get("bom-ref")
                            and counts.get(component["bom-ref"]) != 1})
    if without_ref or without_entry:
        message = ("components lack a bom-ref or a unique dependency entry; "
                   "leaves carry an empty dependency list, so a missing "
                   "entry is a defect, not a leaf")
        if without_ref:
            message += (f" ({len(without_ref)} component(s) carry no "
                        "bom-ref)")
        return "unmet", message, without_entry
    return "verified", ("every component bom-ref appears exactly once in the "
                        "dependency graph")


def _check_scope_of_delivery_resolution(context):
    graph = context.get("graph") or {}
    boundary = (graph.get("boundaryRefs") or []) + \
        ((graph.get("integrity") or {}).get("dangling") or [])
    if boundary:
        return "unverifiable", ("dependency paths cross into components "
                                "outside the scope of delivery or reference "
                                "missing nodes; resolution beyond that point "
                                "is unknown and is not claimed"), \
            sorted(set(boundary))
    return "verified", ("every known dependency path resolved to a "
                        "represented component")


def _check_static_link_coverage(context):
    """Coverage state of the pkgdata debug-source evidence lane; per
    component, missing records already yield unverifiable compositions
    (CycloneDX aggregate `unknown`), never absent claims (ADR-0004)."""
    graph = context.get("graph") or {}
    coverage = ((graph.get("dependencyEvidence") or {})
                .get("pkgdataDebugSources") or {}).get("coverage")
    unknown = graph.get("staticUnknownRefs") or []
    if coverage == "partial" or unknown:
        return ("unverifiable",
                "pkgdata debug-source records cover only part of the "
                "delivered recipes, so static linking for the rest is "
                "unknown coverage, never an absence-of-dependencies "
                "claim", unknown)
    if coverage != "complete":
        return ("unverifiable",
                "the build recorded no usable pkgdata debug-source "
                "records for the delivered recipes; static linking is "
                "unknown coverage, never an absence-of-dependencies "
                "claim")
    return "verified", ("every delivered recipe's pkgdata debug-source "
                        "records were consumed for static-link attribution")


def _dependency_evidence_source(lane, verdict_of):
    def check(context):
        evidence = ((context.get("graph") or {}).get("dependencyEvidence")
                    or {}).get(lane) or {}
        return verdict_of(evidence.get("coverage"), evidence)
    return check


def _runtime_evidence_verdict(coverage, _evidence):
    if coverage == "observed":
        return ("verified", "Yocto runtime dependency metadata supplied "
                            "observed installed-package edges for the "
                            "dependency graph")
    return ("unverifiable", "the build recorded no runtime dependency "
                            "metadata; edges from that source are unknown "
                            "coverage, never assumed")


def _imported_evidence_verdict(coverage, evidence):
    defects = evidence.get("defects") or 0
    if coverage == "used":
        message = ("imported ecosystem BOM graphs contributed their "
                   "authored dependency structure to the graph")
        if defects:
            message += (f"; {defects} defective imported input(s) are "
                        "judged by the composition finding, not hidden")
        return "verified", message
    message = ("no usable ecosystem BOM dependency graphs were imported "
               "for this build; that source contributed no coverage")
    if defects:
        message += (f"; {defects} defective imported input(s) are judged "
                    "by the composition finding, not hidden")
    return "unverifiable", message


def _check_reference_integrity(context):
    integrity = (context.get("graph") or {}).get("integrity") or {}
    problems = []
    if integrity.get("duplicates"):
        problems.append("duplicate bom-ref values")
    if integrity.get("dangling"):
        problems.append("dangling dependency references")
    if integrity.get("ambiguous"):
        problems.append("components unreachable from the primary component "
                        "leave the dependency-graph root ambiguous")
    if problems:
        refs = sorted({ref for group in integrity.values() for ref in group})
        return "unmet", ("the graph carries " + ", ".join(problems) +
                         "; references are reported, never silently "
                         "repaired"), refs
    return "verified", ("every bom-ref is unique and every dependency "
                        "reference resolves inside the graph")


def _check_imported_embedded_composition(context):
    defects = (context.get("graph") or {}).get("mergeDefects") or []
    if defects:
        detail = "; ".join(f"{d['source']}: {d['message']}" for d in defects)
        refs = sorted({ref for d in defects for ref in d.get("refs") or ()})
        return "unmet", ("imported or embedded BOM composition hit "
                         "defective input: " + detail +
                         "; all usable evidence was composed and the "
                         "defect is reported, never silently "
                         "truncated"), refs
    return "verified", ("imported ecosystem BOMs and embedded image BOMs "
                        "composed their component instances, dependency "
                        "edges, scopes and VEX references without loss")


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
        "id": "REQ-FMT-002",
        "source": ("BSI TR-03183-2 v2.1.0 §4 (CycloneDX format: schema-"
                   "valid documents)"),
        "representation": ("the SBOM validates against the official "
                           "CycloneDX JSON schema of the selected version"),
        "origin": "generated-document",
        "check": _check_sbom_schema,
    },
    {
        "id": "REQ-FMT-003",
        "source": ("BSI TR-03183-2 v2.1.0 §4 (CycloneDX format: schema-"
                   "valid documents)"),
        "representation": ("the VEX validates against the official "
                           "CycloneDX JSON schema of the selected version"),
        "origin": "generated-document",
        "check": _check_vex_schema,
    },
    {
        "id": "REQ-TAX-001",
        "source": ("BSI TR-03183-2 v2.1.0 \u00a78.1 (property taxonomy "
                   "v0.1.2: registered properties and allowed locations)"),
        "representation": ("every bsi: property is registered in the "
                           "pinned taxonomy and appears only in "
                           "components[]/properties or "
                           "metadata/component/properties"),
        "origin": "generated-document",
        "check": _check_taxonomy_registry,
    },
    {
        "id": "REQ-TAX-002",
        "source": ("BSI TR-03183-2 v2.1.0 \u00a78.1 (property taxonomy "
                   "v0.1.2: property value domains)"),
        "representation": ("registered property values are non-empty "
                           "strings inside the registry's value domains "
                           "(executable/non-executable, archive/no "
                           "archive, structured/unstructured, bare "
                           "filenames, licence expressions)"),
        "origin": "generated-document",
        "check": _check_taxonomy_values,
    },
    {
        "id": "REQ-TAX-003",
        "source": ("BSI TR-03183-2 v2.1.0 \u00a78.1 (property taxonomy "
                   "v0.1.2: per-component cardinality)"),
        "representation": ("per component: the executable/archive/"
                           "structured triple occurs complete exactly "
                           "once when it applies; filename, effective"
                           "Licence and associatedLicences occur at most "
                           "once"),
        "origin": "generated-document",
        "check": _check_taxonomy_cardinality,
    },
    {
        "id": "REQ-SBOM-001",
        "source": ("BSI TR-03183-2 v2.1.0 §5.2.1 (SBOM-level data fields: "
                   "creator of SBOM)"),
        "representation": "metadata.authors entry with an email address or URL",
        "origin": "caller-assertion",
        "check": _check_sbom_creator,
    },
    {
        "id": "REQ-COMP-001",
        "source": ("BSI TR-03183-2 v2.1.0 §5.2.2 (component-level data "
                   "fields: component name)"),
        "representation": "components[].name",
        "origin": "generated-document",
        "check": _check_component_names,
    },
    {
        "id": "REQ-COMP-002",
        "source": ("BSI TR-03183-2 v2.1.0 §5.2.2 (component-level data "
                   "fields: component version)"),
        "representation": "components[].version",
        "origin": "generated-document",
        "check": _check_component_versions,
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
        "id": "REQ-COMP-012",
        "source": ("BSI TR-03183-2 v2.1.0 \u00a75.2.2 (component-level data "
                   "fields: primary component creator)"),
        "representation": ("metadata.component authors contacts (or the "
                           "author name) with an email address or URL"),
        "origin": "caller-assertion",
        "check": _check_primary_component_creator,
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
        "id": "REQ-DEPS-002",
        "source": ("BSI TR-03183-2 v2.1.0 §5.2.2 (component-level data "
                   "fields: dependency graph root)"),
        "representation": ("dependencies graph rooted at the primary "
                           "metadata.component bom-ref"),
        "origin": "generated-document",
        "check": _check_graph_root,
    },
    {
        "id": "REQ-DEPS-003",
        "source": ("BSI TR-03183-2 v2.1.0 §5.2.2 (component-level data "
                   "fields: dependency graph completeness)"),
        "representation": ("a unique bom-ref and exactly one dependencies "
                           "entry per component, leaves with an empty list"),
        "origin": "generated-document",
        "check": _check_dependency_entries,
    },
    {
        "id": "REQ-DEPS-004",
        "source": ("BSI TR-03183-2 v2.1.0 §5.2.2 (dependency resolution at "
                   "the scope-of-delivery boundary)"),
        "representation": ("identified boundary components and composition "
                           "completeness instead of dropped dependencies"),
        "origin": "generated-document",
        "check": _check_scope_of_delivery_resolution,
    },
    {
        "id": "REQ-DEPS-005",
        "source": ("BSI TR-03183-2 v2.1.0 §5.2.2 (statically linked "
                   "dependencies)"),
        "representation": ("dependency edges derived from pkgdata "
                           "debug-source records, with evidence origin"),
        "origin": "recipe-metadata",
        "check": _check_static_link_coverage,
    },
    {
        "id": "REQ-DEPS-006",
        "source": ("BSI TR-03183-2 v2.1.0 \u00a74 (dependency graph) and "
                   "\u00a75.2.2 (dependency evidence from the build)"),
        "representation": ("the runtime dependency metadata source of the "
                           "build reports its coverage of the dependency "
                           "graph"),
        "origin": "recipe-metadata",
        "check": _dependency_evidence_source("yoctoRuntimeMetadata",
                                             _runtime_evidence_verdict),
    },
    {
        "id": "REQ-DEPS-007",
        "source": ("BSI TR-03183-2 v2.1.0 \u00a74 (dependency graph) and "
                   "\u00a75.2.2 (dependency evidence from imported "
                   "ecosystem documents)"),
        "representation": ("imported ecosystem BOM graphs report their "
                           "coverage of the dependency graph; defective "
                           "inputs stay visible"),
        "origin": "upstream-metadata",
        "check": _dependency_evidence_source("importedBomGraphs",
                                             _imported_evidence_verdict),
    },
    {
        "id": "REQ-REF-001",
        "source": ("BSI TR-03183-2 v2.1.0 §4 (structurally valid document: "
                   "unique, resolvable references)"),
        "representation": ("unique bom-refs, resolvable dependency "
                           "references, unambiguous graph root"),
        "origin": "generated-document",
        "check": _check_reference_integrity,
    },
    {
        "id": "REQ-MERGE-001",
        "source": ("BSI TR-03183-2 v2.1.0 §5.2.2 (dependency evidence "
                   "from imported ecosystem BOMs and embedded image "
                   "SBOMs)"),
        "representation": ("imported and embedded BOM graphs composed "
                           "losslessly; defective input reported as a "
                           "finding instead of truncated output"),
        "origin": "generated-document",
        "check": _check_imported_embedded_composition,
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
        "id": "REQ-FILE-001",
        "source": ("BSI TR-03183-2 v2.1.0 §3.2.1 (file components) and "
                   "§5.2.2 (mandatory inventory of delivered executables "
                   "and archives)"),
        "representation": ("one type:file component with artifact identity "
                           "per delivered mandatory file"),
        "origin": "generated-document",
        "applies": _applies_file_inventory,
        "check": _check_file_inventory_coverage,
    },
    {
        "id": "REQ-FILE-002",
        "source": ("BSI TR-03183-2 v2.1.0 §3.2.1 (artifact identity) and "
                   "§5.2.2 (hash of the deployable artifact)"),
        "representation": ("SHA-512 and classification facts for every "
                           "mandatory artifact; defective artifacts are "
                           "reported instead of vanishing"),
        "origin": "artifact-inspection",
        "applies": _applies_file_inventory,
        "check": _check_file_artifact_inspection,
    },
    {
        "id": "REQ-FILE-003",
        "source": ("BSI TR-03183-2 v2.1.0 §5.2.2 (dependency graph "
                   "participation of file components)"),
        "representation": ("file components as graph leaves owned by their "
                           "delivering logical component"),
        "origin": "generated-document",
        "applies": _applies_file_components,
        "check": _check_file_component_graph,
    },
    {
        "id": "REQ-FILE-004",
        "source": ("BSI TR-03183-2 v2.1.0 §3.2.1 (file components) and "
                   "§5.2.2 (mandatory primary deployable artifact)"),
        "representation": ("one type:file component with artifact "
                           "identity per deployed primary artifact, owned "
                           "by the primary component"),
        "origin": "generated-document",
        "applies": _applies_deployable_inventory,
        "check": _check_deployable_coverage,
    },
    {
        "id": "REQ-FILE-005",
        "source": ("BSI TR-03183-2 v2.1.0 §4 (scope of delivery) and "
                   "§5.2.2 (explicitly selected additional delivered "
                   "files)"),
        "representation": ("one file component per explicitly selected "
                           "additional file; a selection that resolves to "
                           "nothing stays an affected-file finding"),
        "origin": "generated-document",
        "applies": _applies_selected_files,
        "check": _check_selected_files,
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
    {
        "id": "REQ-SBOM-002",
        "source": ("BSI TR-03183-2 v2.1.0 \u00a75.2.1 (SBOM-level data fields: "
                   "timestamp)"),
        "representation": "metadata.timestamp",
        "origin": "generated-document",
        "check": _check_sbom_timestamp,
    },
    {
        "id": "REQ-COMP-009",
        "source": ("BSI TR-03183-2 v2.1.0 \u00a75.2.2 (dependencies with a "
                   "completeness indicator)"),
        "representation": ("dependencies graph plus CycloneDX composition "
                           "completeness data"),
        "origin": "generated-document",
        "check": _check_dependency_completeness_declaration,
    },
    {
        "id": "REQ-COMP-010",
        "source": ("BSI TR-03183-2 v2.1.0 \u00a75.2.2 (component-level data "
                   "fields: component creator)"),
        "representation": ("component authors contacts with an email "
                           "address or URL (organizationalContact), or "
                           "the author name, from an explicit override "
                           "or trustworthy upstream identity metadata"),
        "origin": "generated-document",
        "check": _check_component_creators,
    },
    {
        "id": "REQ-COMP-011",
        "source": ("BSI TR-03183-2 v2.1.0 \u00a75.2.2 (distribution "
                   "licences), \u00a76.1 and \u00a78.1.13 (licence "
                   "identifiers and their CycloneDX mapping)"),
        "representation": ('components[].licenses entries with CycloneDX '
                           'acknowledgement "concluded"; only an explicitly '
                           'identified authoritative source supplies them'),
        "origin": "caller-assertion",
        "check": _check_distribution_licences,
    },
    {
        "id": "REQ-COMP-013",
        "source": ("BSI TR-03183-2 v2.1.0 \u00a75.2.4 (original licences), "
                   "\u00a73.2.8 and \u00a78.1.13 (licence information)"),
        "representation": ("components[].licenses entries with CycloneDX "
                           "acknowledgement \"declared\"; recipe LICENSE is "
                           "original licence evidence only"),
        "origin": "recipe-metadata",
        "check": _check_original_licences,
    },
    {
        "id": "REQ-COMP-014",
        "source": ("BSI TR-03183-2 v2.1.0 \u00a75.2.5 (effective licence, "
                   "optional) and \u00a76.1; property taxonomy v0.1.2 "
                   "bsi:component:effectiveLicence"),
        "representation": ("bsi:component:effectiveLicence property "
                           "explicitly supplied by the SBOM creator, never "
                           "inferred and at most once per component"),
        "origin": "caller-assertion",
        "applies": _applies_effective_licences,
        "check": _check_effective_licences,
    },
    {
        "id": "REQ-IDEN-001",
        "source": ("BSI TR-03183-2 v2.1.0 §5.2.2 (component-level data "
                   "fields: distinct component instances and identifiers)"),
        "representation": ("one bom-ref per independently assessable "
                           "component instance; CPE collisions reported, "
                           "never silently deduplicated"),
        "origin": "generated-document",
        "check": _check_logical_identity_collisions,
    },
    {
        "id": "REQ-IDEN-002",
        "source": ("BSI TR-03183-2 v2.1.0 \u00a75.2.2 (component-level "
                   "data fields: Package URL)"),
        "representation": ("every emitted purl parses as a Package URL "
                           "(pkg:<type>/[<namespace>/]<name>[@<version>]"
                           "[?<qualifiers>][#<subpath>])"),
        "origin": "generated-document",
        "check": _check_purl_syntax,
    },
    {
        "id": "REQ-IDEN-003",
        "source": ("BSI TR-03183-2 v2.1.0 \u00a75.2.2 (component-level "
                   "data fields: CPE) and \u00a73.2.1 (CPE 2.3)"),
        "representation": ("every emitted CPE - component field or "
                           "correlation alias - is a formatted CPE 2.3 "
                           "string"),
        "origin": "generated-document",
        "check": _check_cpe_syntax,
    },
    {
        "id": "REQ-IDEN-004",
        "source": ("BSI TR-03183-2 v2.1.0 \u00a75.2.2 (hash of the "
                   "deployable artifact) and \u00a73.2.1 (SHA-512)"),
        "representation": ("every SHA-512 digest is lowercase hex of 512 "
                           "bits riding components[].hashes[] under the "
                           "SHA-512 algorithm"),
        "origin": "generated-document",
        "check": _check_sha512_syntax,
    },
    {
        "id": "REQ-VULN-001",
        "source": "BSI TR-03183-2 v2.1.0 \u00a73.1 (no vulnerability data in the SBOM)",
        "representation": ("vulnerability status in the separate VEX document "
                           "only"),
        "origin": "generated-document",
        "check": _check_no_vulnerability_data_in_sbom,
    },
    {
        "id": "REQ-VULN-002",
        "source": ("BSI TR-03183-2 v2.1.0 \u00a73.1 (vulnerability status "
                   "assessed against the product's logical components) and "
                   "\u00a75.2.2 (file components as delivery detail)"),
        "representation": ("every VEX affects reference resolves to a "
                           "logical (non-file) component of the product "
                           "SBOM"),
        "origin": "generated-document",
        "check": _check_vex_targets_logical_components,
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
        "requirementsMatrixVersion": "2.1.0-r8",
        "specVersions": ["1.6", "1.7"],
        "requirements": TR03183_2_REQUIREMENTS,
    },
}

# Supported alignment enforcement values: "report" publishes the documents
# and the alignment report despite known gaps; "strict" fails the build on
# every machine-detectable violation or missing required assertion.
ENFORCEMENT_VALUES = ["report", "strict"]


def evaluate(profile_id, spec_version, sbom, vex, facts, collisions=None,
             graph=None):
    """
    Evaluate the requirements matrix of one alignment profile against the
    rendered documents and their facts.

    Returns (profile baseline, findings): the exact guideline, property
    taxonomy, CycloneDX schema and matrix versions used, and one finding
    per matrix row, ordered by requirement identifier. collisions carries
    the renderer-computed component identity collision groups.
    """
    profile = PROFILES[profile_id]
    baseline = {
        "guideline": profile["guideline"],
        "guidelineVersion": profile["guidelineVersion"],
        "propertyTaxonomyVersion": profile["propertyTaxonomyVersion"],
        "cyclonedxSchemaVersion": spec_version,
        "requirementsMatrixVersion": profile["requirementsMatrixVersion"],
    }
    findings = [_evaluate_requirement(row, spec_version, sbom, vex, facts,
                                      collisions, graph)
                for row in profile["requirements"]]
    findings.sort(key=lambda finding: finding["requirementId"])
    return baseline, findings


def _evaluate_requirement(row, spec_version, sbom, vex, facts,
                          collisions=None, graph=None):
    """Turn one requirements-matrix row into one alignment report finding."""
    context = {"spec_version": spec_version, "sbom": sbom, "vex": vex,
               "facts": facts, "collisions": collisions or [],
               "graph": graph or {}}
    applicability = "applicable"
    if row.get("applies"):
        applies, reason = row["applies"](context)
        if not applies:
            applicability = "not-applicable"
            result = ("unverifiable", reason)

    if applicability == "applicable":
        result = row["check"](context)

    verdict, message = result[0], result[1]
    origin = result[3] if len(result) > 3 else row["origin"]
    finding = {
        "requirementId": row["id"],
        "normativeSource": row["source"],
        "cyclonedxRepresentation": row["representation"],
        "applicability": applicability,
        "verdict": verdict,
        "evidenceOrigin": origin,
        "diagnosticMessage": message,
    }
    declared_refs = result[2] if len(result) > 2 else None
    bom_refs = sorted(ref for ref in declared_refs or () if ref)
    if bom_refs:
        finding["bomRefs"] = bom_refs
    return finding

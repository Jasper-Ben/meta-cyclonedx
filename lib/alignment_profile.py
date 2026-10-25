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

import urllib.parse

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
    if primary.get("author") or primary.get("contact"):
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
    components = context["sbom"].get("components") or []
    missing = [component["bom-ref"] for component in components
               if not component.get("author") and not component.get("contact")]
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


def _check_distribution_licences(context):
    return "unmet", ("recipe-declared licences are original licence evidence "
                     "only; no authoritative distribution licence source is "
                     "represented in the SBOM")


def _check_no_vulnerability_data_in_sbom(context):
    if "vulnerabilities" in context["sbom"]:
        return "unmet", ("the SBOM embeds vulnerability records; vulnerability "
                         "status belongs in the separate VEX document")
    return "verified", ("the SBOM carries no vulnerability data; status lives "
                        "in the separate VEX document")


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
    unknown = (context.get("graph") or {}).get("staticUnknownRefs") or []
    if unknown:
        return "unverifiable", ("debug-source records are missing or "
                                "inhibited for these components, so static "
                                "linking is unknown coverage, never an "
                                "absence-of-dependencies claim"), unknown
    return "verified", ("every delivered recipe's pkgdata debug-source "
                        "records were consumed for static-link attribution")


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
        "representation": ("metadata.component author or contact with an "
                           "email address or URL"),
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
        "origin": "generated-document",
        "check": _check_static_link_coverage,
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
        "representation": ("component author or contact with an email "
                           "address or URL, from an explicit override or "
                           "trustworthy upstream identity metadata"),
        "origin": "generated-document",
        "check": _check_component_creators,
    },
    {
        "id": "REQ-COMP-011",
        "source": ("BSI TR-03183-2 v2.1.0 \u00a75.2.2 (distribution licences) "
                   "and \u00a76.1 (SPDX licence identifiers)"),
        "representation": ("distribution licence with SPDX identifiers or "
                           "expressions"),
        "origin": "generated-document",
        "check": _check_distribution_licences,
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
        "id": "REQ-VULN-001",
        "source": "BSI TR-03183-2 v2.1.0 \u00a73.1 (no vulnerability data in the SBOM)",
        "representation": ("vulnerability status in the separate VEX document "
                           "only"),
        "origin": "generated-document",
        "check": _check_no_vulnerability_data_in_sbom,
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
        "requirementsMatrixVersion": "2.1.0-r3",
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

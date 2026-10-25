# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: Copyright (C) 2022 BG Networks, Inc.
# SPDX-FileCopyrightText: Copyright (C) 2024 Savoir-faire Linux Inc. (<www.savoirfairelinux.com>).
# SPDX-FileCopyrightText: Copyright (C) 2026 iris-GmbH infrared & intelligent sensors.

"""CycloneDX document renderer for meta-cyclonedx.

This module is the single production owner of SBOM and VEX document
semantics: component identity, dependency graph construction, document
mapping, configuration validation and rendering. It consumes normalized
build facts and artifact facts (plain data structures) and never touches
the BitBake data store, task state or the filesystem. The BitBake class
in classes/ is a thin adapter that collects the facts and deploys the
returned documents.

render(facts) is the primary behavioral seam of the layer.

Facts layout (all keys plain data unless noted):

config                rendered document options:
    spec_version                  "1.6" | "1.7"
    add_component_scopes          bool
    add_citation                  bool
    add_vuln_timestamps           bool
    include_unpatched_vulns       bool   (sbom-cve-check merge only)
    unpatched_vulns_state         str    (sbom-cve-check merge only)
    sbom_serial_placeholder       str    placeholder used in fragment VEX refs
    profile                       str    alignment profile name ("" = none)
    enforcement                   str    "report" (default) | "strict"
timestamp             ISO-8601 string used for both document metadata blocks
log                   callable(level, message); level is an int debug level
                      or one of "warn", "error", "note"
primary               the delivered product:
    type / name / version         primary component metadata
    cpe / purl                    optional identifiers, generated or
                                  configured; when present they are emitted
                                  on the primary component
    external_references           optional list; when the key is absent the
                                  primary component carries none
fragments             per-recipe normalized facts, keyed by recipe name, in
                      the on-disk partial-SBOM format written by
                      do_populate_cyclonedx: "pkgs", "cves", "dependencies",
                      "extra_components", "extra_dependencies", "extra_roots"
runtime_recipes       recipe names whose components are "required"
image_install_recipes recipe names installed by image author intent; their
                      components hang directly off the graph root
runtime_edges         recipe -> dependency recipe edges observed from the
                      installed packages (empty when unresolved by design)
included_images       ordered embedded-image documents:
    name                          recipe name of the included image
    sbom                          its completed SBOM document
    vex                           its completed VEX document, or None
    vex_error                     parse error text when unreadable, else None
"""

import copy
import importlib
import importlib.util
import json
import os
import re
import uuid
from datetime import datetime, timezone


def _alignment_profile():
    """
    Load the project-owned requirements-matrix module that sits next to
    this file. Under BitBake the layer's lib directory is not on the
    worker's module search path, so fall back to loading by path, mirroring
    how the adapter loads this module itself.
    """
    try:
        return importlib.import_module("alignment_profile")
    except ImportError:
        name = "cyclonedx_alignment_profile"
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "alignment_profile.py")
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module


SUPPORTED_SPEC_VERSIONS = ["1.6", "1.7"]

# Vocabulary note (ADR-0011): meta-cyclonedx produces alignment evidence,
# never a conformance claim; the conformance determination stays with the
# manufacturer. This statement rides along in every alignment report.
CONFORMANCE_DETERMINATION_NOTE = (
    "meta-cyclonedx makes no TR-03183-2 or CRA conformance claim; this "
    "alignment report is evidence for the manufacturer's conformance "
    "determination, which also requires completeness evidence unavailable "
    "to meta-cyclonedx."
)

# Image types supported by CycloneDX 1.6 and 1.7
SUPPORTED_IMAGE_TYPES = [
    "application",
    "framework",
    "library",
    "container",
    "operating-system",
    "device",
    "firmware",
    "file",
    "platform",
    "device-driver",
    "machine-learning-model",
    "data",
    "cryptographic-asset",
]

# The CPE part of the image component CPE, keyed by CycloneDX image type.
# Types not listed here get the wildcard part.
IMAGE_CPE_PARTS = {
    "application": "a",
    "device": "h",
    "firmware": "o",
    "operating-system": "o",
}

# Grammar of the CPE 2.3 formatted string binding, per the NIST binding spec.
_CPE_23_ESCAPED = r"""\\[\\*?!"#$%&'()+,/:;<=>@\[\]^`{|}~ ]"""
_CPE_23_VALUE = rf"(?:[*-]|(?:\?*|\*?)(?:[a-zA-Z0-9\-\._]|{_CPE_23_ESCAPED})+(?:\?*|\*?))"
_CPE_23_LANGUAGE = r"(?:[*-]|[a-zA-Z]{2,3}(?:-(?:[a-zA-Z]{2}|[0-9]{3}))?)"
CPE_23_REGEX = re.compile(
    rf"cpe:2\.3:[aho*-](?::{_CPE_23_VALUE}){{5}}:{_CPE_23_LANGUAGE}(?::{_CPE_23_VALUE}){{4}}"
)


def cpe_23_escape(value):
    """
    Escape a value for use in a single component of a CPE 2.3 formatted
    string binding. Characters outside [a-z0-9._-] are lower-cased and
    backslash escaped; the wildcard values "*" and "-" pass through
    unchanged.
    """
    if value in ("*", "-"):
        return value
    return re.sub(r"[^a-z0-9\-._]", lambda match: "\\" + match.group(0), value.lower())


def cpe_23_is_valid(cpe):
    """
    Check whether a string matches the CPE 2.3 formatted string binding
    grammar.
    """
    return bool(CPE_23_REGEX.fullmatch(cpe))


def image_cpe(image_type, vendor, name, version, override=None):
    """
    Build the CPE of the image component. A configured override is returned
    unchanged (config_errors validates it); the generated CPE derives its
    part from the image type, uses the wildcard vendor when none is
    configured and escapes the identity values it takes from the component.
    """
    if override:
        return override
    return "cpe:2.3:{}:{}:{}:{}:*:*:*:*:*:*:*".format(
        IMAGE_CPE_PARTS.get(image_type, "*"),
        cpe_23_escape(vendor or "*"),
        cpe_23_escape(name),
        cpe_23_escape(version),
    )


def image_purl(base_purl, layer_version=None, repository_url=None):
    """
    Assemble the PURL of the image component from the Yocto base PURL (built
    from the layer namespace, BPN and PV of the image recipe) and the layer
    facts. Both qualifiers are optional and are emitted in ascending key
    order, per the PURL specification.
    """
    import urllib.parse

    qualifiers = []
    if layer_version:
        qualifiers.append("layer_version=" + layer_version)
    if repository_url:
        qualifiers.append("repository_url=" + urllib.parse.quote(repository_url, safe=""))
    if not qualifiers:
        return base_purl
    return base_purl + "?" + "&".join(qualifiers)


def config_errors(spec_version, image_type, image_cpe=None, profile=None, enforcement=None):
    """
    Validate renderer-relevant configuration and return a human-readable
    fatal error string, or None when the configuration is supported. The
    image_cpe carries the optional CYCLONEDX_IMAGE_CPE override. An absent
    profile keeps the plain output; strict enforcement requires a profile.
    """
    matrix = _alignment_profile()
    if profile:
        baseline = matrix.PROFILES.get(profile)
        if baseline is None:
            return (f"Unsupported CYCLONEDX_PROFILE: {profile}. "
                    f"Supported profiles: {', '.join(sorted(matrix.PROFILES))}")
        if spec_version not in baseline["specVersions"]:
            return (
                f"Alignment profile '{profile}' supports CycloneDX "
                f"{', '.join(baseline['specVersions'])}; CYCLONEDX_SPEC_VERSION "
                f"'{spec_version}' is an unsupported profile/schema combination"
            )

    if spec_version not in SUPPORTED_SPEC_VERSIONS:
        return (f"Unsupported CYCLONEDX_SPEC_VERSION: {spec_version}. "
                f"Supported versions: {', '.join(SUPPORTED_SPEC_VERSIONS)}")

    if image_type not in SUPPORTED_IMAGE_TYPES:
        return (
            f"Unsupported CYCLONEDX_IMAGE_TYPE value '{image_type}'. "
            f"Valid types are: {', '.join(SUPPORTED_IMAGE_TYPES)}"
        )

    if image_cpe and not cpe_23_is_valid(image_cpe):
        return f"Invalid CPE 2.3 in CYCLONEDX_IMAGE_CPE: '{image_cpe}'"
    if enforcement and enforcement not in matrix.ENFORCEMENT_VALUES:
        return (f"Unsupported CYCLONEDX_PROFILE_ENFORCEMENT: {enforcement}. "
                f"Supported values: {', '.join(matrix.ENFORCEMENT_VALUES)}")

    if not profile and enforcement and enforcement != "report":
        return ("CYCLONEDX_PROFILE_ENFORCEMENT requires CYCLONEDX_PROFILE "
                "to select an alignment profile")
    return None


def serialize_report(report):
    """
    Serialize an alignment report to its canonical artifact text.

    The findings are ordered by requirement identifier and the keys are
    sorted, so equivalent normalized facts always produce byte-identical
    output; the report carries no wall-clock time and no values derived
    from per-render random identifiers.
    """
    return json.dumps(report, indent=2, sort_keys=True) + "\n"


# A creator-assigned identity override is authoritative verbatim. The
# semantically valid BPN/PV defaults must look like a name and like a
# version: single identifier-like tokens, the version carrying at least
# one digit; degenerate defaults never enter documents as identity.
VALID_LOGICAL_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+_~+-]*")
VALID_LOGICAL_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+~+-]*")

# Vulnerability correlation aliases survive in component properties so
# every CVE_PRODUCT / CVE_VERSION token keeps reaching the VEX and CVE
# matching inputs without ever becoming component identity (ADR-0006).
ALIAS_PRODUCT_PROPERTY = "yocto:cve:product"
ALIAS_VERSION_PROPERTY = "yocto:cve:version"
ALIAS_CPE_PROPERTY = "yocto:cve:cpe"


def _short_version(version):
    """Short upstream version of a Yocto version string (drops +git suffixes)."""
    return (version or "").split("+git")[0].strip()


def default_logical_version(pv):
    """
    The logical version a PV implies: the short version when it is
    semantically valid (identifier-shaped and carrying at least one
    digit), otherwise the "unknown" placeholder.
    """
    short = _short_version(pv)
    if VALID_LOGICAL_VERSION.fullmatch(short) and any(c.isdigit() for c in short):
        return short
    return "unknown"


def logical_identity(bpn, pv, name_override=None, version_override=None):
    """
    Resolve the logical component identity of a recipe: the creator-
    assigned name and version of its component instance (ADR-0006).

    Explicit CycloneDX identity overrides (CYCLONEDX_COMPONENT_NAME and
    CYCLONEDX_COMPONENT_VERSION) take precedence verbatim. The defaults
    are BPN and the short PV, used only when semantically valid; an
    invalid default degrades to the "unknown" placeholder.
    """
    default_name = (bpn or "").strip()
    if not VALID_LOGICAL_NAME.fullmatch(default_name):
        default_name = "unknown"
    name = name_override.strip() if name_override else default_name
    version = (version_override.strip() if version_override
               else default_logical_version(pv))
    return name, version


def component_identity(bpn, pv, purl, cve_products=None, cve_versions=None,
                       name_override=None, version_override=None,
                       external_references=None, cpe_update="-"):
    """
    Build the single logical component identity record of a recipe.

    One recipe is one independently assessable logical component (ADR-0006,
    ADR-0009): its name and version are creator-assigned — explicit
    overrides over semantically valid BPN and PV defaults. CVE_PRODUCT and
    CVE_VERSION are vulnerability-correlation aliases only: they never
    create or rename the component, they carry a "vendor:" qualifier into
    the CPE, and every token stays available through yocto:cve:product,
    yocto:cve:version and yocto:cve:cpe properties for the VEX and CVE
    matching inputs. The purl records the Yocto/package identity of the
    build (pkg:yocto, OpenEmbedded's purl prefix) alongside, never
    instead of, the logical identity.
    """
    name, version = logical_identity(bpn, pv, name_override, version_override)

    # BitBake defaults CVE_PRODUCT to BPN and CVE_VERSION to PV; mirror
    # that so the function's own defaults carry complete correlation data.
    products = sorted({token for token in (cve_products or "").split() if token}) \
        or [token for token in [(bpn or "").strip()] if token]
    versions = sorted({_short_version(token)
                       for token in (cve_versions or "").split()} - {""}) \
        or [default_logical_version(pv)]

    cpes = []
    for token in products:
        vendor, _, product = token.partition(":")
        if not product:
            vendor, product = "", token
        for short in versions:
            cpes.append("cpe:2.3:*:{}:{}:{}:{}:*:*:*:*:*:*".format(
                vendor or "*", product, short, cpe_update))

    pkg = {
        "name": name,
        "version": version,
        "type": "library",
        "purl": purl,
        "bom-ref": str(uuid.uuid4()),
    }
    if cpes:
        pkg["cpe"] = cpes[0]
    pkg["properties"] = (
        [{"name": ALIAS_PRODUCT_PROPERTY, "value": token} for token in products]
        + [{"name": ALIAS_VERSION_PROPERTY, "value": short} for short in versions]
        + [{"name": ALIAS_CPE_PROPERTY, "value": cpe} for cpe in cpes])
    if external_references:
        pkg["externalReferences"] = external_references
    return pkg


def component_correlation_cpes(component):
    """Every correlation CPE of a component: its own plus alias CPEs."""
    cpes = set()
    if component.get("cpe"):
        cpes.add(component["cpe"])
    for prop in component.get("properties") or []:
        if prop.get("name") == ALIAS_CPE_PROPERTY and prop.get("value"):
            cpes.add(prop["value"])
    return cpes


def identity_collisions(sbom, vex=None):
    """
    Group the components whose CPE correlation identifiers collide.

    Components sharing at least one CPE (transitively) form one collision
    group. A group is explained when every member carries observable
    evidence that distinguishes it from all others — package purl, licence
    set, dependency targets or VEX status — which is exactly the case for
    genuinely independent instances. Any two members indistinguishable on
    all these axes are an unresolved identity collision. Returns a list
    of dicts with keys bomRefs and correlationCpes (both sorted) and bool
    explained, ordered by the first bomRef.
    """
    components_by_ref = {}
    for component in sbom.get("components") or []:
        ref = component.get("bom-ref")
        if ref:
            components_by_ref[ref] = component

    dep_targets = {}
    for entry in sbom.get("dependencies") or []:
        ref = entry.get("ref")
        if ref:
            dep_targets[ref] = sorted(set(entry.get("dependsOn") or []))

    vex_status = {}
    for vuln in (vex or {}).get("vulnerabilities") or []:
        state = (vuln.get("analysis") or {}).get("state")
        for affect in vuln.get("affects") or []:
            _prefix, _sep, ref = (affect.get("ref") or "").rpartition("#")
            if ref:
                vex_status.setdefault(ref, []).append((vuln["id"], state))

    def distinguishable_evidence(component):
        ref = component.get("bom-ref")
        return (
            component.get("purl"),
            json.dumps(component.get("licenses"), sort_keys=True),
            tuple(dep_targets.get(ref, [])),
            tuple(sorted(vex_status.get(ref, []))))

    # union-find over the shared-CPE relation
    parents = {ref: ref for ref in components_by_ref}

    def find(ref):
        while parents[ref] != ref:
            ref = parents[ref]
        return ref

    cpe_owner = {}
    for ref in sorted(components_by_ref):
        for cpe in sorted(component_correlation_cpes(components_by_ref[ref])):
            owner = cpe_owner.get(cpe)
            if owner is None:
                cpe_owner[cpe] = ref
                continue
            root_owner, root_ref = find(owner), find(ref)
            if root_owner != root_ref:
                parents[root_ref] = root_owner

    groups = {}
    for ref in sorted(components_by_ref):
        groups.setdefault(find(ref), []).append(ref)

    collisions = []
    for group in groups.values():
        if len(group) < 2:
            continue
        cpes = set()
        for ref in group:
            cpes |= component_correlation_cpes(components_by_ref[ref])
        evidence = [distinguishable_evidence(components_by_ref[ref])
                    for ref in group]
        collisions.append({
            "bomRefs": sorted(group),
            "correlationCpes": sorted(cpes),
            "explained": len(set(evidence)) == len(evidence),
        })
    collisions.sort(key=lambda collision: collision["bomRefs"][0])
    return collisions


def normalize_cve_id(cve_id):
    """
    Normalize CVE ID by removing patch file suffixes.

    Yocto recipes often use multiple patches for the same CVE with suffixes like:
    - CVE-2025-52886-0001.patch
    - CVE-2025-52886-0002.patch

    This function strips the numeric suffix to get the canonical CVE ID.
    """
    # Match CVE-YYYY-NNNNN format, optionally followed by -NNNN suffix
    match = re.match(r'(CVE-\d{4}-\d+)(?:-\d+)?', cve_id)
    if match:
        return match.group(1)
    return cve_id


def add_status_vex_statement(cve, cves, bom_ref, recipe, placeholder,
                             add_timestamps, log=None):
    """
    Map one recipe CVE status tuple to a VEX statement and append it to the
    statement list, merging duplicate CVE statements (patch-file suffixes,
    multiple aliases of the same recipe) as required by the VEX document
    model. The "affects" reference embeds the SBOM serial placeholder, to be
    resolved at render time.
    """
    cve_id, abbrev_status, status, justification = cve

    # Normalize CVE ID to remove patch file suffixes (e.g., CVE-2025-52886-0001 -> CVE-2025-52886)
    normalized_cve_id = normalize_cve_id(cve_id)

    # See https://docs.yoctoproject.org/singleindex.html#term-CVE_CHECK_STATUSMAP for possible statuses.
    if abbrev_status == "Patched":
        _log(log, 2, f"Found patch for {normalized_cve_id} in {recipe}")
        vex_state = "resolved"
    elif abbrev_status == "Ignored":
        _log(log, 2, f"Found ignore statement for {normalized_cve_id} in {recipe}")
        vex_state = "not_affected"
    else:
        _log(log, 2, f"Found unknown or irrelevant CVE status {abbrev_status} for "
                     f"{normalized_cve_id} in {recipe}. Skipping...")
        return

    # Check if this CVE already exists in the list (avoid duplicates from multiple patches)
    for existing_cve in cves:
        if existing_cve["id"] == normalized_cve_id:
            # CVE already recorded, just update the detail to mention this patch too
            if cve_id != normalized_cve_id:  # Only if there was a suffix
                existing_cve["analysis"]["detail"] += f"Additional patch: {cve_id}\n"
            _log(log, 2, f"CVE {normalized_cve_id} already recorded, updated details")
            # record additional bom reference if unique
            if not any(existing_bom_ref["ref"].endswith(bom_ref)
                       for existing_bom_ref in existing_cve["affects"]):
                existing_cve["affects"].append({"ref": f"urn:cdx:{placeholder}/1#{bom_ref}"})
            return

    detail_string = ""
    detail_string += f"STATE: {status}\n"
    if justification:
        detail_string += f"JUSTIFICATION: {justification}\n"
    # Mention original patch filename if it had a suffix
    if cve_id != normalized_cve_id:
        detail_string += f"Patch file: {cve_id}\n"

    # Build analysis object
    analysis = {
        "detail": detail_string
    }
    if vex_state:
        analysis["state"] = vex_state

    # Add timestamps when enabled
    # This provides better tracking of when vulnerabilities were identified and updated
    if add_timestamps:
        timestamp = datetime.now(timezone.utc).isoformat()
        analysis["firstIssued"] = timestamp
        analysis["lastUpdated"] = timestamp

    cves.append({
        "id": normalized_cve_id,
        # vex documents require a valid source, see https://github.com/DependencyTrack/dependency-track/issues/2977
        # this should always be NVD for yocto CVEs.
        "source": {"name": "NVD", "url": f"https://nvd.nist.gov/vuln/detail/{normalized_cve_id}"},
        "analysis": analysis,
        "affects": [{"ref": f"urn:cdx:{placeholder}/1#{bom_ref}"}]
    })
    return


def kernel_vex_statement(cve_id, bom_refs, placeholder, detail):
    """
    Build a not_affected VEX statement for a kernel CVE whose affected files
    were never compiled, affecting every component of the kernel recipe.
    """
    return {
        'id': cve_id,
        'source': {'name': 'NVD', 'url': f'https://nvd.nist.gov/vuln/detail/{cve_id}'},
        'analysis': {
            'state': 'not_affected',
            'justification': 'code_not_present',
            'detail': detail,
        },
        'affects': [{'ref': f"urn:cdx:{placeholder}/1#{ref}"} for ref in bom_refs],
    }


def render(facts):
    """
    Render the SBOM and VEX documents from normalized build facts.

    Returns {"sbom": ..., "vex": ...}, plus {"report": ...} when an
    alignment profile is selected. With strict alignment enforcement and
    at least one machine-detectable violation the renderer returns no
    documents but {"failure": ...}. Everything depends only on the facts;
    diagnostics are reported through the facts["log"] callback.
    """
    timestamp = facts.get("timestamp")
    log = facts.get("log")
    config = facts.get("config") or {}
    spec_version = config.get("spec_version") or "1.7"
    add_scopes = config.get("add_component_scopes", True)
    placeholder = config.get("sbom_serial_placeholder", "")
    profile = config.get("profile") or ""
    enforcement = config.get("enforcement") or "report"

    fragments = copy.deepcopy(facts.get("fragments") or {})
    runtime_recipes = set(facts.get("runtime_recipes") or ())
    image_install_recipes = set(facts.get("image_install_recipes") or ())
    runtime_edges = facts.get("runtime_edges") or {}

    primary = facts.get("primary") or {}
    image_type = primary.get("type") or "firmware"
    image_name = primary.get("name") or "image"
    image_version = primary.get("version") or "unknown"

    # Order of these uuid generations is part of the document identity.
    metadata_component_ref = str(uuid.uuid4())
    sbom_serial_number = str(uuid.uuid4())
    vex_serial_number = str(uuid.uuid4())

    # Generate sbom document header
    _log(log, 2, f"Creating empty temporary sbom file with serial number {sbom_serial_number}")
    sbom_metadata = {
        "timestamp": timestamp,
        "tools": _create_tools_metadata()
    }
    sbom_metadata["component"] = {
        "type": image_type,
        "name": image_name,
        "version": image_version,
        "bom-ref": metadata_component_ref
    }
    if primary.get("cpe"):
        sbom_metadata["component"]["cpe"] = primary["cpe"]
    if primary.get("purl"):
        sbom_metadata["component"]["purl"] = primary["purl"]
    if "external_references" in primary:
        sbom_metadata["component"]["externalReferences"] = primary["external_references"]

    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": spec_version,
        "serialNumber": f"urn:uuid:{sbom_serial_number}",
        "version": 1,
        "metadata": sbom_metadata,
        "components": [],
        "dependencies": []
    }

    # 1.7-only additions: root-level citations and TLP marking. Applied to
    # the whole document, as citations are not part of metadata.
    _add_document_extensions(config, spec_version, sbom, log)

    # Lifecycles are supported since CycloneDX 1.5.
    sbom["metadata"]["lifecycles"] = [
        {"phase": "build"}
    ]

    # Generate vex document header
    _log(log, 2, f"Creating empty temporary vex file with serial number {sbom_serial_number}")
    vex_metadata = {
        "timestamp": timestamp,
        "tools": _create_tools_metadata()
    }
    vex = {
        "bomFormat": "CycloneDX",
        "specVersion": spec_version,
        "serialNumber": f"urn:uuid:{vex_serial_number}",
        "version": 1,
        "metadata": vex_metadata,
        "vulnerabilities": []
    }

    # 1.7-only additions, applied at the document root (citations) and in
    # metadata.distributionConstraints (TLP).
    _add_document_extensions(config, spec_version, vex, log)

    # taken from https://github.com/yoctoproject/poky/blob/fec201518be3c35a9359ec8c37675a33e458b92d/meta/classes/cve-check.bbclass
    # SPDX-License-Identifier: MIT
    # SPDX-FileCopyrightText: Copyright OpenEmbedded Contributors
    # Collect sbom data from the recipe fragments of the included recipes

    # Maps used to turn a dependency token into the components of its recipe
    recipe_refs = {}
    component_recipes = {}
    ref_recipes = {}

    image_recipe_names = set(fragments)

    # Track direct-install components without persisting debug properties in output.
    directly_installed_component_refs = set()

    # First loop to fill the dictionary. Iterate in a stable order: the
    # recipe names arrive unordered and component declaration order feeds
    # the dependency-target ordering.
    for pkg in sorted(fragments):
        pn_list = fragments[pkg]

        for pn_pkg in pn_list["pkgs"]:
            # A recipe contributes its one logical component; index it so a
            # dependency on the recipe or its logical name reaches it.
            recipe_refs.setdefault(pkg, []).append(pn_pkg["bom-ref"])
            component_recipes.setdefault(pn_pkg["name"], pkg)
            ref_recipes[pn_pkg["bom-ref"]] = pkg

    for pkg in sorted(fragments):
        pn_list = fragments[pkg]

        for pn_pkg in pn_list["pkgs"]:
            # Every fragment component is an independently assessable
            # instance and enters the inventory as-is: CPE equality never
            # merges component instances (ADR-0006). Collisions with other
            # instances are reported downstream, never deduplicated here.

            # Add scope field to indicate runtime vs build-time component
            # Can be disabled for certain SBOM profiles or tool compatibility
            if add_scopes:
                pn_pkg["scope"] = "required" if pkg in runtime_recipes else "excluded"

            if pkg in image_install_recipes:
                directly_installed_component_refs.add(pn_pkg["bom-ref"])

            sbom["components"].append(pn_pkg)
        for pn_cve in pn_list["cves"]:
            # Don't replace serial number yet - it will be done after all CVEs are collected
            # This fixes multi-output builds where shared components would get the wrong serial
            vex["vulnerabilities"].append(pn_cve)


    # Sort components by name for a stable, human-readable order.
    # The recipe set is unordered, so insertion order above is non-deterministic.
    sbom["components"].sort(key=lambda c: (c["name"], c["version"]))

    # Add dependencies.
    # Runtime edges observed from the installed packages cover RRECOMMENDS,
    # per-package RDEPENDS and generated shlib dependencies, which the recipe
    # metadata alone misses. They are empty when the caller resolved
    # dependencies by configuration instead.
    for pkg in sorted(fragments):
        pn_list = fragments[pkg]

        deps = pn_list.get("dependencies")
        extra_depends = sorted(runtime_edges.get(pkg, ()))
        if not deps:
            if not extra_depends:
                continue
            deps = [{"ref": pn_pkg["bom-ref"], "dependsOn": []}
                    for pn_pkg in pn_list["pkgs"] if pn_pkg.get("bom-ref")]

        for dep_entry in deps:
            component_ref = dep_entry["ref"]

            # Skip if component doesn't exist in SBOM
            if not any(comp["bom-ref"] == component_ref for comp in sbom["components"]):
                continue

            resolved_depends = []

            for depends in list(dep_entry["dependsOn"]) + extra_depends:
                if depends not in image_recipe_names:
                    _log(log, 2, f"Skipping dependency {depends} - not in this image")
                    continue

                resolved_refs = _resolve_dependency_refs(depends, recipe_refs,
                                                        component_recipes, ref_recipes)

                for resolved_ref in resolved_refs:

                    if resolved_ref == component_ref:
                        continue

                    # Skip references to components absent from the SBOM
                    if not any(comp["bom-ref"] == resolved_ref for comp in sbom["components"]):
                        continue

                    if resolved_ref not in resolved_depends:
                        resolved_depends.append(resolved_ref)

            if resolved_depends:
                # CycloneDX graph nodes are unique per bom-ref, so merge
                # repeated declarations of the same component ref.
                existing_entry = next((entry for entry in sbom["dependencies"]
                                       if entry["ref"] == component_ref), None)
                if existing_entry:
                    existing_entry["dependsOn"].extend(
                        ref for ref in resolved_depends if ref not in existing_entry["dependsOn"])
                else:
                    sbom["dependencies"].append({"ref": component_ref, "dependsOn": resolved_depends})

    # Fold in pre-resolved CycloneDX fragments contributed by recipes.
    #
    # Language ecosystems that resolve their own dependency trees (cargo, npm,
    # go, ...) are invisible to Yocto's package model: the image BOM lists the
    # recipe that builds the binary, but not the hundreds of modules linked into
    # it. Such a recipe contributes a CycloneDX document at build time through
    # its fragment under "extra_components" / "extra_dependencies", and it is
    # merged into the image BOM here.
    #
    # These entries already carry their own bom-refs, purls and dependency
    # edges, so they are appended verbatim: the recipe-name dependency
    # remapping above applies to components derived from Yocto packages and
    # would corrupt an externally resolved tree.
    extra_seen_refs = {c["bom-ref"] for c in sbom["components"] if c.get("bom-ref")}
    for pkg in sorted(fragments):
        pn_list = fragments[pkg]
        for component in pn_list.get("extra_components", []):
            ref = component.get("bom-ref") or component.get("purl")
            if ref:
                if ref in extra_seen_refs:
                    continue
                extra_seen_refs.add(ref)
            sbom["components"].append(component)
        for dep_entry in pn_list.get("extra_dependencies", []):
            if dep_entry not in sbom["dependencies"]:
                sbom["dependencies"].append(dep_entry)

        # Attach each contributed tree to the recipe that produced it, so the
        # modules are attributable to the binary they are linked into instead of
        # floating unreferenced at the top level of the BOM.
        extra_roots = pn_list.get("extra_roots") or []
        if not extra_roots:
            continue
        owner_refs = recipe_refs.get(pkg) or []
        owner_ref = owner_refs[0] if owner_refs else None
        if not owner_ref or not any(c.get("bom-ref") == owner_ref for c in sbom["components"]):
            _log(log, 1, f"CYCLONEDX_EXTRA_BOM_FILES: {pkg}: no component to attach "
                         f"{len(extra_roots)} contributed tree(s) to")
            continue
        owner_entry = next((x for x in sbom["dependencies"] if x["ref"] == owner_ref), None)
        if owner_entry is None:
            owner_entry = {"ref": owner_ref, "dependsOn": []}
            sbom["dependencies"].append(owner_entry)
        for root_ref in extra_roots:
            if root_ref in extra_seen_refs and root_ref not in owner_entry["dependsOn"]:
                owner_entry["dependsOn"].append(root_ref)

    # Fold in complete SBOMs of the included embedded images. Components
    # carrying the same logical identity and package purl are the same
    # instance and merge onto the parent's bom-ref; unique components are
    # added with scope "required". A shared CPE alone never merges.
    _merge_included_images(sbom, vex, copy.deepcopy(facts.get("included_images")) or (),
                           config, spec_version, sbom_serial_number,
                           add_scopes, directly_installed_component_refs, log)

    # Add a root dependency node as the first entry.
    # It references metadata.component and points to all directly installed
    # components; the dependency-target sort below fixes the array order.
    root_dep_entry = {
        "ref": metadata_component_ref,
        "dependsOn": list(directly_installed_component_refs)
    }
    sbom["dependencies"].insert(0, root_dep_entry)

    # CycloneDX dependency lists are sets; the array order is presentation.
    # bom-refs are minted fresh by every do_populate_cyclonedx rerun, so
    # ordering by the ref values would shuffle these arrays on every
    # regeneration. Order each target by its component's declaration position
    # (the name/version sort above) instead, deterministic across
    # regenerations; targets outside the component list keep a ref-string
    # fallback.
    dep_rank = {comp["bom-ref"]: index
                for index, comp in enumerate(sbom["components"])
                if comp.get("bom-ref")}
    for dep_entry in sbom["dependencies"]:
        targets = dep_entry.get("dependsOn")
        if targets:
            dep_entry["dependsOn"] = sorted(
                targets, key=lambda ref: (dep_rank.get(ref, len(dep_rank)), ref))

    # Replace SBOM serial placeholder in VEX vulnerabilities
    # This must be done after all vulnerabilities are collected to ensure each image
    # gets its own SBOM serial number in multi-output builds (e.g., rootfs + initramfs)
    sbom_refs = {comp["bom-ref"] for comp in sbom["components"]}
    serial_placeholder = placeholder
    resolved_vulns = []
    covered_refs = {}
    for vuln in vex["vulnerabilities"]:
        affects = []
        for affect in vuln.get("affects", []):
            if "ref" not in affect:
                affects.append(affect)
                continue

            prefix, _, bom_ref = affect["ref"].rpartition("#")
            # References to components absent from the SBOM are dangling.
            if bom_ref not in sbom_refs:
                continue

            # Refs merged from another image only become comparable to this
            # document's own, still-templated refs once the serial is substituted.
            ref = f"{prefix}#{bom_ref}".replace(serial_placeholder, sbom_serial_number)
            if not any(existing.get("ref") == ref for existing in affects):
                affects.append({**affect, "ref": ref})

        if not affects:
            continue

        # Statements that add no component reference beyond earlier ones
        # are redundant; the first statement of the CVE wins.
        refs = {affect["ref"] for affect in affects if "ref" in affect}
        if refs and refs.issubset(covered_refs.get(vuln["id"], set())):
            continue
        covered_refs.setdefault(vuln["id"], set()).update(refs)

        vuln["affects"] = affects
        resolved_vulns.append(vuln)
    vex["vulnerabilities"] = resolved_vulns

    # Sort vulnerabilities by CVE id for a stable, human-readable order.
    vex["vulnerabilities"].sort(key=lambda v: v["id"])

    # CPE equality never authorizes deduplication; ambiguous identity
    # collisions are reported instead. Explainable groups (distinct
    # artifact, build, dependency, licence or vulnerability evidence) are
    # deliberately separate instances; indistinguishable duplicates are
    # an unresolved collision.
    collisions = identity_collisions(sbom, vex)
    for collision in collisions:
        refs = ", ".join(collision["bomRefs"])
        cpes = ", ".join(collision["correlationCpes"])
        if collision["explained"]:
            _log(log, 2, f"Component instances {refs} share CPE(s) {cpes} "
                         f"with distinct evidence; kept separate")
        else:
            _log(log, "warn", f"Unexplained component identity collision: "
                              f"{refs} share CPE(s) {cpes} with identical "
                              f"artifact, build, dependency, licence and "
                              f"vulnerability evidence; kept separate, never "
                              f"deduplicated")

    if not profile:
        return {"sbom": sbom, "vex": vex}

    baseline, findings = _alignment_profile().evaluate(
        profile, spec_version, sbom, vex, facts, collisions=collisions)
    report = {
        "alignmentProfile": profile,
        "alignmentEnforcement": enforcement,
        "profileBaseline": baseline,
        "conformanceDetermination": CONFORMANCE_DETERMINATION_NOTE,
        "findings": findings,
    }
    if enforcement == "strict":
        unmet = sorted(finding["requirementId"] for finding in findings
                       if finding["verdict"] == "unmet"
                       and finding["applicability"] == "applicable")
        if unmet:
            return {"failure": {
                "alignmentEnforcement": "strict",
                "unmetRequirementIds": unmet,
                "diagnosticMessage": (
                    f"Alignment profile {profile} with strict enforcement "
                    f"rejects the output over {len(unmet)} unmet requirement(s): "
                    f"{', '.join(unmet)}. Strict enforcement is an alignment "
                    "gate and makes no conformance claim."),
                "report": report,
            }}
    return {"sbom": sbom, "vex": vex, "report": report}


def merge_sbom_cve_check(sbom, vex, report, config, log=None):
    """
    Map a completed sbom-cve-check report onto the VEX document.

    Issues are attached to the logical components they match in the SBOM
    (by any correlation CPE — the component's own or a CVE alias — first,
    falling back to the recipe purl), duplicate statements
    already covered by the VEX are skipped, and every remaining issue
    becomes one statement per analysis (id, detail, state). The VEX is
    modified in place; returns the number of added statements.
    """
    ref_prefix = f"urn:cdx:{sbom['serialNumber'].split(':')[-1]}/{sbom.get('version', 1)}#"
    refs_by_cpe = {}
    refs_by_pn = {}
    for component in sbom.get("components", []):
        for cpe in sorted(component_correlation_cpes(component)):
            refs_by_cpe.setdefault(cpe, []).append(component["bom-ref"])
        purl = component.get("purl", "")
        if purl.startswith("pkg:yocto/"):
            refs_by_pn.setdefault(purl.split("/")[-1].split("@")[0], []).append(component["bom-ref"])

    covered = {(v["id"], a["ref"]) for v in vex.get("vulnerabilities", []) for a in v.get("affects", [])}

    timestamp = None
    if (config.get("spec_version") in SUPPORTED_SPEC_VERSIONS
            and config.get("add_vuln_timestamps")):
        timestamp = datetime.now(timezone.utc).isoformat()

    statements = {}
    for package in report.get("package", []):
        refs = []
        for cpe in package.get("cpes", []):
            refs += refs_by_cpe.get(cpe, [])
        if not refs:
            refs = refs_by_pn.get(package["name"], [])
        if not refs:
            _log(log, 1, f"No SBOM component for sbom-cve-check results of {package['name']}")
            continue

        for issue in package.get("issue", []):
            analysis = _sbom_cve_check_analysis(
                issue,
                config.get("include_unpatched_vulns", False),
                config.get("unpatched_vulns_state") or "")
            if analysis is None:
                continue
            affects = [ref_prefix + r for r in sorted(set(refs)) if (issue["id"], ref_prefix + r) not in covered]
            if not affects:
                continue
            covered.update((issue["id"], a) for a in affects)
            if timestamp:
                analysis["firstIssued"] = timestamp
                analysis["lastUpdated"] = timestamp
            key = (issue["id"], analysis["detail"], analysis.get("state"))
            statement = statements.setdefault(key, {
                "id": issue["id"],
                "source": {"name": "NVD", "url": f"https://nvd.nist.gov/vuln/detail/{issue['id']}"},
                "analysis": analysis,
                "affects": [],
            })
            statement["affects"] += [{"ref": a} for a in affects]

    vex.setdefault("vulnerabilities", []).extend(statements[k] for k in sorted(statements))
    return len(statements)


def _sbom_cve_check_analysis(issue, include_unpatched, unpatched_state):
    """
    Map one sbom-cve-check issue to a VEX analysis object, or None when the
    issue carries no reportable statement.
    """
    status = issue.get("status")
    detail = issue.get("detail", "")
    kind = detail.split(":", 1)[0]

    if status == "Patched":
        analysis = {"state": "not_affected" if kind == "version-not-in-range" else "resolved"}
    elif status == "Ignored":
        analysis = {"state": "not_affected"}
        if kind == "not-applicable-config":
            analysis["justification"] = "code_not_present"
    elif status == "Unpatched" and include_unpatched:
        analysis = {}
        if unpatched_state:
            analysis["state"] = unpatched_state
    else:
        return None

    analysis["detail"] = f"STATE: {detail}\n"
    if issue.get("description"):
        analysis["detail"] += f"JUSTIFICATION: {issue['description']}\n"
    return analysis


def _instance_key(component):
    """
    Instance key used to recognize one and the same component instance in
    different documents: the same logical name and version delivered by
    the same package build (purl). Components without a name and purl are
    never identified through a key; a CPE is correlation data only and
    never part of instance identity (ADR-0006).
    """
    name = component.get("name")
    if name is None or not component.get("purl"):
        return None
    return (name, component.get("version"), component["purl"])


def _merge_included_images(sbom, vex, included_images, config, spec_version,
                           sbom_serial_number, add_scopes,
                           directly_installed_component_refs, log):
    """
    Merge the completed SBOM and VEX of each embedded image into the parent
    documents, remapping bom-refs of components that are the same instance
    as one of the parent's (same logical identity from the same package
    build) and the VEX references to the parent SBOM serial number.
    """
    extra_seen_image_refs = {c["bom-ref"] for c in sbom["components"] if c.get("bom-ref")}
    identity_index = {}
    for component in sbom["components"]:
        key = _instance_key(component)
        if key and key not in identity_index:
            identity_index[key] = component
    for img in included_images:
        img_name = img["name"]
        img_sbom_data = img["sbom"]
        img_vex_data = img.get("vex")
        img_vex_error = img.get("vex_error")

        img_spec = img_sbom_data.get("specVersion")
        if img_spec and img_spec != spec_version:
            _log(log, "warn", f"CYCLONEDX_EXTRA_RUNTIME_IMAGE_RECIPES: {img_name} specVersion {img_spec} "
                              f"differs from parent {spec_version}; merging anyway")

        # The UUID portion of the included SBOM's serialNumber appears verbatim in its VEX affects refs.
        included_serial = (img_sbom_data.get("serialNumber") or "").removeprefix("urn:uuid:")

        # Map included bom-refs to parent bom-refs for components that are
        # the same instance: the same logical identity delivered by the
        # same package build (name, version and package purl). A CPE is
        # vulnerability-correlation data and never merges instances.
        included_bom_ref_remap = {}
        for inc_comp in img_sbom_data.get("components") or []:
            inc_ref = inc_comp.get("bom-ref")
            key = _instance_key(inc_comp)
            if not inc_ref or not key:
                continue
            existing = identity_index.get(key)
            if existing:
                included_bom_ref_remap[inc_ref] = existing["bom-ref"]
                if add_scopes:
                    merged_scope = _highest_priority_scope(existing.get("scope"), inc_comp.get("scope"))
                    if merged_scope:
                        existing["scope"] = merged_scope

        # Add components unique to the included image (no instance match in the parent SBOM).
        for inc_comp in img_sbom_data.get("components") or []:
            inc_ref = inc_comp.get("bom-ref")
            key = _instance_key(inc_comp)
            if inc_ref and inc_ref in included_bom_ref_remap:
                continue
            if inc_ref and inc_ref in extra_seen_image_refs:
                continue
            if add_scopes and "scope" not in inc_comp:
                inc_comp = dict(inc_comp)
                inc_comp["scope"] = "required"
            sbom["components"].append(inc_comp)
            if inc_ref:
                extra_seen_image_refs.add(inc_ref)
            if key and key not in identity_index:
                identity_index[key] = inc_comp

        # Represent the included image itself as a firmware component in the parent SBOM.
        inc_metadata_comp = (img_sbom_data.get("metadata") or {}).get("component") or {}
        img_firmware_ref = str(uuid.uuid4())
        img_firmware_comp = {
            "type": "firmware",
            "name": img_name,
            "version": inc_metadata_comp.get("version") or "unknown",
            "bom-ref": img_firmware_ref,
        }
        if add_scopes:
            img_firmware_comp["scope"] = "required"
        sbom["components"].append(img_firmware_comp)
        extra_seen_image_refs.add(img_firmware_ref)
        # The embedded image is a direct child of the parent image in the dependency tree.
        directly_installed_component_refs.add(img_firmware_ref)

        inc_metadata_ref = inc_metadata_comp.get("bom-ref")
        if inc_metadata_ref:
            included_bom_ref_remap[inc_metadata_ref] = img_firmware_ref

        def remap_ref(ref, _remap=included_bom_ref_remap):
            return _remap.get(ref, ref)

        # Add dependency edges from the included SBOM, remapping shared bom-refs.
        # Merge into an existing dep entry when the ref is already present in the parent.
        for dep_entry in img_sbom_data.get("dependencies") or []:
            r_ref = remap_ref(dep_entry.get("ref", ""))
            if not r_ref or not any(c.get("bom-ref") == r_ref for c in sbom["components"]):
                continue
            r_depends = []
            for dr in dep_entry.get("dependsOn") or []:
                rdr = remap_ref(dr)
                if rdr == r_ref:
                    continue
                if not any(c.get("bom-ref") == rdr for c in sbom["components"]):
                    continue
                if rdr not in r_depends:
                    r_depends.append(rdr)
            if not r_depends:
                continue
            existing_entry = next((x for x in sbom["dependencies"] if x["ref"] == r_ref), None)
            if existing_entry:
                for rdr in r_depends:
                    if rdr not in existing_entry["dependsOn"]:
                        existing_entry["dependsOn"].append(rdr)
            else:
                sbom["dependencies"].append({"ref": r_ref, "dependsOn": r_depends})

        _log(log, 1, f"CYCLONEDX_EXTRA_RUNTIME_IMAGE_RECIPES: merged {img_name} "
                     f"({len(img_sbom_data.get('components') or [])} components)")

        # Merge VEX vulnerabilities: remap included SBOM serial and shared bom-refs, avoid CVE ID duplicates.
        if img_vex_error:
            _log(log, "warn", f"CYCLONEDX_EXTRA_RUNTIME_IMAGE_RECIPES: cannot parse VEX for {img_name}: {img_vex_error}")
            continue
        if img_vex_data is None:
            _log(log, 1, f"CYCLONEDX_EXTRA_RUNTIME_IMAGE_RECIPES: no VEX for {img_name}")
            continue

        for inc_vuln in img_vex_data.get("vulnerabilities") or []:
            cve_id = inc_vuln.get("id")
            if not cve_id:
                continue
            remapped_affects = []
            for affect in inc_vuln.get("affects") or []:
                ref = affect.get("ref", "")
                if included_serial and included_serial in ref:
                    ref = ref.replace(included_serial, sbom_serial_number)
                if "#" in ref:
                    prefix, bom_ref_part = ref.rsplit("#", 1)
                    ref = f"{prefix}#{remap_ref(bom_ref_part)}"
                bom_ref_in_ref = ref.rsplit("#", 1)[-1] if "#" in ref else ""
                if bom_ref_in_ref and not any(
                    c.get("bom-ref") == bom_ref_in_ref for c in sbom["components"]
                ):
                    continue
                remapped_affects.append({"ref": ref})
            if not remapped_affects:
                continue
            existing_vuln = next(
                (v for v in vex["vulnerabilities"] if v.get("id") == cve_id), None
            )
            if existing_vuln:
                for a in remapped_affects:
                    if a not in existing_vuln["affects"]:
                        existing_vuln["affects"].append(a)
            else:
                merged_vuln = dict(inc_vuln)
                merged_vuln["affects"] = remapped_affects
                vex["vulnerabilities"].append(merged_vuln)


def _create_tools_metadata():
    """
    Create tools metadata in the CycloneDX 1.6+ object format:
    {"components": [{"type": "application", "name": "yocto", ...}]}
    """
    return {
        "components": [
            {
                "type": "application",
                "name": "yocto",
                "bom-ref": str(uuid.uuid4())
            }
        ]
    }


def _create_citations(metadata, log=None):
    """
    Create the root-level citations array for CycloneDX 1.7 to document SBOM
    provenance.

    Each citation requires a timestamp, must point at the fields it attributes
    (pointers) and name who supplied the data (attributedTo). The document
    timestamp and the bom-ref of the yocto tool component are reused from the
    document's own metadata so the citation resolves cleanly.
    """
    tool_refs = [
        comp["bom-ref"]
        for comp in (metadata.get("tools") or {}).get("components", [])
        if comp.get("bom-ref")
    ]
    if not tool_refs:
        _log(log, "warn", "CYCLONEDX_ADD_CITATION: no tool bom-ref to attribute citation to, skipping")
        return []

    citation = {
        "timestamp": metadata.get("timestamp") or datetime.now(timezone.utc).isoformat(),
        # JSON pointer "" refers to the whole document: every field in it
        # was generated by the cited tool.
        "pointers": [""],
        "attributedTo": tool_refs[0],
        "note": "Generated by meta-cyclonedx layer for Yocto Project (https://github.com/iris-GmbH/meta-cyclonedx)"
    }
    return [citation]


def _add_document_extensions(config, spec_version, doc, log=None):
    """
    Add CycloneDX 1.7 specific document extensions: root-level citations and
    the TLP marking in metadata.distributionConstraints.
    Modifies the document dict in place.
    """
    if spec_version != "1.7":
        return

    # Add TLP marking if specified.
    tlp_marking = config.get("tlp_marking")
    if tlp_marking and tlp_marking in ["CLEAR", "GREEN", "AMBER", "AMBER_AND_STRICT", "RED"]:
        doc.setdefault("metadata", {}).setdefault("distributionConstraints", {})["tlp"] = tlp_marking
        _log(log, 2, f"Added TLP marking: {tlp_marking}")

    # Add citations if enabled.
    if config.get("add_citation"):
        citations = _create_citations(doc.get("metadata") or {}, log)
        if citations:
            doc["citations"] = citations
            _log(log, 2, "Added citations to SBOM")


def _resolve_dependency_refs(depends, recipe_refs, component_recipes, ref_recipes):
    """
    Replace a dependency token by the bom-refs of the components its recipe
    contributes. A recipe contributes its one logical component, so a
    well-formed fragment resolves to exactly one component.
    """

    # Recipe name
    if depends in recipe_refs:
        recipe = depends
    # Component name, which may differ from the recipe name
    elif depends in component_recipes:
        recipe = component_recipes[depends]
    # If depends is already a bom-ref
    elif depends in ref_recipes:
        recipe = ref_recipes[depends]
    else:
        return []

    return list(recipe_refs[recipe])


def _highest_priority_scope(*scopes):
    """
    Return the most significant of the given CycloneDX scopes, ordered
    required > optional > excluded. Unknown or missing values are ignored,
    and None is returned when no scope is known.
    """
    priority = ["required", "optional", "excluded"]
    known = [scope for scope in scopes if scope in priority]
    if not known:
        return None
    return min(known, key=priority.index)


def _log(log, level, message):
    if log is not None:
        log(level, message)

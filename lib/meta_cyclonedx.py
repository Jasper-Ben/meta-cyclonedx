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
    external_references           optional list; when the key is absent the
                                  primary component carries none
    creator                       optional creator-contact grammar string
                                  naming the product manufacturer as the
                                  creator of the delivered product
    source_uri / deployable_uri   optional explicit URIs for the primary
                                  component (source and deployable form)
    licenses                      optional original licence entries for the
                                  delivered product (its recipe LICENSE)
    distribution_licence          optional SPDX expression; the explicitly
                                  identified authoritative distribution
                                  licence source of the delivered product
    effective_licence             optional SPDX expression; the effective
                                  licence the SBOM creator supplies for the
                                  delivered product
sbom_creator            creator-contact grammar string naming the entity
                        responsible for compiling this SBOM; entries are
                        separated by ';' and each entry is
                        "NAME <EMAIL-or-URL>", "<URL>", a bare email
                        address or a bare URL
fragments             per-recipe normalized facts, keyed by recipe name, in
                      the on-disk partial-SBOM format written by
                      do_populate_cyclonedx: "pkgs", "cves", "dependencies",
                      "extra_components", "extra_dependencies", "extra_roots",
                      plus "extra_bom_errors": rows {"file", "error"} for
                      imported ecosystem BOM files the adapter could not
                      read or attach in report enforcement (the graph is
                      composed from what is usable; the rest is reported),
                      plus creator and URI evidence keys "creator",
                      "source_uri" and "deployable_uri" (grammar strings /
                      URIs; explicit overrides above recorded metadata),
                      plus licence-role evidence keys
                      "distribution_licence" and "effective_licence" (SPDX
                      expressions; the component "licenses" entries are
                      original licence evidence only)
runtime_recipes       recipe names whose components are "required"
image_install_recipes recipe names installed by image author intent; their
                      components hang directly off the graph root
runtime_edges         recipe -> dependency recipe edges observed from the
                      installed packages (empty when unresolved by design)
debug_sources         recipe -> delivered file -> debug-source paths recorded
                      in pkgdata; prefixes of other recipes become statically
                      linked dependency edges (missing/empty = unknown
                      static coverage, never absent dependencies)
included_images       ordered embedded-image documents:
    name                          recipe name of the included image
    sbom                          its completed SBOM document, or None when
                                  unreadable (see sbom_error)
    vex                           its completed VEX document, or None
    vex_error                     parse error text when unreadable, else None
    sbom_error                    parse/availability error text when the
                                  SBOM itself is unreadable, else absent
"""

import bz2
import copy
import importlib
import importlib.util
import json
import lzma
import os
import posixpath
import re
import stat
import struct
import urllib.parse
import uuid
import zlib
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


def config_errors(spec_version, image_type, profile=None, enforcement=None):
    """
    Validate renderer-relevant configuration and return a human-readable
    fatal error string, or None when the configuration is supported.

    profile and enforcement carry the CYCLONEDX_PROFILE and
    CYCLONEDX_PROFILE_ENFORCEMENT selections; an absent or empty profile
    keeps the plain (unaligned) output, so demanding enforcement without a
    profile is a configuration error.
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

# Statically linked code is attributed only from the debugsrc lists BitBake's
# own do_package records in pkgdata; delivered binaries are never parsed
# (ADR-0002). A debug-source prefix /usr/src/debug/<BPN>/<PV>/ identifies the
# recipe that compiled the file it names.
DEBUG_SRC_RECIPE_PREFIX = re.compile(r"^/usr/src/debug/([^/]+)/[^/]+(?:/|$)")
DEPENDENCY_EVIDENCE_PROPERTY = "yocto:dependency:evidence"

# File inventory (BSI TR-03183-2 v2.1.0 §3.2.1 and §5.2.2): delivered
# executables and archives arrive as normalized artifact facts and compose
# into exact file components. The bom-ref is derived from the delivering
# recipe and the delivered path, so reruns mint stable references without
# randomness; file components carry artifact identity only and never a
# purl, CPE or licence (ADR-0006).
BSI_FILENAME_PROPERTY = "bsi:component:filename"
BSI_EXECUTABLE_PROPERTY = "bsi:component:executable"
BSI_ARCHIVE_PROPERTY = "bsi:component:archive"
BSI_STRUCTURED_PROPERTY = "bsi:component:structured"


def _file_bom_ref(recipe, path):
    """The deterministic bom-ref of one inventoried delivered file."""
    return f"yocto-file:{recipe}:{path}"


# Artifact inspection signatures (ADR-0002): deterministic magic numbers
# and file-structure metadata used only for inventory classification -
# never to infer dependencies, embedded software or debug information.
ARTIFACT_HEAD_SIZE = 65536
_ELF_MAGIC = b"\x7fELF"
_ZIP_LOCAL_MAGIC = b"PK\x03\x04"
_ZIP_EMPTY_MAGIC = b"PK\x05\x06"
_GZIP_MAGIC = b"\x1f\x8b"
_XZ_MAGIC = b"\xfd7zXZ\x00"
_BZIP2_MAGIC = b"BZh"
_ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"
_7Z_MAGIC = b"7z\xbc\xaf\x27\x1c"
_RPM_MAGIC = b"\xed\xab\xee\xdb"
_AR_MAGIC = b"!<arch>\n"
_CPIO_MAGICS = (b"070701", b"070707")
_TAR_MAGIC = b"ustar"
_SHT_SYMTAB = 2


def _archive_kind(data):
    """The container or compressed-stream family a signature reveals."""
    if data.startswith((_ZIP_LOCAL_MAGIC, _ZIP_EMPTY_MAGIC)):
        return "zip"
    if data.startswith(_GZIP_MAGIC):
        return "gzip"
    if data.startswith(_XZ_MAGIC):
        return "xz"
    if data[0:3] == _BZIP2_MAGIC and data[3:4] in b"123456789":
        return "bzip2"
    if data.startswith(_ZSTD_MAGIC):
        return "zstd"
    if data.startswith(_7Z_MAGIC):
        return "7z"
    if data.startswith(_RPM_MAGIC):
        return "rpm"
    if data[:6] in _CPIO_MAGICS:
        return "cpio"
    if data[257:262] == _TAR_MAGIC:
        return "tar"
    if data.startswith(_AR_MAGIC):
        return "ar"
    return None


def _decompressed_head(kind, data):
    """The leading inner bytes of a single-stream compressed container."""
    try:
        if kind == "gzip":
            return zlib.decompressobj(zlib.MAX_WBITS | 31).decompress(
                data, 4096)
        if kind == "xz":
            return lzma.LZMADecompressor().decompress(
                data[:ARTIFACT_HEAD_SIZE])
        if kind == "bzip2":
            return bz2.BZ2Decompressor().decompress(data[:ARTIFACT_HEAD_SIZE])
    except Exception:
        return b""
    return b""


def _elf_has_symbol_table(data):
    """True when the ELF section header table still carries a symtab.

    Reading the fixed-offset header and section entries is metadata
    inspection only: an unstripped image keeps the structured content
    metadata BSI counts, a stripped one does not (TR-03183-2 v2.1.0
    §8.1.6); no code analysis happens here (ADR-0002).
    """
    if len(data) < 64:
        return False
    endian = "<" if data[5] == 1 else ">"
    if data[4] == 2:  # ELFCLASS64
        sh_off = struct.unpack_from(endian + "Q", data, 0x28)[0]
        sh_entsize = struct.unpack_from(endian + "H", data, 0x3a)[0]
        sh_num = struct.unpack_from(endian + "H", data, 0x3c)[0]
    else:  # ELFCLASS32
        sh_off = struct.unpack_from(endian + "I", data, 0x20)[0]
        sh_entsize = struct.unpack_from(endian + "H", data, 0x2e)[0]
        sh_num = struct.unpack_from(endian + "H", data, 0x30)[0]
    if not sh_off or not sh_entsize or not 0 < sh_num <= 4096:
        return False
    for index in range(sh_num):
        entry = sh_off + index * sh_entsize
        if entry + 4 > len(data):
            return False
        if struct.unpack_from(endian + "I", data, entry)[0] == _SHT_SYMTAB:
            return True
    return False


def classify_delivered_file(path, mode, data):
    """Classify one delivered file for the mandatory file inventory.

    Inputs: the delivered path, the lstat mode of the delivered entry
    and the leading bytes (or full content) of the delivered bytes.
    The decision table is deterministic:

    - regular files only: symlinks and other special entries are not
      separate delivered artifacts - their content identity belongs to
      the regular file they resolve to, which is inventoried itself.
    - executable: any mode exec bit, a shebang at offset 0 or an ELF
      signature.
    - archive: a recognized container or compressed-stream signature.
    - mandatory (= inventoried here): executable or archive; ordinary
      configuration, documentation and data files stay omitted
      (ADR-0005).
    - structured: the container still carries content metadata -
      entry/directory tables (zip, tar, cpio, ar, rpm, 7z) or an ELF
      symbol table; stripped ELFs, scripts and single-stream
      compressed files are unstructured.
    - error "ambiguous-classification": a recognized signature too
      truncated or corrupt to classify; the entry is reported, never
      guessed.
    """
    if not stat.S_ISREG(mode):
        return {"inventory": False, "mandatory": False,
                "executable": "non-executable", "archive": "no archive",
                "structured": "unstructured"}
    executable = (bool(mode & 0o111) or data.startswith(b"#!")
                  or data.startswith(_ELF_MAGIC))
    kind = _archive_kind(data)
    structured = "unstructured"
    error = None
    if kind in ("zip", "tar", "cpio", "ar", "rpm", "7z"):
        structured = "structured"
    elif kind in ("gzip", "xz", "bzip2"):
        inner = _decompressed_head(kind, data)
        if _archive_kind(inner) in ("zip", "tar", "cpio", "ar", "rpm", "7z",
                                    "gzip", "xz", "bzip2"):
            structured = "structured"
    if data.startswith(_ELF_MAGIC):
        if len(data) < 64:
            error = "ambiguous-classification"
        elif _elf_has_symbol_table(data):
            structured = "structured"
    if data.startswith(_ZIP_LOCAL_MAGIC) and len(data) < 30:
        error = "ambiguous-classification"
    return {"inventory": True,
            "mandatory": executable or kind is not None,
            "executable": "executable" if executable else "non-executable",
            "archive": "archive" if kind else "no archive",
            "structured": structured,
            **({"error": error} if error else {})}


# The dependency graph crosses the scope of delivery exactly once per
# known path: the first external component is represented as identified —
# creator-unverified name and identifier plus a delivery-scope marker that
# keeps it distinct from delivered component instances — and resolution
# stops there unless deeper evidence exists (ADR-0004, never a silent drop).
DELIVERY_SCOPE_PROPERTY = "yocto:delivery:scope"


# Licence roles (BSI TR-03183-2 v2.1.0 §3.2.8 and the §8.2 mapping
# tables): ORIGINAL licences are the licences assigned by the component
# creator and ride the CycloneDX licences field with acknowledgement
# "declared"; DISTRIBUTION licences ("concluded") are the licences under
# which a recipient may use the component and require a semantically
# authoritative source; the EFFECTIVE licence is the licence under which
# the creator of the current SBOM uses the component and rides the
# official BSI property. The property name follows the pinned property
# taxonomy v0.1.2 registry spelling ("Licence"); the TR-03183-2 v2.1.0
# PDF tables carry a "License" variant of the same property. The
# generator performs no legal or composition analysis and never derives
# one licence role from another (ADR-0003).
EFFECTIVE_LICENCE_PROPERTY = "bsi:component:effectiveLicence"
ORIGINAL_LICENCE_ACKNOWLEDGEMENT = "declared"
DISTRIBUTION_LICENCE_ACKNOWLEDGEMENT = "concluded"

# A distribution or effective licence fact must be a syntactically valid
# SPDX licence expression (TR-03183-2 v2.1.0 §6.1): licence identifiers
# combined with the AND, OR and WITH operators and parentheses. This is
# pure syntax; the generator draws no conclusion about the identifiers'
# legal relationship and infers no licence role from another.
SPDX_LICENCE_ID_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9.\-+]*")


def _spdx_expression_is_valid(expression):
    """True when the string parses as an SPDX licence expression."""
    if not isinstance(expression, str) or not expression.strip():
        return False
    expect_operand = True
    after_identifier = False
    depth = 0
    for token in re.findall(r"\(|\)|\S+", expression):
        if token == "(":
            if not expect_operand:
                return False
            depth += 1
            expect_operand = True
        elif token == ")":
            if expect_operand or depth == 0:
                return False
            depth -= 1
            expect_operand = False
            after_identifier = False
        elif token in ("AND", "OR"):
            if expect_operand:
                return False
            expect_operand = True
            after_identifier = False
        elif token == "WITH":
            if expect_operand or not after_identifier:
                return False
            expect_operand = True
        elif expect_operand and SPDX_LICENCE_ID_TOKEN.fullmatch(token):
            expect_operand = False
            after_identifier = True
            continue
        else:
            return False
        after_identifier = False
    return not expect_operand and depth == 0


def _apply_distribution_licence(component, expression, log, holder):
    """Append an explicitly supplied distribution licence entry."""
    if not _spdx_expression_is_valid(expression):
        _log(log, "warn", f"{holder}: distribution licence {expression!r} "
                           f"is not a valid SPDX licence expression; "
                           f"omitted")
        return
    component.setdefault("licenses", []).append(
        {"expression": expression,
         "acknowledgement": DISTRIBUTION_LICENCE_ACKNOWLEDGEMENT})


def _apply_effective_licence(component, expression, log, holder):
    """Attach an explicitly supplied effective licence property once."""
    if not _spdx_expression_is_valid(expression):
        _log(log, "warn", f"{holder}: effective licence {expression!r} is "
                           f"not a valid SPDX licence expression; omitted")
        return
    properties = component.setdefault("properties", [])
    if any(p.get("name") == EFFECTIVE_LICENCE_PROPERTY
           for p in properties):
        return
    properties.append({"name": EFFECTIVE_LICENCE_PROPERTY,
                       "value": expression})



def _apply_licence_evidence(component, evidence, log, holder):
    """Attach explicitly supplied distribution and effective licences.

    Both roles exist only from a semantically authoritative source the
    product integration supplied; neither is ever derived from original
    licence evidence (ADR-0003).
    """
    if evidence.get("distribution_licence"):
        _apply_distribution_licence(component,
                                    evidence["distribution_licence"],
                                    log, holder)
    if evidence.get("effective_licence"):
        _apply_effective_licence(component, evidence["effective_licence"],
                                 log, holder)


def _mark_original_licences(component):
    """Make the original licence role explicit on every licence entry.

    Recipe LICENSE metadata is original licence evidence only; entries
    that already carry an acknowledgement keep whatever role the
    document states, and none is ever rewritten into another.
    """
    for entry in component.get("licenses") or []:
        if "acknowledgement" in entry:
            continue
        target = entry["license"] if isinstance(entry.get("license"),
                                                 dict) else entry
        target.setdefault("acknowledgement", ORIGINAL_LICENCE_ACKNOWLEDGEMENT)


def _identified_component(recipe_name, add_scope):
    """The minimal CycloneDX representation of an external dependency."""
    component = {
        "type": "library",
        "name": recipe_name,
        "version": "unknown",
        "purl": f"pkg:yocto/{recipe_name}",
        "bom-ref": str(uuid.uuid4()),
    }
    if add_scope:
        component["scope"] = "excluded"
    component["properties"] = [{
        "name": DELIVERY_SCOPE_PROPERTY,
        "value": "external",
    }]
    return component


def _debugsrc_targets(debug_sources, represented_recipes):
    """
    Map each recipe to the represented recipes whose code its debug-source
    records show was statically linked in. Own-prefix paths are the recipe
    compiling itself and prefixes of unrepresented recipes carry no claim;
    both are ignored.
    """
    targets = {}
    for recipe in sorted(debug_sources):
        found = set()
        for paths in (debug_sources[recipe] or {}).values():
            if isinstance(paths, str):
                paths = paths.split()
            for path in paths:
                match = DEBUG_SRC_RECIPE_PREFIX.match(path)
                if (match and match.group(1) != recipe
                        and match.group(1) in represented_recipes):
                    found.add(match.group(1))
        if found:
            targets[recipe] = sorted(found)
    return targets


def _add_dependency_evidence(component, origin):
    """Record where a component's dependency evidence came from."""
    properties = component.setdefault("properties", [])
    entry = {"name": DEPENDENCY_EVIDENCE_PROPERTY, "value": origin}
    if entry not in properties:
        properties.append(entry)


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
                       external_references=None):
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
            cpes.append("cpe:2.3:*:{}:{}:{}:*:*:*:*:*:*:*".format(
                vendor or "*", product, short))

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



# Creator evidence uses a small document grammar; every contact must be
# machine-actionable through an email address or URL, mirroring the BSI
# requirement that a creator be identifiable by contact data.
CREATOR_CONTACT_SEPARATOR = ";"
_CREDITED_CONTACT = re.compile(r"^\s*(?P<name>[^<>]*?)\s*<(?P<contact>[^<>]+)>\s*$")
_EMAIL_ADDRESS = re.compile(r"^[^@\s<>(),:;]+@[^@\s<>(),:;]+\.[^@\s<>(),:;]+$")

# URI reference categories that carry the BSI source or deployable URIs.
# Only these are filtered for trustworthy evidence and syntax-validated;
# other external-reference types are documentation, not URIs the
# profile requires.
SOURCE_URI_TYPES = {"vcs", "source-distribution"}
DEPLOYABLE_URI_TYPES = {"distribution"}
URI_REFERENCE_TYPES = SOURCE_URI_TYPES | DEPLOYABLE_URI_TYPES | {"website"}


def _valid_uri(uri):
    """True when the string parses as a URI with a usable location."""
    if not isinstance(uri, str) or not uri.strip():
        return False
    try:
        parsed = urllib.parse.urlparse(uri.strip())
    except ValueError:
        return False
    if parsed.scheme.lower() == "mailto":
        return bool(_EMAIL_ADDRESS.match(parsed.path))
    return bool(parsed.scheme and parsed.netloc)


def _parse_contacts(spec, log=None):
    """Parse creator-contact grammar into sorted organizationalEntities.

    One entity per ';'-separated entry; each entry is
    "NAME <EMAIL-or-URL>", "<URL>", a bare email address or a bare URL.
    An entry without a machine-actionable email or URL is rejected with a
    warning and never emitted as contact data. Entities come back sorted
    so equivalent evidence always renders identical bytes.
    """
    entities = {}
    for entry in (spec or "").split(CREATOR_CONTACT_SEPARATOR):
        entry = entry.strip()
        if not entry:
            continue
        name, contact = "", entry
        credited = _CREDITED_CONTACT.match(entry)
        if credited:
            name = credited.group("name").strip()
            contact = credited.group("contact").strip()
        if _EMAIL_ADDRESS.match(contact):
            kind, value = "email", contact
        elif _valid_uri(contact):
            if contact.lower().startswith("mailto:"):
                kind, value = "email", contact[len("mailto:"):]
            else:
                kind, value = "url", contact
        else:
            _log(log, "warn", f"creator contact {entry!r} carries no usable "
                              f"email address or URL; not emitted")
            continue
        entity = entities.setdefault(name, {"email": set(), "url": set()})
        entity[kind].add(value)
    contacts = []
    for name, found in entities.items():
        entity = {}
        if name:
            entity["name"] = name
        for kind in ("email", "url"):
            if found[kind]:
                entity[kind] = sorted(found[kind])
        contacts.append(entity)
    contacts.sort(key=lambda entity: (entity.get("name", ""),
                                      entity.get("email", []),
                                      entity.get("url", [])))
    return contacts


def _creator_fields(entities):
    """author and contact strings for a component from parsed contacts."""
    author = next((entity["name"] for entity in entities if entity.get("name")),
                  "")
    component_contacts = sorted({contact
                                 for entity in entities
                                 for contact in entity.get("email", [])
                                 + entity.get("url", [])})
    return author, component_contacts


def _apply_creator_identity(component, entities):
    """Stamp creator contacts onto a component; never overwrite claims."""
    author, contacts = _creator_fields(entities)
    if not contacts or component.get("author") or component.get("contact"):
        return False
    if author:
        component["author"] = author
    component["contact"] = contacts
    return True


# "Semantically trustworthy upstream metadata" for creator evidence is
# defined narrowly: only machine-readable upstream identity fields --
# repository-type upstream purls, whose namespace is the upstream
# organization, and fetcher-derived vcs references recorded on the
# component. Free-form author names are never scraped into contacts.
_UPSTREAM_PURL = re.compile(r"^pkg:(?P<type>github|gitlab|bitbucket)/"
                            r"(?P<owner>[^/@?#]+)/(?P<project>[^/?#]+)")
_UPSTREAM_VCS = re.compile(
    r"^(?:(?:https?|ssh|git)://|git@)"
    r"(?P<host>github\.com|gitlab\.com|bitbucket\.org)"
    r"[:/]+(?P<owner>[^/@:;]+)/(?P<project>[^;?#]+?)(?:\.git)?(?:[;/?#].*)?$")


def _upstream_creator_entities(component):
    """Upstream creator contacts derived from recorded upstream identity."""
    match = _UPSTREAM_PURL.match(component.get("purl") or "")
    if match:
        purl_type = match.group("type")
        host = ("bitbucket.org" if purl_type == "bitbucket"
                else f"{purl_type}.com")
        owner, project = match.group("owner"), match.group("project")
    else:
        match = None
        for reference in component.get("externalReferences") or ():
            if reference.get("type") not in SOURCE_URI_TYPES:
                continue
            match = _UPSTREAM_VCS.match(reference.get("url") or "")
            if match:
                break
        if not match:
            return []
        host = match.group("host")
        owner, project = match.group("owner"), match.group("project")
    project = re.sub(r"\.git$", "", project)
    return [{"name": owner, "url": [f"https://{host}/{owner}/{project}"]}]


def _compatible_component_records(existing, candidate):
    """
    True when a candidate component carries no evidence contradicting the
    component already in the graph under the same bom-ref: every field
    present in both (bom-ref aside) agrees. Only then may the candidate
    merge onto the existing record without losing an independently
    assessable component instance.
    """
    for key, value in candidate.items():
        if key == "bom-ref":
            continue
        if key in existing and existing[key] != value:
            return False
    return True


def _merge_instance_evidence(existing, incoming, add_scopes):
    """
    Fold one component instance's evidence into the surviving instance:
    the higher-priority scope wins and licence entries union. Dependency
    evidence unions separately as the graph edges merge, so a reconciled
    instance never loses what either document declared about it.
    """
    if add_scopes:
        merged_scope = _highest_priority_scope(existing.get("scope"),
                                               incoming.get("scope"))
        if merged_scope:
            existing["scope"] = merged_scope
    licences = incoming.get("licenses")
    if licences:
        kept = existing.setdefault("licenses", [])
        for licence in licences:
            if licence not in kept:
                kept.append(licence)


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
    sbom_creators = _parse_contacts(facts.get("sbom_creator"), log)
    if sbom_creators:
        sbom_metadata["authors"] = sbom_creators
    sbom_metadata["component"] = {
        "type": image_type,
        "name": image_name,
        "version": image_version,
        "bom-ref": metadata_component_ref
    }
    if "external_references" in primary:
        sbom_metadata["component"]["externalReferences"] = primary["external_references"]
    _apply_creator_identity(
        sbom_metadata["component"], _parse_contacts(primary.get("creator"), log))
    if primary.get("licenses"):
        sbom_metadata["component"]["licenses"] = copy.deepcopy(
            primary["licenses"])
    for reference_key, reference_type in (("source_uri", "vcs"),
                                          ("deployable_uri", "distribution")):
        if primary.get(reference_key):
            sbom_metadata["component"].setdefault(
                "externalReferences", []).append(
                    {"type": reference_type, "url": primary[reference_key]})
    _mark_original_licences(sbom_metadata["component"])
    _apply_licence_evidence(sbom_metadata["component"], primary, log,
                            "primary component")

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

            # Third-party creator precedence: explicit per-recipe
            # override, then trustworthy upstream identity metadata,
            # then unresolved. The product manufacturer is never stamped
            # onto bundled third-party software.
            creator_override = _parse_contacts(pn_list.get("creator"), log)
            if creator_override:
                _apply_creator_identity(pn_pkg, creator_override)
            elif not pn_pkg.get("author") and not pn_pkg.get("contact"):
                _apply_creator_identity(
                    pn_pkg, _upstream_creator_entities(pn_pkg))

            for reference_key, reference_type in (("source_uri", "vcs"),
                                                  ("deployable_uri",
                                                   "distribution")):
                if pn_list.get(reference_key):
                    pn_pkg.setdefault("externalReferences", []).append(
                        {"type": reference_type,
                         "url": pn_list[reference_key]})

            # Recipe LICENSE metadata enters the document only as
            # original licence evidence; its role is made explicit here
            # and never rewritten into another role (ADR-0003).
            _mark_original_licences(pn_pkg)
            _apply_licence_evidence(pn_pkg, pn_list, log, pkg)

            if pkg in image_install_recipes and pn_pkg.get("bom-ref"):
                directly_installed_component_refs.add(pn_pkg["bom-ref"])

            sbom["components"].append(pn_pkg)
        for pn_cve in pn_list["cves"]:
            # Don't replace serial number yet - it will be done after all CVEs are collected
            # This fixes multi-output builds where shared components would get the wrong serial
            vex["vulnerabilities"].append(pn_cve)



    # Add dependencies.
    # Runtime edges observed from the installed packages cover RRECOMMENDS,
    # per-package RDEPENDS and generated shlib dependencies, which the recipe
    # metadata alone misses. They are empty when the caller resolved
    # dependencies by configuration instead.
    boundary_components = {}
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

            # A ref that names no component is a dangling reference; the
            # entry is preserved for the reference-integrity finding and
            # never silently discarded (ADR-0004).
            resolved_depends = []

            for depends in list(dep_entry["dependsOn"]) + extra_depends:
                if depends not in image_recipe_names:
                    # A known dependency recipe outside the delivery item:
                    # follow the path to it, represent it as identified and
                    # stop — deeper resolution is not claimed without
                    # evidence, and the edge is never dropped either.
                    boundary = boundary_components.get(depends)
                    if boundary is None:
                        boundary = _identified_component(depends, add_scopes)
                        boundary_components[depends] = boundary
                        sbom["components"].append(boundary)
                        _log(log, 2, f"Dependency {depends} is outside the "
                                     f"scope of delivery; represented as "
                                     f"identified")
                    if boundary["bom-ref"] not in resolved_depends:
                        resolved_depends.append(boundary["bom-ref"])
                    continue

                resolved_refs = _resolve_dependency_refs(depends, recipe_refs,
                                                        component_recipes, ref_recipes)

                for resolved_ref in resolved_refs:

                    if resolved_ref == component_ref:
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
    # These entries carry their own bom-refs, purls and dependency edges,
    # so the recipe-name dependency remapping above does not apply: it
    # addresses Yocto-derived components and would corrupt an externally
    # resolved tree. Components are reconciled by instance identity
    # (logical name, version and purl), edges are merged, and everything
    # that stays unusable is published as a composition finding.
    merge_defects = []
    for pkg in sorted(fragments):
        for failure in fragments[pkg].get("extra_bom_errors") or []:
            _log(log, "warn", f"CYCLONEDX_EXTRA_BOM_FILES: {pkg}: imported "
                              f"BOM {failure.get('file')} is unusable: "
                              f"{failure.get('error')}")
            merge_defects.append({
                "kind": "imported-bom-unusable",
                "source": f"{pkg} ({failure.get('file')})",
                "message": f"imported BOM {failure.get('file')} could not "
                           f"be read: {failure.get('error')}",
                "refs": [],
            })
    extra_ref_components = {}
    extra_identity_index = {}
    for component in sbom["components"]:
        ref = component.get("bom-ref")
        if ref:
            extra_ref_components.setdefault(ref, component)
        key = _instance_key(component)
        if key and key not in extra_identity_index:
            extra_identity_index[key] = component
    contributed_ref_remap = {}
    for pkg in sorted(fragments):
        pn_list = fragments[pkg]
        for component in pn_list.get("extra_components", []):
            ref = component.get("bom-ref")
            key = _instance_key(component)
            survivor = extra_identity_index.get(key) if key else None
            if survivor is not None and survivor.get("bom-ref") != ref:
                # Same logical name, version and package build seen
                # through two ecosystem documents: one component
                # instance, reconciled onto the surviving bom-ref. Both
                # graphs' edges converge on it below; a shared CPE alone
                # never reconciles anything (ADR-0006).
                if ref:
                    contributed_ref_remap[ref] = survivor["bom-ref"]
                _merge_instance_evidence(survivor, component, add_scopes)
                continue
            if ref and ref in extra_ref_components and \
                    _compatible_component_records(extra_ref_components[ref],
                                                  component):
                # The very same record is already in the graph; merging
                # onto it loses no evidence. Contradicting evidence under
                # the same bom-ref keeps both instances and surfaces as a
                # reference-integrity finding, never a silent drop.
                continue
            sbom["components"].append(component)
            if ref:
                extra_ref_components.setdefault(ref, component)
            if key and key not in extra_identity_index:
                extra_identity_index[key] = component

    # Fold the imported edges in after the whole contributed graph is
    # reconciled, so ref rewrites apply consistently. Edges are merged,
    # never recomputed or flattened: the ecosystem document remains
    # authoritative for its own resolution (no package-manager
    # reimplementation here), this layer only composes it.
    for pkg in sorted(fragments):
        pn_list = fragments[pkg]
        for edge in pn_list.get("extra_dependencies") or []:
            edge_ref = contributed_ref_remap.get(edge.get("ref"),
                                                 edge.get("ref"))
            if not edge_ref:
                _log(log, "warn", f"CYCLONEDX_EXTRA_BOM_FILES: {pkg}: "
                                  f"contributed dependency entry without "
                                  f"a ref; its edges cannot be attached")
                continue
            depends_on = [contributed_ref_remap.get(target, target)
                          for target in edge.get("dependsOn") or []
                          if contributed_ref_remap.get(target,
                                                       target) != edge_ref]
            existing_entry = next((entry for entry in sbom["dependencies"]
                                   if entry["ref"] == edge_ref), None)
            if existing_entry is None:
                sbom["dependencies"].append({"ref": edge_ref,
                                             "dependsOn": depends_on})
            else:
                existing_entry["dependsOn"].extend(
                    target for target in depends_on
                    if target not in existing_entry["dependsOn"])

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
            root_ref = contributed_ref_remap.get(root_ref, root_ref)
            if root_ref not in extra_ref_components:
                # A root no component carries: the imported document is
                # malformed. The attach edge is published anyway and goes
                # out as a dangling reference finding, never silently
                # detached from the owner (ADR-0004).
                _log(log, "warn", f"CYCLONEDX_EXTRA_BOM_FILES: {pkg}: "
                                  f"contributed root {root_ref} names no "
                                  f"component; the imported graph is "
                                  f"malformed")
                merge_defects.append({
                    "kind": "imported-root-missing",
                    "source": pkg,
                    "message": f"contributed root {root_ref} names no "
                               f"component",
                    "refs": [root_ref],
                })
            if root_ref not in owner_entry["dependsOn"]:
                owner_entry["dependsOn"].append(root_ref)

    # Fold in complete SBOMs of the included embedded images. Components
    # carrying the same logical identity and package purl are the same
    # instance and merge onto the parent's bom-ref; unique components are
    # added with scope "required". A shared CPE alone never merges.
    _merge_included_images(sbom, vex, copy.deepcopy(facts.get("included_images")) or (),
                           config, spec_version, sbom_serial_number,
                           add_scopes, directly_installed_component_refs, log,
                           merge_defects)

    # Statically linked edges observed from pkgdata debug-source records:
    # another recipe's debug-source prefix in this recipe's file list proves
    # that recipe's code was linked in. The edge rides the dependency graph;
    # its evidence origin rides the depending component's properties.
    static_targets = _debugsrc_targets(facts.get("debug_sources") or {},
                                       set(fragments))
    components_by_ref = {c["bom-ref"]: c for c in sbom["components"]
                         if c.get("bom-ref")}
    for owner in sorted(static_targets):
        for owner_ref in recipe_refs.get(owner, []):
            owner_entry = next((entry for entry in sbom["dependencies"]
                                if entry["ref"] == owner_ref), None)
            for target in static_targets[owner]:
                for target_ref in recipe_refs.get(target, []):
                    if target_ref == owner_ref:
                        continue
                    if owner_entry is None:
                        owner_entry = {"ref": owner_ref, "dependsOn": []}
                        sbom["dependencies"].append(owner_entry)
                    if target_ref not in owner_entry["dependsOn"]:
                        owner_entry["dependsOn"].append(target_ref)
                    _add_dependency_evidence(components_by_ref[owner_ref],
                                             "debugsrc")


    # Compose the file inventory: every delivered mandatory file becomes
    # an exact file component owned by the recipe's logical component,
    # whose graph entry gains the file reference. Active only with a
    # selected alignment profile; ordinary output stays a logical-component
    # SBOM (ADR-0005), and the renderer never inspects files itself -
    # classification and hashing stay artifact facts (ADR-0002). Entries
    # the adapter could not classify carry an error kind and stay
    # reported, never silently dropped (ADR-0004).
    file_inventory = facts.get("file_inventory") or {}
    file_facts = []
    for recipe in sorted(file_inventory):
        for entry in file_inventory[recipe]:
            file_facts.append({**entry, "recipe": recipe,
                               "ref": _file_bom_ref(recipe, entry["path"])})
    for artifact in file_facts:
        if artifact.get("error"):
            _log(log, "warn", f"File inventory: {artifact['recipe']}: "
                              f"mandatory delivered file "
                              f"{artifact['path']} is {artifact['error']}")
    if profile:
        for artifact in file_facts:
            if artifact.get("error"):
                continue
            recipe = artifact["recipe"]
            owner_refs = recipe_refs.get(recipe) or []
            version = next((component.get("version")
                            for component in
                            (fragments.get(recipe) or {}).get("pkgs", ())
                            if component.get("version")), "unknown")
            name = posixpath.basename(artifact["path"])
            sbom["components"].append({
                "type": "file",
                "name": name,
                "version": version,
                "bom-ref": artifact["ref"],
                "hashes": [{"alg": "SHA-512",
                            "content": artifact["sha512"]}],
                "properties": [
                    {"name": BSI_FILENAME_PROPERTY, "value": name},
                    {"name": BSI_EXECUTABLE_PROPERTY,
                     "value": artifact["executable"]},
                    {"name": BSI_ARCHIVE_PROPERTY,
                     "value": artifact["archive"]},
                    {"name": BSI_STRUCTURED_PROPERTY,
                     "value": artifact["structured"]},
                ],
            })
            owner_ref = owner_refs[0] if owner_refs else None
            if owner_ref:
                owner_entry = next((dep for dep in sbom["dependencies"]
                                    if dep["ref"] == owner_ref), None)
                if owner_entry is None:
                    owner_entry = {"ref": owner_ref, "dependsOn": []}
                    sbom["dependencies"].append(owner_entry)
                if artifact["ref"] not in owner_entry["dependsOn"]:
                    owner_entry["dependsOn"].append(artifact["ref"])

    # The component declaration order is fixed here, after EVERY append:
    # the recipe set above is unordered, boundary, contributed and
    # embedded components are appended in discovery order, which moves
    # between task reruns, and everything positional downstream - leaf
    # entries, dependency-target ranks, compositions - derives from this
    # one deterministic order.
    sbom["components"].sort(key=lambda c: (c.get("name") or "",
                                           c.get("version") or "",
                                           c.get("bom-ref") or ""))

    # Every represented component participates in the dependency graph.
    # A leaf gets a dependency entry with an empty list, so a machine can
    # tell a known leaf apart from a component whose edges were lost.
    dependency_entry_refs = {entry["ref"] for entry in sbom["dependencies"]}
    for component in sbom["components"]:
        component_ref = component.get("bom-ref")
        if component_ref and component_ref not in dependency_entry_refs:
            sbom["dependencies"].append({"ref": component_ref,
                                         "dependsOn": []})
            dependency_entry_refs.add(component_ref)

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

    # CycloneDX composition data declares how complete the dependency
    # evidence behind each component's graph entry is. Yocto facts decide
    # the aggregate: usable debug-source records with nothing unresolved
    # say complete, missing or inhibited debug information says unknown,
    # and a reference that goes nowhere says incomplete. Unknown facts
    # never become a complete declaration (ADR-0004).
    debug_evidence_recipes = set()
    for recipe, files in (facts.get("debug_sources") or {}).items():
        for paths in (files or {}).values():
            if isinstance(paths, str):
                paths = paths.split()
            if paths:
                debug_evidence_recipes.add(recipe)
                break
    graph_node_refs = {comp.get("bom-ref") for comp in sbom["components"]}
    graph_node_refs.add(metadata_component_ref)
    entries_by_ref = {}
    for dep_entry in sbom["dependencies"]:
        entries_by_ref.setdefault(dep_entry.get("ref"), dep_entry)
    declared_refs = set()
    sbom["compositions"] = []
    for component in sbom["components"]:
        component_ref = component.get("bom-ref")
        if not component_ref or component_ref in declared_refs:
            continue
        declared_refs.add(component_ref)
        entry = entries_by_ref.get(component_ref)
        targets = (entry or {}).get("dependsOn") or []
        if any(target not in graph_node_refs for target in targets):
            aggregate = "incomplete"
        elif ref_recipes.get(component_ref) in debug_evidence_recipes:
            aggregate = "complete"
        else:
            aggregate = "unknown"
        # The CycloneDX composition declares the completeness of exactly
        # one assembly; 1.6 and 1.7 spell its dependencies field
        # differently, so the declaration rides on assemblies only.
        sbom["compositions"].append({"aggregate": aggregate,
                                     "assemblies": [component_ref]})

    graph = _graph_evidence(sbom, metadata_component_ref, ref_recipes,
                            debug_evidence_recipes, merge_defects, log)
    if file_facts:
        graph["fileInventory"] = {"entries": [
            {key: artifact.get(key)
             for key in ("recipe", "path", "ref", "error")}
            for artifact in file_facts]}

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

    # Source and deployable URIs are emitted only from trustworthy
    # metadata, and only when the URI is syntactically valid; an
    # unparseable URI is dropped with a warning instead of entering the
    # document, and the URI requirement rows report the gap.
    for holder in [sbom_metadata["component"], *sbom["components"]]:
        references = holder.get("externalReferences") or []
        kept = [reference for reference in references
                if reference.get("type") not in URI_REFERENCE_TYPES
                or _valid_uri(reference.get("url"))]
        if len(kept) != len(references):
            _log(log, "warn", f"{holder.get('name') or 'metadata.component'}: "
                              f"dropped "
                              f"{len(references) - len(kept)} external "
                              f"reference(s) with a syntactically invalid "
                              f"URI")
            holder["externalReferences"] = kept

    if not profile:
        return {"sbom": sbom, "vex": vex}

    baseline, findings = _alignment_profile().evaluate(
        profile, spec_version, sbom, vex, facts, collisions=collisions,
        graph=graph)
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
                           directly_installed_component_refs, log,
                           merge_defects=None):
    """
    Merge the completed SBOM and VEX of each embedded image into the parent
    documents, remapping bom-refs of components that are the same instance
    as one of the parent's (same logical identity from the same package
    build) and the VEX references to the parent SBOM serial number.

    Defective input is recorded in merge_defects and reported; the graph
    is never repaired by dropping nodes, edges, scopes or VEX statements
    (ADR-0004).
    """
    if merge_defects is None:
        merge_defects = []
    ref_components = {c["bom-ref"]: c for c in sbom["components"]
                      if c.get("bom-ref")}
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
        img_sbom_error = img.get("sbom_error")

        if img_sbom_data is None:
            # The adapter could not read the embedded document at all.
            # The delivered payload stays represented - as a firmware
            # component of unknown version, hung off the graph root -
            # and the unreadable evidence becomes a composition finding,
            # never a silently missing delivery-item part (ADR-0004).
            _log(log, "warn", f"CYCLONEDX_EXTRA_RUNTIME_IMAGE_RECIPES: "
                              f"cannot read SBOM for {img_name}: "
                              f"{img_sbom_error or 'no document'}")
            merge_defects.append({
                "kind": "embedded-sbom-unusable",
                "source": img_name,
                "message": f"embedded image SBOM could not be read: "
                           f"{img_sbom_error or 'no document'}",
                "refs": [],
            })
            orphan_ref = str(uuid.uuid4())
            orphan_comp = {"type": "firmware", "name": img_name,
                           "version": "unknown", "bom-ref": orphan_ref}
            if add_scopes:
                orphan_comp["scope"] = "required"
            sbom["components"].append(orphan_comp)
            extra_seen_image_refs.add(orphan_ref)
            directly_installed_component_refs.add(orphan_ref)
            continue


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
                # The same package build seen through two documents: the
                # survivor unions both views' evidence - the higher
                # scope and every licence entry - so reconciliation never
                # discloses into evidence loss. Dependency evidence
                # unions separately as the image edges merge.
                _merge_instance_evidence(existing, inc_comp, add_scopes)

        # Add components unique to the included image (no instance match in the parent SBOM).
        for inc_comp in img_sbom_data.get("components") or []:
            inc_ref = inc_comp.get("bom-ref")
            key = _instance_key(inc_comp)
            if inc_ref and inc_ref in included_bom_ref_remap:
                continue
            if inc_ref and inc_ref in ref_components and \
                    _compatible_component_records(ref_components[inc_ref],
                                                  inc_comp):
                # The very same record; merging onto it loses nothing.
                # Contradicting evidence under a colliding bom-ref keeps
                # both instances and surfaces as a reference-integrity
                # finding, never a silent drop of an image component.
                continue
            if add_scopes and "scope" not in inc_comp:
                inc_comp = dict(inc_comp)
                inc_comp["scope"] = "required"
            sbom["components"].append(inc_comp)
            if inc_ref:
                extra_seen_image_refs.add(inc_ref)
                ref_components.setdefault(inc_ref, inc_comp)
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
        else:
            # No root to hang the graph on: the document is malformed.
            # Its components and edges stay in the merged graph and the
            # missing attachment is published as a finding instead of
            # being tidied away (ADR-0004).
            unattached = sorted({
                included_bom_ref_remap.get(entry.get("ref", ""),
                                           entry.get("ref", ""))
                for entry in img_sbom_data.get("dependencies") or []
                if entry.get("ref")
                and included_bom_ref_remap.get(entry.get("ref", ""),
                                               entry.get("ref", "")) not in
                extra_seen_image_refs})
            _log(log, "warn", f"CYCLONEDX_EXTRA_RUNTIME_IMAGE_RECIPES: "
                              f"{img_name} SBOM has no metadata.component "
                              f"bom-ref; its graph cannot be attached as "
                              f"a tree")
            merge_defects.append({
                "kind": "embedded-root-missing",
                "source": img_name,
                "message": "embedded image SBOM has no metadata.component "
                           "root" + (f"; unattached graph reference(s): "
                                     + ", ".join(unattached)
                                     if unattached else ""),
                "refs": unattached,
            })

        def remap_ref(ref, _remap=included_bom_ref_remap):
            return _remap.get(ref, ref)

        # Add dependency edges from the included SBOM, remapping shared bom-refs.
        # Merge into an existing dep entry when the ref is already present in the parent.
        for dep_entry in img_sbom_data.get("dependencies") or []:
            # Edges of the embedded graph ride along as they are; refs that
            # resolve to nothing after remapping become reference-integrity
            # findings and are never dropped to tidy the merged graph.
            r_ref = remap_ref(dep_entry.get("ref", ""))
            if not r_ref:
                continue
            r_depends = []
            for dr in dep_entry.get("dependsOn") or []:
                rdr = remap_ref(dr)
                if rdr == r_ref or rdr in r_depends:
                    continue
                r_depends.append(rdr)
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
            merge_defects.append({
                "kind": "embedded-vex-unusable",
                "source": img_name,
                "message": f"embedded image VEX could not be read: "
                           f"{img_vex_error}; its SBOM graph was still "
                           f"merged",
                "refs": [],
            })
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
            same_analysis = (
                (existing_vuln or {}).get("analysis", {}).get("state") ==
                inc_vuln.get("analysis", {}).get("state"))
            if existing_vuln and same_analysis:
                # One analysis seen twice: union the affected refs. A
                # differing analysis is a distinct statement about the
                # same CVE and rides along separately - folding would
                # silently lose it.
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


def _graph_integrity(sbom, root_ref):
    """
    Reference integrity of the finished dependency graph: unique bom-refs,
    resolvable references, and an unambiguous root. Detection only — the
    graph is never repaired by dropping nodes or edges (ADR-0004).
    """
    entries = sbom.get("dependencies") or []
    node_refs = set()
    duplicates = []
    for component in sbom.get("components") or []:
        ref = component.get("bom-ref")
        if not ref:
            continue
        if ref in node_refs or ref == root_ref:
            duplicates.append(ref)
        node_refs.add(ref)
    if root_ref in node_refs:
        duplicates.append(root_ref)

    dangling = []
    entry_counts = {}
    targets_of = {}
    for entry in entries:
        ref = entry.get("ref")
        targets = list(entry.get("dependsOn") or [])
        if ref:
            entry_counts[ref] = entry_counts.get(ref, 0) + 1
            targets_of.setdefault(ref, []).extend(targets)
            if ref not in node_refs and ref != root_ref:
                dangling.append(ref)
        for target in targets:
            if target not in node_refs and target != root_ref:
                dangling.append(target)

    ambiguous = []
    if any(root_ref in (entry.get("dependsOn") or []) for entry in entries):
        ambiguous.append(root_ref)
    ambiguous.extend(ref for ref, count in entry_counts.items() if count > 1)
    reachable = {root_ref}
    frontier = [root_ref]
    while frontier:
        for target in targets_of.get(frontier.pop(), []):
            if target in node_refs and target not in reachable:
                reachable.add(target)
                frontier.append(target)
    ambiguous.extend(ref for ref in node_refs if ref not in reachable)
    return {"duplicates": sorted(set(duplicates)),
            "dangling": sorted(set(dangling)),
            "ambiguous": sorted(set(ambiguous))}


def _graph_evidence(sbom, root_ref, ref_recipes, debug_evidence_recipes,
                    merge_defects, log):
    """
    Summarize the graph facts the requirements matrix evaluates: reference
    integrity (logged even without a profile, so defects are never silent),
    the bom-refs of components outside the scope of delivery, and the bom-
    refs of delivered recipes whose debug-source evidence is unavailable.
    """
    integrity = _graph_integrity(sbom, root_ref)
    for label, refs in (("duplicate bom-ref value", integrity["duplicates"]),
                        ("dangling dependency reference", integrity["dangling"]),
                        ("ambiguous dependency-graph root", integrity["ambiguous"])):
        if refs:
            _log(log, "warn", f"Graph integrity: {label}: {', '.join(refs)}")
    boundary_refs = sorted({
        component["bom-ref"] for component in sbom.get("components") or []
        if component.get("bom-ref") and any(
            property.get("name") == DELIVERY_SCOPE_PROPERTY
            for property in component.get("properties") or [])})
    static_unknown_refs = sorted({
        component["bom-ref"] for component in sbom.get("components") or []
        if component.get("bom-ref")
        and ref_recipes.get(component["bom-ref"]) is not None
        and ref_recipes.get(component["bom-ref"]) not in debug_evidence_recipes})
    return {"rootRef": root_ref, "integrity": integrity,
            "boundaryRefs": boundary_refs,
            "staticUnknownRefs": static_unknown_refs,
            "mergeDefects": merge_defects}


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

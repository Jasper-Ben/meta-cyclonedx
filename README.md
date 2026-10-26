# meta-cyclonedx

> **:warning: Before proceeding to read the documentation, please verify that
> you are on the correct branch for your Yocto release, as the feature set and
> default configurations may vary!**

The branch support policy for the BSI TR-03183-2 alignment capability is in
[docs/release-branches.md](docs/release-branches.md).

`meta-cyclonedx` is a [Yocto](https://www.yoctoproject.org/) meta-layer which
produces [CycloneDX](https://cyclonedx.org/) Software Bill of Materials
(aka [SBOMs](https://www.ntia.gov/SBOM)) from your target root filesystem.

## Features

This layer generates **CycloneDX** compliant SBOMs with the following features:

- Currently, support for CycloneDX specification 1.6 and 1.7
- Support for multiple supported Yocto (LTS) releases.
- Improved package matching against the [NIST NVD](https://nvd.nist.gov/) by
  fixing [CPE](https://nvd.nist.gov/products/cpe) generation process.
- Included [purl](https://github.com/package-url/purl-spec) package URLs.
- Added generation of an additional CycloneDX VEX file which contains
  information on patched and ignored CVEs from within the OpenEmbedded build
  system.
- Component scopes to differentiate between runtime (`required`) and build-time
  (`optional`) dependencies, enabling per-use-case SBOM filtering.
- Include component licenses.
- Added option to reduce the SBOM size by limiting SBOM collection to run-time
  packages ([which might potentially come at some expense](#potentially-missing-packages-after-runtime-filtering))
- Optional BSI TR-03183-2 alignment profile with `report` and `strict`
  enforcement, publishing a machine-readable alignment report beside the SBOM
  and VEX ([guide](docs/alignment-profile.md)).

This repository was originally forked from the
[BG Networks repository](https://github.com/bgnetworks/meta-dependencytrack).

## Installation

To install this meta-layer simply clone the repository into the `sources`
directory, check out the corresponding branch for your Yocto release
(e.g. scarthgap, kirkstone, ...)
and add it to your `build/conf/bblayers.conf` file:

```sh
cd sources
git clone https://github.com/iris-GmbH/meta-cyclonedx.git
cd meta-cyclonedx
git checkout <YOCTO_RELEASE>
```

and in your `bblayers.conf` file:

```sh
BBLAYERS += "${BSPDIR}/sources/meta-cyclonedx"
```

## Configuration

> **:warning: Breaking change when upgrading to Wrynose or later:**
> Starting with Wrynose the `CYCLONEDX_INCLUDE_UNPATCHED_VULNS` option requires
> the `sbom-cve-check` class, see [sbom-cve-check Results](#sbom-cve-check-results).

> **:warning: Breaking change in the release carrying TR-03183-2 alignment
> support:** components are now named and versioned by creator-assigned
> logical identity instead of CVE aliases, and CPE-equality deduplication is
> removed; component names, versions, counts and references change in every
> generated SBOM, with no compatibility mode. See the
> [migration guidance](docs/migration/tr-03183-alignment.md).

To enable and configure the layer simply inherit the `cyclonedx-export` class
in your `local.conf` file:

```sh
INHERIT += "cyclonedx-export"
```

### CycloneDX Specification Version

By default, meta-cyclonedx generates **CycloneDX 1.7** format SBOMs. You can configure a different version if needed:

```sh
CYCLONEDX_SPEC_VERSION = "1.7"  # Default - latest format
# Or for compatibility with older tools:
# CYCLONEDX_SPEC_VERSION = "1.6"
```

**Version differences:**

- **1.6**: Modern format with enhanced metadata and timestamps
- **1.7**: Latest version with advanced cryptography transparency (CBOM), intellectual property visibility, citations, and improved custom license handling (default)

### Image Component Version

The generated SBOM includes a top-level image component in metadata. Its version
value is controlled by CYCLONEDX_IMAGE_VERSION.

By default, this is derived from Yocto's distro/image version variables:

```sh
CYCLONEDX_IMAGE_VERSION = "${DISTRO_VERSION}${IMAGE_VERSION_SUFFIX}"
```

You can override it to match your release process (for example, a semantic
version, CI build number, or git tag):

```sh
CYCLONEDX_IMAGE_VERSION = "2026.07.0"
```

### Image Component Name

The name of the top-level image component in metadata is `${IMAGE_BASENAME}` by default.
You can change the name if necessary:

```sh
CYCLONEDX_IMAGE_NAME = "Fancy Image"
```

### Image Component Type

The type of the top-level image component in metadata is `firmware` by default.
You can change this type to match the type of your image if needed:

```sh
CYCLONEDX_IMAGE_TYPE = "operating-system"
```

Possible values depend on the configured CycloneDX specification version.
For a complete list see [CycloneDX 1.6](https://cyclonedx.org/docs/1.6/json/#metadata_tools_oneOf_i0_components_items_type),
[CycloneDX 1.7](https://cyclonedx.org/docs/1.7/json/#metadata_tools_oneOf_i0_components_items_type).

### Yocto Metadata Layer References

The layers that have a git remote url are added to the `externalReferences` of
the top-level image component in metadata by default. The `url` of the external
reference is in the format `{remote_url}@{revision}{is_modified}`. If the layer
has been modified, the `is_modified` in the url will be set to ` -- modified`.
Layers for which no git remote url can be resolved are skipped with a warning.
Credentials embedded in a resolved remote url are stripped from the reference
and its properties. Layer references use the CycloneDX `vcs` external reference
type.

For CycloneDX SBOMs with version 1.7 the name, remote url, revision and whether
it was modified are saved as `properties`. The property names for these are
`yocto:layer:name`, `yocto:layer:remote_url`, `yocto:layer:rev` and
`yocto:layer:is_modified` respectively.

You may disable this by setting:

```sh
CYCLONEDX_ADD_LAYER_REFERENCES = "0"
```

### Runtime vs Build-time Packages

By default, meta-cyclonedx will only include run-time packages in the SBOM,
which drastically reduces the number of potentially irrelevant packages.
However, this can lead to valid packages being omitted from the SBOM
(see [here](#potentially-missing-packages-after-runtime-filtering)).

If preferred, you can add the following configuration setting
(e.g in your local.conf), which will cause meta-cyclonedx to include
all build-time packages as well:

```sh
CYCLONEDX_RUNTIME_PACKAGES_ONLY = "0"
```

### Extra Runtime Recipes

Some components are embedded directly into the image without going through the
normal package installation process (e.g. OP-TEE compiled into a fitImage).
Because these recipes do not produce rootfs packages, they are not detected by
the standard runtime package discovery and would either be omitted (when
`CYCLONEDX_RUNTIME_PACKAGES_ONLY = "1"`) or included only as build-time
components with `scope = "optional"`/`"excluded"`.

Use `CYCLONEDX_EXTRA_RUNTIME_RECIPES` to explicitly list such recipes so that
they are always included in the SBOM with `scope = "required"`:

```sh
CYCLONEDX_EXTRA_RUNTIME_RECIPES = "optee-os trusted-firmware-a"
```

Multiple recipe names are separated by spaces. Each listed recipe must have
already run `do_populate_cyclonedx` during the build, otherwise an error is
raised and the recipe is skipped.

### Recipe-contributed CycloneDX Fragments

Language ecosystems that resolve their own dependency trees — cargo, npm, go —
are invisible to OpenEmbedded's package model. The image BOM lists the recipe
that builds the binary, but not the modules linked into it, so for instance a
Rust service appears as a single component while the crates it depends on
(and their advisories) are missing.

A recipe can close that gap by generating a CycloneDX document at build time and
pointing `CYCLONEDX_EXTRA_BOM_FILES` at it:

```sh
CYCLONEDX_EXTRA_BOM_FILES = "${B}/cargo-cyclonedx.json"
```

Multiple documents are separated by spaces. Each file is read during
`do_populate_cyclonedx`, so it must already exist by then — a recipe that
generates the document while building should order the task accordingly:

```sh
addtask do_populate_cyclonedx after do_compile
```

The components and dependency edges are merged into the image BOM verbatim.
They already carry their own bom-refs, purls and dependency edges, so the CPE
deduplication and the recipe-name dependency remapping applied to Yocto-derived
components are deliberately skipped — those would corrupt an externally
resolved tree. Duplicate `bom-ref`s (the same crate pulled in by two recipes)
are dropped, keeping the first occurrence.

The document's own root — `metadata.component`, the module the recipe builds —
is carried over as a component too, and a dependency edge is added from the
contributing recipe's component to it. The resulting tree therefore hangs off
the package it belongs to:

```
ripgrep (pkg:yocto)          the recipe, as discovered by Yocto
└── ripgrep (metadata.component of the contributed document)
    └── regex (pkg:cargo) → aho-corasick (pkg:cargo) → …
```

Both steps are needed: CycloneDX does not repeat `metadata.component` inside
`components`, yet the document's dependency edges reference it, so without
them the merged tree would hang off an unresolvable bom-ref and the modules
would float unattributed at the top level of the BOM.

By default, a missing or unparsable file will cause the build to fail.
You may change this behavior to emit only a warning instead
by setting:

```sh
CYCLONEDX_EXTRA_BOM_FILES_FAIL_ON_BROKEN_BOM_FILES = "0"
```

### Extra Runtime Image Recipes

Some images embed another complete image inside them — the most common case is a
initramfs that is bundled into a fitImage. The embedded image has its own rootfs
and its own components, and those components belong in the outer image's SBOM.

Because the embedded image is built separately, its SBOM is generated and
deployed independently. Use `CYCLONEDX_EXTRA_RUNTIME_IMAGE_RECIPES` to name the
image recipes whose completed SBOMs should be merged into the current image's
SBOM+VEX:

```sh
CYCLONEDX_EXTRA_RUNTIME_IMAGE_RECIPES = "dm-verity-image-initramfs"
```

Multiple image names are separated by spaces.

**Merging behaviour:**

- **Deduplication by CPE.** A component that exists in both SBOMs is kept
  exactly once (the parent's copy wins). Dependency edges from both images
  are preserved under the parent's `bom-ref`, so the dependency graph
  remains complete. The surviving copy keeps the more significant of the two
  scopes, ordered `required` > `optional` > `excluded`.
- **Unique components** from the included image are added to the parent SBOM
  with `scope = "required"`, unless they already declare a scope of their own.
- **The included image itself** appears as an additional `firmware` component
  with `scope = "required"` in the parent SBOM and is listed as a direct
  dependency of the parent image in the root `dependsOn` entry.
- **VEX vulnerabilities** are merged: the included image's SBOM serial is
  remapped to the parent's, shared `bom-ref`s are remapped, and CVE IDs are
  deduplicated — additional `affects` entries are appended to existing
  vulnerability records rather than creating duplicates.

All scope handling above is skipped when `CYCLONEDX_ADD_COMPONENT_SCOPES` is
disabled.

**Task ordering** is handled automatically. BitBake injects a
`do_cyclonedx_complete` dependency for each listed image into the parent's
`do_rootfs`. This waits for the included image's CycloneDX deployment and,
when that image inherits `sbom-cve-check`, its final CVE-enriched VEX.

The documents are read from an internal, sstate-managed image-data store,
not by reconstructing the included image's public filenames. Each image
publishes its own documents and a manifest selecting the VEX to consume.
The store is separated by multiconfig, package architecture and recipe.
It is restored with the corresponding deployment tasks, so lookup also
works when those tasks are restored from sstate.

Public SBOM/VEX filenames and links retain the usual image naming convention.
By default, image recipes publish these links:

```
${CYCLONEDX_EXPORT_DIR}/${IMAGE_LINK_NAME}.cyclonedx.bom.json
${CYCLONEDX_EXPORT_DIR}/${IMAGE_LINK_NAME}.cyclonedx.vex.json
```

The link paths can be customized with `CYCLONEDX_EXPORT_SBOM_LINK` and
`CYCLONEDX_EXPORT_VEX_LINK`, or disabled by setting them to an empty string.
Neither affects cross-image lookup. The included image can use a different
`IMAGE_BASENAME`, `IMAGE_NAME_SUFFIX`, timestamp or export directory.
If its internal image data is missing, a warning is emitted and the image
is skipped without failing the export.

### Logical Component Identity

Each recipe contributes exactly one logical component: an independently
assessable component instance with a creator-assigned name and version.
The defaults are the recipe's `BPN` and `PV` (shortened: `+git...`
suffixes are dropped), used only when semantically valid — a name-like
and version-like value; degenerate values degrade to the `"unknown"`
placeholder. Explicit overrides take precedence verbatim:

```sh
# Per-recipe, in the recipe or a .bbappend:
CYCLONEDX_COMPONENT_NAME = "upstream-widget"
CYCLONEDX_COMPONENT_VERSION = "2.4.1"
```

`CVE_PRODUCT` and `CVE_VERSION` are vulnerability-correlation aliases
only: they never create or rename components. Every whitespace-separated
alias token (including `vendor:`-qualified tokens, which qualify the
correlation CPE) remains available in the component's
`yocto:cve:product`, `yocto:cve:version` and `yocto:cve:cpe` properties,
so all aliases keep reaching CVE and VEX matching. The Yocto/package
identity of the build stays in the component purl (`pkg:yocto/...`,
OpenEmbedded's purl prefix) alongside the logical identity.

The component's single `cpe` uses the first declared `CVE_PRODUCT` token
crossed with the first declared `CVE_VERSION` token; repeated aliases are
deduplicated without changing declaration order in the properties.
Other aliases remain available for in-layer vulnerability matching, but
CPE-keyed external tools match the selected `cpe` field only.

Two component instances that share a CPE are never deduplicated: they
remain separate while their artifact, build, dependency, licence or
vulnerability evidence differs; indistinguishable duplicates produce a
`REQ-IDEN-001` alignment finding (see the alignment profile below) and a
build warning. Backported fixes are recorded as VEX statements and never
change the logical component version. See
`docs/migration/component-identity-cutover.md` for the breaking change
history.

### Dependency Graph

The primary component (the delivered product) is the root of the
dependency graph, and every component in the SBOM carries a `bom-ref`
and exactly one `dependencies` entry - leaves with an empty list, so a
machine can tell a known leaf apart from lost edges.

Known dependency recipes outside the scope of delivery are no longer
pruned: each path is followed to the first component outside the
delivery item, which joins the document as an identified component
(recipe name, `pkg:yocto/...` purl, scope `excluded` and a
`yocto:delivery:scope: external` property that keeps it distinct from
delivered instances). Resolution stops there; deeper dependencies are
not claimed without evidence.

Statically linked code is attributed from the debug-source lists
BitBake's own `do_package` already records in pkgdata: a
`/usr/src/debug/<BPN>/<PV>/` prefix of another recipe in a file's debug
sources identifies the recipe whose code was linked in and becomes a
dependency edge marked with a `yocto:dependency:evidence: debugsrc`
property. No delivered binary is ever parsed. Missing or inhibited
debug info (`INHIBIT_PACKAGE_DEBUG_SPLIT`) yields an honest unknown,
never an absence-of-dependencies claim.

CycloneDX `compositions` data declares the completeness of the
dependency evidence per component - `complete`, `incomplete` or
`unknown` - derived from those facts; unknown evidence never becomes a
`complete` declaration. Inconsistent references (duplicate `bom-ref`s,
dangling dependency references, ambiguous graph roots) are reported as
alignment findings with the affected references and are never silently
repaired: report enforcement publishes the graph as the build evidence
states it, strict enforcement fails on it. See
`docs/migration/graph-integrity-cutover.md` for the behavior changes.

### Component Scopes

When including both runtime and build-time packages, meta-cyclonedx uses
[CycloneDX component scopes](https://cyclonedx.org/docs/1.6/json/#components_items_scope)
to differentiate between them:

- Runtime packages are marked with `"scope": "required"`
- Build-time only packages are marked with `"scope": "optional"`

This allows tools to filter components based on their use case:

- **CVE matching**: Focus on components with `"scope": "required"`
- **License compliance**: Include all components regardless of scope
- **Supply chain tracking**: Include all components regardless of scope

Component scopes are enabled by default and available in both CycloneDX 1.6 and 1.7
specifications. If you need to disable them (e.g., for compatibility with certain
SBOM profiles or tools):

```sh
CYCLONEDX_ADD_COMPONENT_SCOPES = "0"
```

### Vulnerability Analysis Timestamps

By default, vulnerability analysis records include `firstIssued` and `lastUpdated`
timestamps in both CycloneDX 1.6 and 1.7. To generate minimal VEX documents without timestamps:

```sh
CYCLONEDX_ADD_VULN_TIMESTAMPS = "0"
```

### Kernel CVE Filtering

Kernel CVE feeds are matched by kernel version alone and routinely flag CVEs
whose affected files were never compiled into your particular kernel
configuration, so meta-cyclonedx cross-checks each kernel CVE's affected
files against the sources actually compiled for `virtual/kernel` and marks
the unaffected ones as `not_affected` in the VEX output, letting
DependencyTrack automatically filter them out instead of flagging them for
manual triage:

```sh
CYCLONEDX_VEX_ADD_KERNEL_CVE = "1"
```

This is disabled by default (`"0"`) and only applies to whichever recipe
provides `virtual/kernel`. No extra configuration is required: the CVE
database it relies on is fetched automatically.

### sbom-cve-check Results

Since Wrynose, OE-core checks the image SPDX SBOM for CVEs with the
`sbom-cve-check` class. For images inheriting it, meta-cyclonedx adds its
results to the VEX, so the analysis done at build time (fixed versions, stable
kernel backports, sources not compiled, `CVE_STATUS`, ...) reaches
DependencyTrack instead of showing up there as open findings. It is enabled
with the OE-core fragment:

```sh
bitbake-config-build enable-fragment core/yocto/sbom-cve-check
```

The fragment fetches the NVD and CVE List databases, several GB each, and
updates them on every build unless their revisions are pinned.

The results of each recipe are added to its components, matched by CPE, as
follows. Statements the VEX already has for a CVE and component are kept.

| sbom-cve-check status                    | VEX state                                                                                                         |
| ---------------------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| `Patched`, outside the affected versions | `not_affected`                                                                                                    |
| `Patched`, otherwise                     | `resolved`                                                                                                        |
| `Ignored`                                | `not_affected` (`code_not_present` for sources not compiled)                                                      |
| `Unpatched`                              | only with `CYCLONEDX_INCLUDE_UNPATCHED_VULNS = "1"`, with `CYCLONEDX_UNPATCHED_VULNS_STATE` (default `in_triage`) |

The merged VEX is written after `do_sbom_cve_check` to
`CYCLONEDX_EXPORT_SBOM_CVE_CHECK_VEX` (default
`${IMAGE_NAME}.cyclonedx.sbom-cve-check.vex.json`), and
`CYCLONEDX_EXPORT_VEX_LINK` points at it. The report is read through the
`${IMAGE_LINK_NAME}` link, and `SBOM_CVE_CHECK_EXPORT_CVECHECK` must stay in
`SBOM_CVE_CHECK_EXPORT_VARS` (the default).

### Component Licenses

By default, component licenses are included in the SBOM.

You may choose to exclude license information from your SBOM:

```sh
CYCLONEDX_ADD_COMPONENT_LICENSES = "0"
```

The licenses data is taken from the component recipe
(see [LICENSE](https://docs.yoctoproject.org/singleindex.html#term-LICENSE).
Single licenses are matched against a list of [known SPDX licenses](/https://github.com/iris-GmbH/meta-cyclonedx/tree/main/meta/files/spdx-license-list-data)
where possible.

These are original licence evidence only - the licences the component
creator assigned, carried with the CycloneDX acknowledgement `declared`.
The distribution and effective licence roles and their authoritative
sources are documented under "Licence Roles" in the alignment profile
section below.

If multiple licenses are specified using `&` or `|`, the license is converted
into a [SPDX license expression](https://spdx.github.io/spdx-spec/v2.3/SPDX-license-expressions/#).

Additionally, simple expressions (only containing "AND" operators) are split
into multiple license entries by default, improving the SBOM data quality.
Note however, that this might not be supported by your SBOM consuming tool of
choice (e.g. [DependencyTrack](https://github.com/DependencyTrack/dependency-track/issues/170)).

To disable this feature you can set

```sh
CYCLONEDX_SPLIT_LICENSE_EXPRESSIONS = "0"
```

### Component Source and Build Input References

By default, `externalReferences` using `SRC_URI` aren't added to components.
This can be enabled by setting:

```sh
CYCLONEDX_ADD_COMPONENT_SOURCE_REFERENCES = "1"
```

The generated references describe both component source locations and direct
local build inputs. Version-control fetchers use the CycloneDX `vcs` external
reference type; other remote fetchers use `distribution`.

For remote sources, the `url` of the external reference is the URL from
`SRC_URI`. If a revision is set for that source, `@{revision}` will be added to
the external reference's `url` as well. Hashes set for a remote source are
included in the `hashes` property.

A `SRC_URI` entry that embeds credentials, e.g.
`https://user:token@git.internal/repo.git`, is published without them: the
reference `url` and the `yocto:src_uri` property use the credential-free URL,
which stays usable with the consumer's own credentials. The build log notes
the stripping and masks the credentials.

Direct `file://` entries that resolve inside a configured Yocto metadata layer
are included as `other` references. Their URL has the form
`file:{layer}/{layer-relative-path}`, and regular files include a computed
SHA-512 hash. The reference comment identifies the owning layer. Entries that
cannot be resolved or attributed to a configured layer are skipped with a
warning.
Absolute local paths are normalized to the layer-relative URL so build-host
paths are not exposed.

Local VCS repositories are not added because they do not provide portable
component source locations. Fetchers whose effective transport is `file`, such
as `git://` or `gitsm://` with `protocol=file` or without a hostname, are
skipped with a warning. References are collected without network access;
sources whose revision can only be resolved by contacting the network (e.g.
`AUTOREV`) are skipped with a warning. Every warning identifies the affected
`SRC_URI` entry, with credentials masked.

For CycloneDX SBOMs with version 1.7, the URL, revision and options of a source
are added as properties named `yocto:src_uri`, `yocto:srcrev` and
`yocto:src_uri:{option}` respectively. Local file references also include
`yocto:layer:name` and `yocto:layer:path`. When present, the corresponding
top-level Yocto metadata layer reference supplies its remote URL, revision and
modification state.

### Component Properties

The CycloneDX spec supports a `properties` array on components for arbitrary
organization-specific metadata (e.g. downstream/vendor tagging). You can
populate it per-recipe with a space-separated list of `name=value` pairs:

```sh
CYCLONEDX_COMPONENT_PROPERTIES = "custom:modified=true custom:team=platform"
```

Entries missing an `=` are skipped with a warning rather than failing the
build. The variable is empty (no properties added) by default.

### CycloneDX 1.7 Optional Features

When using CycloneDX 1.7, you can enable additional optional features for enhanced SBOM quality:

#### License Expression Details

For custom or proprietary licenses (appearing as `LicenseRef-*` in expressions), you can include the actual license text in the SBOM:

```sh
CYCLONEDX_ADD_LICENSE_DETAILS = "1"  # default: enabled for 1.7
```

This feature extracts license text from:

- Yocto's `COMMON_LICENSE_DIR` (e.g., `/meta/files/common-licenses/`)
- Package-specific license files referenced in `LIC_FILES_CHKSUM`

The license text is embedded in the SBOM's `expressionDetails` field, enabling SBOM consumers to view the full license content without external lookups.

#### Citations

Citations document the SBOM's provenance and generation methodology:

```sh
CYCLONEDX_ADD_CITATION = "1"  # default: enabled for 1.7
```

This adds a root-level `citations` array attributing the document to the yocto
tooling recorded in `metadata.tools`, enabling supply chain transparency.

#### Traffic Light Protocol (TLP) Marking

For enterprise environments, you can mark SBOMs with TLP distribution restrictions:

```sh
CYCLONEDX_TLP_MARKING = "GREEN"  # options: CLEAR, GREEN, AMBER, AMBER_AND_STRICT, RED
```

TLP markings control how the SBOM can be shared:

- `CLEAR`: Unlimited distribution
- `GREEN`: Community-wide distribution
- `AMBER`: Limited distribution to organizations
- `AMBER_AND_STRICT`: Limited distribution to specified recipients only
- `RED`: Personal for named recipients only

Leave empty (default) to omit TLP marking.

#### Unsupported Advanced Features

The following CycloneDX 1.7 features are **not currently supported** due to the high implementation complexity and lack of native Yocto support:

**Cryptography Bill of Materials (CBOM)**

- Documents cryptographic algorithms, certificates, keys, and protocols
- Use case: Post-quantum cryptography (PQC) readiness and compliance
- Why unsupported: Requires binary analysis tools to detect crypto usage in compiled packages. Yocto does not natively track cryptographic algorithms used by components.
- Manual workaround: Use the `properties` field to add custom crypto metadata if needed

**Patent Assertions**

- Documents patent ownership, licensing, and defensive termination clauses
- Use case: IP due diligence, M&A activities, patent litigation defense
- Why unsupported: Requires manual legal research and patent database maintenance per package. Open source recipes do not include patent information.
- Manual workaround: Use the `properties` field or external SBOM enrichment tools

If you have specific requirements for these features, consider using external SBOM enrichment tools after generation or contributing implementations that integrate with specialized crypto scanners.

### BSI TR-03183-2 Alignment Profile

Selecting an **alignment profile** makes meta-cyclonedx apply BSI TR-03183-2
mappings and checks and publish a machine-processable **alignment report**
next to the SBOM and the separate VEX document. The alignment capability is
**not a conformance claim**: meta-cyclonedx never labels an SBOM, product or
manufacturer conformant with TR-03183-2 or the CRA. The **conformance
determination** remains the manufacturer's own conclusion and requires
completeness evidence that meta-cyclonedx cannot see.

The full usage, integration and interpretation guide is
[docs/alignment-profile.md](docs/alignment-profile.md); what to expect when
upgrading across this release is in
[docs/migration/tr-03183-alignment.md](docs/migration/tr-03183-alignment.md).

```sh
# Versioned alignment profile; empty disables alignment output (default).
# "tr03183-2.1" pins the profile baseline to BSI TR-03183-2 v2.1.0 and the
# BSI CycloneDX property taxonomy v0.1.2 on CycloneDX 1.6 or 1.7.
CYCLONEDX_PROFILE = "tr03183-2.1"

# Alignment enforcement (default: "report"):
#   report - publish SBOM, VEX and alignment report despite known gaps
#   strict - fail the build on machine-detectable violations or missing
#            required assertions (still no conformance claim)
CYCLONEDX_PROFILE_ENFORCEMENT = "report"
```

Unsupported profile names, unsupported enforcement values, enforcement
without a profile, and profile selections below CycloneDX 1.6 fail during
configuration.

The report is deployed as `${CYCLONEDX_EXPORT_BASENAME}.alignment-report.json`
(configurable via `CYCLONEDX_EXPORT_ALIGNMENT_REPORT`). It is byte-for-byte
deterministic for equivalent build facts: it records the exact profile
baseline (TR-03183-2 v2.1.0, BSI CycloneDX property taxonomy v0.1.2, the
selected CycloneDX schema and the requirements-matrix version), and one
finding per requirements-matrix row with a stable requirement identifier,
its normative source, applicability, verdict (`verified`, `asserted`,
`unmet` or `unverifiable`), evidence origin, affected component references
where applicable and a diagnostic message. Caller assertions can only ever
produce `asserted` findings, never `verified` ones, and `unverifiable`
findings never block the output.

#### Validation Before Publication

With a profile selected, every emitted document is validated before
publication. Every check is a requirements-matrix row, so its verdict
rides the alignment report and gates strict enforcement exactly like
every other finding:

- **Official CycloneDX schema.** Every emitted SBOM and VEX validates
  against the official JSON schema of the selected CycloneDX version
  (`REQ-FMT-002`, `REQ-FMT-003`). The official schemas are vendored
  with the layer under `lib/data/cyclonedx/` (provenance and pin in
  the README there); the `jsonschema` library is feature-detected. A
  build host without it records `unverifiable` schema findings - a
  validator that cannot run never reports a silent pass, and
  `unverifiable` never blocks `strict` enforcement.
- **BSI property taxonomy.** Every `bsi:` property is validated against
  the pinned registry of the profile baseline (property taxonomy
  v0.1.2, vendored verbatim under `lib/data/` and mirrored as the
  matrix's own registry): only registered names count and only in the
  locations the registry allows (`REQ-TAX-001`), values must sit in the
  registry's value domains (`REQ-TAX-002`), and per-component
  cardinality must hold - the executable/archive/structured triple
  complete exactly once when it applies, filename and licence
  properties at most once (`REQ-TAX-003`). Drift away from the pinned
  registry is an `unmet` finding in report mode and a
  strict-enforcement rejection.
- **Identifier syntax.** Emitted identifiers stay parseable downstream:
  every purl parses as a Package URL (`REQ-IDEN-002`), every CPE -
  component field or correlation alias - is a formatted CPE 2.3 string
  (`REQ-IDEN-003`), and every SHA-512 is lowercase hex of 512 bits
  riding `components[].hashes[]` under the `SHA-512` algorithm
  (`REQ-IDEN-004`).
- **Vulnerability separation.** No vulnerability data hides anywhere in
  the SBOM - a document-wide scan catches embedded or nested records
  the renderer copied verbatim (`REQ-VULN-001`) - and every VEX
  assertion resolves to a logical, non-file component of the product:
  files are delivery detail, never vulnerability subjects
  (`REQ-VULN-002`).
- **Enforcement equivalence.** A defect that yields an `unmet` finding
  in report mode rejects the same input under `strict` enforcement -
  there is one requirements matrix and one verdict path. The structured
  strict failure lists every machine-detectable violation at once
  (`violations`, ordered by requirement identifier, each with its
  diagnostic message and affected bom-refs), so one build reports the
  complete repair list.
- **Report enforcement publishes documents with findings** - that
  includes a schema-invalid document: it is published with loud
  `unmet` findings naming the violated schema locations, and the
  finding keeps the alignment report honest about the defect. **Strict
  enforcement refuses publication** of the same document before any
  artifact is deployed. This split is deliberate: report mode exists
  to make gaps visible in CI, strict mode to gate them.

#### Creator and URI Evidence

With a profile selected, the product integration supplies the creator
metadata explicitly; meta-cyclonedx never infers creators from free-form
text and never names the product manufacturer as the creator of bundled
third-party software.

```sh
# Entity responsible for compiling this SBOM (metadata.authors).
# Entries are separated by ';' and each entry is
#   "NAME <email-or-url>", "<URL>", a bare email address or a bare URL.
CYCLONEDX_SBOM_CREATOR = "Acme SBOM Team <sbom@acme.example>; https://acme.example"

# Creator of the delivered product (metadata.component); same grammar.
CYCLONEDX_PRIMARY_COMPONENT_CREATOR = "Acme GmbH <product@acme.example>"

# Per-recipe creator override for third-party components; takes
# precedence over trustworthy upstream metadata (see below).
CYCLONEDX_COMPONENT_CREATOR = ""
```

For third-party components the creator precedence is: the explicit
`CYCLONEDX_COMPONENT_CREATOR` override, then **semantically trustworthy
upstream metadata** — only the machine-readable upstream repository
identity already recorded for the component: an upstream repository purl
(`pkg:github|gitlab|bitbucket/...`, whose namespace is the upstream
organization) or a fetcher-derived `vcs` external reference, from which
the upstream organization and repository URL are derived — then
unresolved, which the alignment report records as `unverifiable`
(never `verified`, never fabricated).

Source and deployable URIs follow the same trust rule: they are emitted
only from the explicit override variables
(`CYCLONEDX_COMPONENT_SOURCE_URI`, `CYCLONEDX_COMPONENT_DEPLOYABLE_URI`,
`CYCLONEDX_PRIMARY_COMPONENT_SOURCE_URI`,
`CYCLONEDX_PRIMARY_COMPONENT_DEPLOYABLE_URI`) or from metadata the layer
already records (SRC_URI-derived references, layer revisions), and every
emitted URI is syntax-validated; recorded URIs that fail validation are
not emitted and are reported as `unmet`. Equivalent normalized evidence
always produces identical creator, URI and report output.

#### Licence Roles

Recipe `LICENSE` metadata is **original licence** evidence - the
licences assigned by a component's creator - with the `declared`
acknowledgement. CycloneDX 1.7 carries it in `licenses`; when a
distribution expression is also supplied, CycloneDX 1.6 carries the
original declarations in `evidence.licenses` and the distribution
expression in `licenses`, respecting 1.6's single-expression constraint.
Distribution and effective licences exist only when explicitly supplied;
neither is inferred from `LICENSE` or from the other role:

```python
# The licence under which recipients may use the component; an SPDX
# licence expression, the explicitly identified semantically
# authoritative source (recipe scope: components built here; image
# scope: the delivered product).
CYCLONEDX_DISTRIBUTION_LICENCE = "MIT"

# The licence under which the creator of this SBOM uses the component;
# optional, represented with the bsi:component:effectiveLicence
# property only where supplied.
CYCLONEDX_EFFECTIVE_LICENCE = ""
```

The renderer validates expressions against the SPDX licence and exception
lists pinned to the selected CycloneDX version. `WITH` exceptions such as
`GPL-2.0-only WITH Linux-syscall-note` are supported; OE `&` and `|`
operators normalize to SPDX `AND` and `OR`. No legal or composition
analysis is performed. Missing required original or distribution evidence
is `unmet`, never filled by relabelling another role (ADR-0003).
Caller-supplied licence assertions remain `asserted`, never `verified`.

The versioned mapping from each baseline requirement to its CycloneDX
representation and evaluation rule is project-owned data in
`lib/alignment_profile.py`; an existing profile never floats to a newer
guideline, taxonomy or schema version.

Note: at this stage the profile's requirements matrix covers the
TR-03183-2 v2.1.0 data-field, dependency-graph and mandatory file
inventory baseline. Where the build itself cannot establish completeness
(component discovery, dependency depth beyond the scope of delivery,
missing debug information), the findings are `unverifiable` - a valid
result that never blocks the output.

#### File Inventory

With an alignment profile selected, the build additionally inventories
the **mandatory delivered files** and represents each as a CycloneDX
`type: file` component (ADR-0005): every delivered executable and
archive in the final root filesystem, the image's **primary deployable
artifact**, and the **additional files** the product integration selects
below. Files created by post-install scripts or image customization are
included even without package ownership. Without a profile the inventory
is fully inactive - no file is read, hashed or represented, and the
SBOM is byte-comparable to earlier logical-component output. This
default is intentional: ordinary configuration, documentation and data
files stay omitted unless an explicit selection includes them.

Representation per inventoried file:

- `name`: the delivered filename (path basename); the `version` is the
  creator-assigned version of the delivering recipe's logical
  component - or, for unowned rootfs files and deploy-directory artifacts,
  of the primary component
- `hashes`: one SHA-512 over the delivered bytes - the artifact
  identity; modes, paths and timestamps never enter the hash
- `properties`: the pinned taxonomy's `bsi:component:filename`
  (`executable|non-executable`), `bsi:component:archive`
  (`archive|no archive`) and `bsi:component:structured`
  (`structured|unstructured`) values
- `bom-ref`: the deterministic `yocto-file:<recipe>:<delivered path>`
  (`yocto-file::<absolute rootfs path>` for unowned rootfs files,
  `yocto-file::<relative deploy path>` for deploy-directory artifacts)
- graph participation: the delivering logical component's dependency
  entry gains the file reference; the primary component owns unclaimed
  rootfs files and deploy-directory artifacts. Each file is a leaf with
  an empty list and never copies its owner's CPE, purl, licences, creator
  or vulnerability findings (ADR-0006). VEX targets logical instances only.

Classification is deterministic artifact inspection (ADR-0002): mode
exec bits, `#!` shebangs and ELF signatures decide executability;
container and compressed-stream magics (zip, tar, cpio, ar/deb, rpm,
7z, gzip, xz, bzip2, zstd) decide archive status; `structured` reflects
the metadata the artifact still carries - entry tables for archives,
an ELF symbol table (a stripped ELF is `unstructured`) - inspected one
nesting level deep for compressed tars. No binary analysis, dependency
inference, debug-info extraction or plugin/`dlopen()` discovery ever
happens; static-link attribution comes from pkgdata debug-source
records only. Symlinks are not inventoried as separate artifacts: a
link is a second name for the regular file it resolves to, which is
inventoried itself. Discovery walks the final root filesystem in a
`do_rootfs` post-function, after rootfs customization and while pseudo
is active. Pkgdata `files_info` records attribute known paths but do not
limit discovery; uninstalled package paths do not become missing files.
Only mandatory regular files are hashed. The final deployment reuses
this inventory snapshot rather than reopening the rootfs outside pseudo.

Mandatory artifacts that are missing, unreadable or too truncated to
classify never vanish from the output: they produce `REQ-FILE-00x`
alignment findings naming the affected file references (`REQ-FILE-001`
inventory coverage, `REQ-FILE-002` artifact inspection, `REQ-FILE-003`
graph participation, `REQ-FILE-004` primary deployable artifact,
`REQ-FILE-005` additional-file selection). `report` enforcement
publishes documents and findings; `strict` enforcement fails on them.

##### Primary deployable artifact and selected additional files

The delivered image itself belongs to the mandatory inventory even
though no root-filesystem package manifest names it. Because image
assembly finishes after `do_rootfs`, the artifact bytes are not final
during the document generation inside `do_rootfs`; hashing them there
would chase a moving target. Image recipes with a profile therefore
generate the final documents once more in `do_deploy_cyclonedx`, which
now runs after `do_image_complete`: there the primary artifact's content is
final, its bytes are hashed, and the entry joins the same file-
inventory facts (`source: deployable`, owned by the primary component
under the recipe-less facts key). Names come from the stable
`${IMAGE_LINK_NAME}.<IMAGE_FSTYPES>` lineage (the same lineage the
export basename follows), never the `DATETIME`-stamped filenames, and
hashes cover content only - equivalent rebuilds, including
sstate-restored artifacts under a fresh build stamp, reproduce identical
inventories.

```python
# Explicitly selected additional deployed files (default: "").
# Whitespace-separated shell-style globs (fnmatch; `*` crosses
# directory boundaries) matched against paths relative to the image
# deploy directory ${DEPLOY_DIR_IMAGE}; a leading "/" anchors there too.
# This includes payloads deployed by kernel, bootloader and firmware
# recipes, not just the image recipe's private staging directory.
# A selection that resolves to nothing is a REQ-FILE-005 finding,
# never silently skipped.
CYCLONEDX_ADDITIONAL_FILES = "bzImage* *.efi firmware/*.bin initramfs-*.cpio.gz"
```

Kernel, bootloader, firmware, trusted-execution-environment, initramfs,
embedded-image and other product payloads selected this way use the
same deterministic classification, SHA-512 identity, BSI properties and
graph rules as root-filesystem file components; they carry the primary
component's version and hang off the graph root. Repeated discovery of
one artifact instance through package, deployable or selection evidence
deduplicates by artifact reference (recipe namespace plus delivered
path): one component, one graph edge, one composition; the same bytes
delivered at a different path remain distinct artifact instances.
Deploy-phase cost: one deploy-directory walk plus SHA-512 of each
deployable and selected file.

### Minimal SBOM Configuration

Meta-cyclonedx supports generating a **minimal SBOM** that includes only the essential information required by the CycloneDX specification. This is useful for:

- Reducing SBOM file size
- Compliance with minimal SBOM requirements
- Fast SBOM generation
- Environments with strict data minimization policies

#### What's Included in a Minimal SBOM

The minimal SBOM always contains:

**Component Information:**

- `name` - Component name
- `version` - Component version
- `type` - Component type (typically "library")
- `bom-ref` - Unique reference identifier

**Identifiers:**

- `cpe` - Common Platform Enumeration for vulnerability matching
- `purl` - Package URL for package identification

**Relationships:**

- `dependencies` - Component dependency graph

**Metadata:**

- `bomFormat`, `specVersion`, `serialNumber`, `version`
- `timestamp` - SBOM generation time
- `tools` - SBOM generation tool information

**VEX (Vulnerability Exploitability Exchange):**

- `vulnerabilities` - CVE status information (patched/ignored)

#### Minimal Configuration Example

To generate a minimal SBOM, disable all optional features:

```sh
INHERIT += "cyclonedx-export"

# Use minimal configuration
CYCLONEDX_SPEC_VERSION = "1.7"           # or "1.6"
CYCLONEDX_RUNTIME_PACKAGES_ONLY = "1"    # Runtime packages only
CYCLONEDX_ADD_COMPONENT_SCOPES = "0"     # Disable scope marking
CYCLONEDX_ADD_VULN_TIMESTAMPS = "0"      # Disable VEX timestamps
CYCLONEDX_ADD_COMPONENT_LICENSES = "0"   # Exclude licenses
```

This produces the smallest valid CycloneDX SBOM with only essential vulnerability and package information.

### Advanced Configuration Summary

```sh
# Specification version (default: "1.7")
CYCLONEDX_SPEC_VERSION = "1.7"  # or "1.6"

# Version for metadata.component in the generated SBOM
# (default: "${DISTRO_VERSION}${IMAGE_VERSION_SUFFIX}")
CYCLONEDX_IMAGE_VERSION = "${DISTRO_VERSION}${IMAGE_VERSION_SUFFIX}"

# The top-level image component type.
# Value must be a valid CycloneDX specified type (default: "firmware").
CYCLONEDX_IMAGE_TYPE = "firmware"

# Include build-time packages (default: "1" = runtime only)
CYCLONEDX_RUNTIME_PACKAGES_ONLY = "1"

# Add component scopes (default: "1")
CYCLONEDX_ADD_COMPONENT_SCOPES = "1"

# Add vulnerability timestamps in 1.6+ (default: "1")
CYCLONEDX_ADD_VULN_TIMESTAMPS = "1"

# Filter kernel CVEs against actually-compiled sources (default: "0").
CYCLONEDX_VEX_ADD_KERNEL_CVE = "0"

# Add component licenses (default: "1")
CYCLONEDX_ADD_COMPONENT_LICENSES = "1"

# split license expressions into multiple license entries
# when possible (default: "1")
CYCLONEDX_SPLIT_LICENSE_EXPRESSIONS = "1"

# Space-separated "name=value" pairs attached to this recipe's components
# as a CycloneDX properties array (default: "").
CYCLONEDX_COMPONENT_PROPERTIES = ""

# Explicit logical component identity overrides (default: "" = BPN/PV).
CYCLONEDX_COMPONENT_NAME = ""
CYCLONEDX_COMPONENT_VERSION = ""

# Creator evidence (contact grammar "NAME <email-or-url>", "<URL>",
# a bare email address or a bare URL; ';' separates multiple contacts).
# The product manufacturer is never the creator of third-party components.
CYCLONEDX_SBOM_CREATOR = ""
CYCLONEDX_PRIMARY_COMPONENT_CREATOR = ""
CYCLONEDX_COMPONENT_CREATOR = ""

# Explicit source/deployable URIs; the only sources besides recorded
# metadata are these overrides, and URIs are syntax-validated (default: "").
CYCLONEDX_COMPONENT_SOURCE_URI = ""
CYCLONEDX_COMPONENT_DEPLOYABLE_URI = ""
CYCLONEDX_PRIMARY_COMPONENT_SOURCE_URI = ""
CYCLONEDX_PRIMARY_COMPONENT_DEPLOYABLE_URI = ""

# CycloneDX 1.7 optional features
CYCLONEDX_ADD_LICENSE_DETAILS = "1"  # Include license text for custom licenses
CYCLONEDX_ADD_CITATION = "1"         # Document SBOM provenance
CYCLONEDX_TLP_MARKING = ""           # TLP marking (CLEAR|GREEN|AMBER|AMBER_AND_STRICT|RED)

# Space-separated list of recipes to always include with scope "required",
# even if they do not produce rootfs packages (default: "").
CYCLONEDX_EXTRA_RUNTIME_RECIPES = ""

# BSI TR-03183-2 alignment profile (default: "", no alignment output)
CYCLONEDX_PROFILE = ""                    # or "tr03183-2.1"
CYCLONEDX_PROFILE_ENFORCEMENT = "report"  # or "strict"
CYCLONEDX_EXPORT_ALIGNMENT_REPORT = "${CYCLONEDX_EXPORT_BASENAME}.alignment-report.json"

# Profile-gated: explicitly selected additional deployed files.
# Whitespace-separated globs relative to the image deploy directory
# ${DEPLOY_DIR_IMAGE}; a leading "/" anchors there too (default: "").
# The primary deployable
# artifact is always inventoried under a profile; ordinary data files
# are not.
CYCLONEDX_ADDITIONAL_FILES = ""
```

### Use with non-rootfs image recipes

The default use of `cyclonedx-export.bbclass` only produces SBOM for recipes
that inherits `image.bbclass`. In order to produce an SBOM for an image like
recipe that does not generate a filesystem image, and thus not inherits
`image.bbclass`, you can use the `CYCLONEDX_EXPORT_DEPENDS` variable to list the
dependencies to consider/include. Something like this

```sh
CYCLONEDX_EXPORT_DEPENDS = "${DEPENDS}"
```

The dependencies will be filtered so that non-target recipes are excluded, and
the remaining dependencies will be processed with `PREFERRED_PROVIDER_*`
variables, so that you can include things like `virtual/bootloader` and
`virtual/kernel`.

Note: There is no recursion of `CYCLONEDX_EXPORT_DEPENDS`, so only the listed
dependencies are included in the SBOM. So while this does allow using with any
kind of recipe, it is in-practise mainly usable for simple compound images, like
a bootloader image consisting of the output from a handful of recipes.

In addition to settting `CYCLONEDX_EXPORT_DEPENDS` you will also need to hook up
`do_populate_cyclonedx` and `do_deploy_cyclonedx` tasks. The
`do_populate_cyclonedx` task should be added to `recrdeptask` flag on the recipe
task that produces the image output, and the `do_deploy_cyclonedx` task should
be added to the recipe.

#### Example for producing SBOM for a genimage.bbclass recipe

This is an example of how to produce SBOM for an image recipe using
`genimage.bbclass` from [meta-ptx](https://github.com/pengutronix/meta-ptx):

```sh
CYCLONEDX_EXPORT_DEPENDS = "${DEPENDS}"
do_genimage[recrdeptask] += "do_populate_cyclonedx"
addtask do_deploy_cyclonedx after do_deploy before do_build
```

## Usage

Once everything is configured simply build your image as you normally would.
By default the final CycloneDX SBOM and VEX files are saved to the same folder
as the corresponding image file(s) (`${DEPLOY_DIR_IMAGE}`), using a filename suffix of
`.cyclonedx.bom.json` and `.cyclonedx.vex.json` respectively.

## Uploading to DependencyTrack (tested against DT v4.11.4)

While this layer does not offer a direct integration with DependencyTrack
(we consider that a feature, since it removes dependencies to external
infrastructure in your build),
it is perfectly possible to use the produced SBOMs within DependencyTrack.

DependencyTrack supports ingesting CycloneDX **1.7** documents only since
version **5.1.0** ([release notes](https://dependencytrack.org/news/dependency-track-5-1)).
If your DependencyTrack instance is older than that, set
`CYCLONEDX_SPEC_VERSION = "1.6"` — older versions will reject the default
1.7 output outright.

At the time of writing DependencyTrack does not support uploading component
and vulnerability information in one go (which is why we currently create a
separate `vex.json` file). The status on supporting this may be tracked
[here](https://github.com/DependencyTrack/dependency-track/issues/919).

### Manual Upload

1. Go into an existing project in your DependencyTrack instance or create a new
   one.
2. Go to the _Components_ tab and click _Upload BOM_.
3. Select the `bom.json` file from your deploy directory.
4. Wait for the vulnerability analysis to complete.
5. Go to the _Audit Vulnerabilities_ tab and click _Apply VEX_.
6. Select the `vex.json` file from your deploy directory.

### Automated Upload

You may want to script the upload of the SBOM files to DependencyTrack,
e.g. as part of a CI job that runs after your build is complete.

This is possible by leveraging DependencyTracks REST API.

Please refer to [DependencyTracks REST API documentation](https://docs.dependencytrack.org/integrations/rest-api/)
regarding the usage of these endpoints as well as the required token
permissions.

An example python script can be found at
`examples/automated-dependencytrack-upload.py` and may be freely used (CC0-1.0).

## Contributing

Thanks for your interest in contributing to `meta-cyclonedx`!

Please read the dedicated [./CONTRIBUTING.md](CONTRIBUTING.md) file before
opening issues or pull requests.

### Development

SBOM and VEX document semantics live in the layer's `lib/meta_cyclonedx.py`
renderer module, which consumes normalized build and artifact facts; the
`cyclonedx-export` class is a BitBake adapter that collects those facts and
deploys the documents. The renderer is importable without a Yocto build and
is covered by a behavioral test suite:

```sh
python3 -m pytest tests/
```

Maintainers can run the kas acceptance matrix with `pytest -m integration`;
prerequisites and the deployed-artifact checks are described in
[docs/testing.md](docs/testing.md).

## Known Limitations

### Potentially Missing Packages After Run-time Filtering

We use the `image_list_installed_packages` function from upstream
OpenEmbedded as a means to reduce the SBOM contents to packages that are added
to the final resulting rootfs. This drastically reduces the "noise" generated
by CVEs in build-time dependencies. This however comes with some potential
downsides (i.e. Missing some packages), as discussed
[here](https://github.com/savoirfairelinux/meta-cyclonedx/issues/9#issue-2494183505).

### Missing Dependencies with Modern Programming Languages

OpenEmbedded and its core mechanisms work best with "traditional" programming
languages such as C and C++, as these are the languages that they were
initially designed around. For instance, a core-assumption prevalent in many
OE mechanisms (including those we depend on in meta-cyclonedx) is that each
library is described in its own OE recipe. This however does not work well
with many modern programming languages, which often come with their own package
managers (e.g. NPM, Cargo, Go Modules, ...), which OpenEmbedded does not know
about. As a result, additional dependencies pulled in by the respective
programming language's package manager will be missing from the SBOM
generated by this layer, unless additional steps are taken.

Please refer to the section [Recipe-contributed CycloneDX Fragments](#recipe-contributed-cyclonedx-fragments)
on how to include these dependencies in the SBOM generation process.

### Kernel CVE Filtering Depends on an Internal oe-core Script

`CYCLONEDX_VEX_ADD_KERNEL_CVE` relies on oe-core's internal
`scripts/contrib/improve_kernel_cve_report.py`, which is not a stable,
guaranteed API and could move or change in a future Yocto release.

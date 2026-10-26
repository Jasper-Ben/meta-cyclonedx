# BSI TR-03183-2 alignment profile: user and integration guide

Audience: manufacturers configuring the profile, compliance engineers
reading its output, and integrators supplying the evidence the build
cannot derive on its own. Configuration grammar lives in the
[README](../README.md#bsi-tr-03183-2-alignment-profile); this guide
explains what the profile does, what its artifacts mean and what it
deliberately does not claim.

## What the profile is - and what it is not

The alignment profile is a versioned configuration that applies BSI
TR-03183-2 mappings and checks to the generated documents and publishes
a machine-processable alignment report beside them. It produces
**alignment evidence, not TR-03183-2 certification and not a CRA
conformance determination**. meta-cyclonedx never labels an SBOM, a
product or a manufacturer conformant.

The **conformance determination** - the conclusion that a product meets
the Cyber Resilience Act and the TR-03183 series - stays with the
manufacturer. It additionally requires completeness evidence the build
cannot see: which components exist outside the delivered artifacts,
which dynamically loaded code ran, which obligations apply to the
product. Every alignment report carries this statement in its
`conformanceDetermination` field. `unverifiable` findings are not
failures of the tool; they name exactly where that external evidence
becomes necessary.

Terminology: the feature produces a **build-time delivery-item SBOM**
and offers **runtime package selection** as a build-time filter
(`CYCLONEDX_RUNTIME_PACKAGES_ONLY`). Neither is a "Runtime SBOM": the
output is generated during the build and never observes executing
software. Use those terms exactly; see the glossary in `CONTEXT.md`.

## Selecting the profile

```python
# The only profile implemented so far; the name carries the baseline.
CYCLONEDX_PROFILE = "tr03183-2.1"

# "report" (default) or "strict". Requires CYCLONEDX_PROFILE.
CYCLONEDX_PROFILE_ENFORCEMENT = "report"
```

`tr03183-2.1` pins its **profile baseline** to BSI TR-03183-2 v2.1.0
plus the BSI CycloneDX property taxonomy v0.1.2, evaluated on CycloneDX
specification 1.6 or 1.7 (`CYCLONEDX_SPEC_VERSION`, default 1.7). The
requirements matrix that turns baseline requirements into verdicts is
project-owned, versioned data (currently 2.1.0-r9) in
`lib/alignment_profile.py`; no third-party validator decides the
verdict.

Unsupported profile names, unsupported enforcement values, enforcement
without a profile and profile selections outside the supported
CycloneDX versions fail during configuration, before any document is
generated. An empty `CYCLONEDX_PROFILE` (the default) keeps the plain
unaligned output.

## Enforcement: report and strict

- **`report`** publishes the SBOM, the VEX and the alignment report
  despite known gaps. Unmet and unverifiable findings ride along in the
  report; nothing is silently repaired. This is the mode for
  introducing alignment incrementally and for making gaps visible in
  CI.
- **`strict`** fails the build at the generating task - inside
  `do_rootfs` for the root-filesystem documents, and inside
  `do_deploy_cyclonedx` for the regenerated documents that carry the
  final deployable artifact hashes. The failure is one aggregated
  rejection listing every machine-detectable violation at once, sorted
  by requirement identifier, each with its diagnostic message and
  affected component references. **No artifact is deployed on
  rejection.**

Strict rejection triggers on `unmet` findings only: machine-detectable
violations and missing required assertions. `verified`, `asserted` and
`unverifiable` findings never fail a strict build - `unverifiable`
marks evidence the build cannot establish, and gating on it would turn
an honest unknown into a false gate. Strict enforcement is an alignment
gate; it makes no conformance claim either.

## Generated artifacts

With a profile selected, the build deploys three documents to
`${CYCLONEDX_EXPORT_DIR}` (default `${DEPLOY_DIR_IMAGE}`), each with a
stable `${IMAGE_LINK_NAME}`.cyclonedx.* symlink for image builds:

| Artifact | Default name | Content |
| SBOM | `${CYCLONEDX_EXPORT_BASENAME}.bom.json` | Build-time delivery-item SBOM; no vulnerability records |
| VEX | `${CYCLONEDX_EXPORT_BASENAME}.vex.json` | Separate vulnerability status, addressing logical components |
| Alignment report | `${CYCLONEDX_EXPORT_BASENAME}.alignment-report.json` | One finding per requirements-matrix row; byte-deterministic for equivalent facts |

Without a profile, only the SBOM and VEX are produced: the file
inventory is fully inactive - no file is read, hashed or represented -
and the output stays byte-comparable to pre-profile releases.

## Reading the alignment report

The report's `profileBaseline` block records exactly what was
evaluated: `guideline` (BSI TR-03183-2), `guidelineVersion` (2.1.0),
`propertyTaxonomyVersion` (0.1.2), `cyclonedxSchemaVersion` (the
selected schema) and `requirementsMatrixVersion`. Results are
reproducible after standards change because the versions are named,
never "latest".

Each finding carries a stable requirement identifier (`REQ-*`), its
normative source, applicability, verdict, evidence origin, the affected
`bomRefs` where applicable, and a diagnostic message.

Verdicts are exactly:

| Verdict | Meaning |
| --- | --- |
| `verified` | Established from evidence the build itself checked |
| `asserted` | Taken from an explicit caller assertion; strength is "stated", not "checked" |
| `unmet` | A detectable violation, or a required assertion that is missing |
| `unverifiable` | The build cannot establish the result; a valid, necessary outcome |

A requirement is never `verified` merely because a caller asserted it.

Evidence origins name where the deciding evidence came from:

| Origin | Source of the evidence |
| --- | --- |
| `generated-document` | The emitted documents themselves (schema, taxonomy, reference and structure checks) |
| `caller-assertion` | An explicit override the product integration supplied |
| `recipe-metadata` | Yocto recipe and pkgdata metadata (e.g. `LICENSE`, debug-source records) |
| `upstream-metadata` | Trustworthy upstream records (repository purl, recorded VCS reference) |
| `artifact-inspection` | Deterministic examination of delivered files (inventory, classification, hashing) |
| `external-evidence` | Evidence meta-cyclonedx does not possess; the finding states what the manufacturer must supply |

## Integrating a product

The profile derives what build metadata proves and never guesses what
it does not. These are the explicit inputs a product integration
should supply; full grammar is in the README.

- **Explicit logical identity.** Where a recipe's BPN/PV differ from
  the creator-assigned upstream identity, set
  `CYCLONEDX_COMPONENT_NAME` / `CYCLONEDX_COMPONENT_VERSION` in the
  recipe. Defaults stay BPN/PV when semantically valid;
  `CVE_PRODUCT`/`CVE_VERSION` are vulnerability-correlation aliases
  only and never define identity.
- **SBOM and component creators.** Set `CYCLONEDX_SBOM_CREATOR` (who
  compiled the SBOM) and `CYCLONEDX_PRIMARY_COMPONENT_CREATOR` (the
  product manufacturer). For third-party components use
  `CYCLONEDX_COMPONENT_CREATOR`; otherwise trustworthy upstream
  metadata (repository purl or recorded VCS reference) is used, and
  missing evidence stays an honest `unverifiable` finding. The
  manufacturer is never the blanket creator of bundled software.
- **Licence roles.** Recipe `LICENSE` is original licence evidence
  only. Supply `CYCLONEDX_DISTRIBUTION_LICENCE` where the delivery
  terms are authoritative, and `CYCLONEDX_EFFECTIVE_LICENCE` only when
  genuinely determined. The generator performs no legal or licence
  composition analysis and never converts one role into another.
  The renderer validates SPDX licence and exception identifiers. With both
  original and distribution roles present, CycloneDX 1.6 preserves original
  declarations in `evidence.licenses`; 1.7 supports both roles in `licenses`.
- **Trusted URIs.** Source and deployable URIs are emitted only from
  the explicit overrides (`CYCLONEDX_COMPONENT_SOURCE_URI`,
  `CYCLONEDX_COMPONENT_DEPLOYABLE_URI`,
  `CYCLONEDX_PRIMARY_COMPONENT_SOURCE_URI`,
  `CYCLONEDX_PRIMARY_COMPONENT_DEPLOYABLE_URI`) or from metadata the
  layer already records, and every emitted URI is syntax-validated.
- **Primary deployable artifact.** Covered automatically: image builds
  regenerate the documents in `do_deploy_cyclonedx`, where the final
  image bytes are hashed and joined to the file inventory. No
  configuration is required; `${IMAGE_LINK_NAME}`-lineage names keep
  the entries stable across rebuilds.
- **Delivered rootfs files.** The final rootfs is walked after rootfs
  customization. Package metadata attributes known files; executables
  and archives without a package owner attach to the primary component.
- **Additional files.** Select product payloads (kernel, bootloader,
  firmware, TEE, initramfs, embedded images) with
  `CYCLONEDX_ADDITIONAL_FILES` globs against `${DEPLOY_DIR_IMAGE}`. A
  selection that resolves to nothing is a `REQ-FILE-005` finding,
  never a silent skip.
- **Separate VEX handling.** The SBOM contains no vulnerability data.
  VEX statements address logical component instances - never file
  components - and backported fixes are expressed as VEX status without
  changing the upstream component version.
  Dangling targets remain visible in report enforcement and fail strict
  enforcement. Equal analysis states do not merge distinct justifications,
  details or responses.

## What the build cannot see

Dependency evidence comes from Yocto metadata, from statically linked
edges observed in the pkgdata debug-source records BitBake's own
`do_package` writes, and from imported ecosystem BOMs. The limits are
permanent, not bugs to fix:

- `dlopen()`, plugin loading and any other runtime loading stay
  undiscovered; meta-cyclonedx performs no binary analysis and no
  automatic dependency discovery.
- Source attribution of data files is not derived; configuration,
  documentation and ordinary data files are not inventoried unless
  explicitly selected.
- Where debug info is inhibited (`INHIBIT_PACKAGE_DEBUG_SPLIT`) or
  absent, static-link evidence is **unknown** - never reported as an
  absence of dependencies.

The SBOM's CycloneDX composition data declares `complete`, `incomplete`
or `unknown` dependency evidence per component accordingly, and the
alignment report records the corresponding `unverifiable` findings.
Consumers should read those declarations rather than assume a
structurally valid graph is a complete one.

## Baseline and matrix governance

Standards versions never float automatically. `tr03183-2.1` pins TR-03183-2
v2.1.0 and taxonomy v0.1.2 forever; a newer guideline, taxonomy or
CycloneDX schema becomes available only as a new, explicitly reviewed
profile identifier plus a reviewed requirements-matrix revision.
Community validators (e.g. `sbomqs`) run as differential checks in
maintainer CI: disagreement prompts review of the affected matrix rows
and never silently changes a verdict.

## Related documents

- [README configuration reference](../README.md#bsi-tr-03183-2-alignment-profile)
- [Migration guidance for this release](migration/tr-03183-alignment.md)
- [Release-branch support policy](release-branches.md)
- [Testing and acceptance evidence](testing.md)

# Release notes

Entry text for tagged releases; the `+semver:` commit trailers drive
the version bump, this file is the curated note body. Release branches
carry only what the
[release-branch support policy](release-branches.md) allows them to.

## Unreleased (development branch)

### Breaking changes

- **Logical component identity cutover.** Component names and
  versions are now creator-assigned (`BPN`/`PV` by default,
  `CYCLONEDX_COMPONENT_NAME`/`CYCLONEDX_COMPONENT_VERSION` as
  overrides) instead of derived from `CVE_PRODUCT`/`CVE_VERSION`;
  CVE aliases no longer create components, and CPE equality no longer
  merges component instances. Component names, versions, counts and
  the set of `bom-ref`s change in every generated SBOM, in ordinary
  output as well as profile output. There is no compatibility mode.
  Expect different diff output against pre-upgrade documents; this is
  the identity correction, not data loss. See the
  [migration guidance](migration/tr-03183-alignment.md).
- **Declaration-order CPE alias selection.** For multi-alias recipes, the
  first declared `CVE_PRODUCT` token crossed with the first declared
  `CVE_VERSION` token now wins the component `cpe` field instead of the
  alphabetically first tokens. CPE-keyed tools may re-key findings to
  that alias; no findings are lost from in-layer matching because the
  full alias set remains in the `yocto:cve:*` properties.
- **Dependency graph integrity.** Every component now carries a
  dependency entry (leaves included), dependencies outside the scope
  of delivery are published as identified boundary components instead
  of being pruned, and broken or duplicate references become visible
  findings instead of silent repairs.

### New features

- **BSI TR-03183-2 alignment profile** (`CYCLONEDX_PROFILE =
  "tr03183-2.1"`): TR-03183-2 v2.1.0 mappings and checks on CycloneDX
  1.6/1.7 with the BSI property taxonomy v0.1.2, publishing a
  deterministic machine-readable alignment report beside the SBOM and
  the separate VEX document. `report` enforcement publishes documents
  and findings; `strict` enforcement fails the build on every
  machine-detectable violation with an aggregated rejection. The
  report is alignment evidence for the manufacturer's own
  determination; it is not an approval and decides nothing itself. See the
  [alignment profile guide](alignment-profile.md).
- **Opt-in CPE collision deduplication** (`CYCLONEDX_DEDUPLICATE_CPE_COLLISIONS
  = "1"`): merge explained native-recipe CPE twins for CPE-keyed tooling,
  selecting the lowest-purl survivor and remapping dependency and VEX
  references. Enabled output is a lossy projection, not a truthful
  per-instance inventory; alignment profiles reject the flag at parse time.
  The default output remains unchanged.
- **File inventory**: delivered executables, archives and the primary
  deployable artifact are represented as file components with SHA-512
  artifact identities; `CYCLONEDX_ADDITIONAL_FILES` selects further
  product payloads.
- **Creator, licence-role and URI evidence**: explicit SBOM/product/
  component creator inputs, recipe `LICENSE` as original-licence
  evidence only, and syntax-validated URIs from trustworthy sources
  only.

### Fixes

- Keep imported and embedded component instances separate when hashes,
  build metadata, licences, dependency graphs or VEX analyses differ,
  even if name, version and purl match. Compatible partial records may
  still enrich an existing instance without discarding evidence.
- Record missing or malformed optional imported BOMs without crashing
  or reusing the previous successfully read document.
- Validate explicit licence expressions in the renderer against the
  selected SPDX licence and exception lists; support `WITH` exceptions
  and normalize OE `&`/`|` operators.
- Preserve both licence roles in schema-valid CycloneDX 1.6 output:
  original declarations in `evidence.licenses`, distribution expression
  in `licenses`. The requirements matrix revision is `2.1.0-r9`.
- Inventory executables and archives from the final rootfs, including
  generated files without package ownership, and select additional
  deployables from `${DEPLOY_DIR_IMAGE}` after `do_image_complete`.
- Preserve dangling VEX targets for report findings and strict
  rejection. Merge statements only when their substantive analysis
  agrees, not merely their CVE ID or analysis state.
- Read sbomqs v2 structural feature results instead of an obsolete JSON
  layout and aggregate quality score. Installed-tool errors no longer
  become skips; actual matrix/tool disagreements remain visible.


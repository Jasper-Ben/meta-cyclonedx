# Migrating to the TR-03183-2 alignment release

Audience: consumers diffing SBOMs across this upgrade, recipe authors,
and downstream tooling owners. This is the consolidated migration
guidance for the identity and graph cutovers; the detail fragments
[component-identity-cutover.md](component-identity-cutover.md) and
[graph-integrity-cutover.md](graph-integrity-cutover.md) remain the
authoritative per-change records and are summarized here. Delivery is
on the development branch; see the
[release-branch support policy](release-branches.md) for which branches
carry this behavior.

## The identity cutover is breaking, with no compatibility mode

The corrected component model applies globally to ordinary output and
alignment-profile output alike. There is no compatibility switch, no
migration flag and no profile-only legacy model (ADR-0009). Expect the
following observable changes when comparing against pre-upgrade SBOMs;
each is the correction of a former conflation of identities, not data
loss.

- **Component names.** Components are named by creator-assigned
  logical identity - `CYCLONEDX_COMPONENT_NAME` when set, otherwise
  the recipe's `BPN` - not by `CVE_PRODUCT` tokens. Recipes whose
  `CVE_PRODUCT` differed from `BPN` now emit the recipe/BPN name; the
  CVE alias survives only as a `yocto:cve:product` property and in the
  correlation CPE. Vendor-qualified aliases no longer set the
  component `group`.
- **Component versions.** The version is the creator-assigned logical
  version - `CYCLONEDX_COMPONENT_VERSION` when set, otherwise the
  short `PV` when semantically valid. `CVE_VERSION` never changes it;
  backported fixes are VEX status and leave the upstream version
  untouched.
- **Component counts move in both directions.** Recipes with several
  `CVE_PRODUCT` aliases emitted one component per alias and now emit
  exactly one - counts shrink, and duplicated VEX findings disappear.
  Recipes previously collapsed onto another recipe's component through
  CPE-equality deduplication now each contribute their own instance -
  counts grow where independently assessable instances had been
  silently merged.
- **References.** Which `bom-ref`s exist changes: one stable logical
  component per recipe instead of one per CVE alias, no refs silently
  rewritten through the removed deduplication map, and VEX `affects`
  targeting exactly those logical component-instance refs. Ref values
  were already regenerated per build (random UUIDs); file components
  add deterministic `yocto-file:<recipe>:<delivered path>` refs.
  Yocto/package identity remains on every logical component as the
  `pkg:yocto/...` purl.

Graph output changes the same way: every component gains a dependency
entry (leaves with an empty list), scope-of-delivery boundary
components appear as identified `scope: excluded` entries instead of
being pruned, and dangling or duplicate references surface as findings
instead of silent repairs. See
[graph-integrity-cutover.md](graph-integrity-cutover.md).

## Consumer migration

- Expect different component `name`/`version` values and different
  component counts; validate against the two fragments before
  concluding a regression.
- Correlate vulnerabilities through `purl`, the component `cpe` and
  the `yocto:cve:*` properties; do not key tooling on `name` alone.
- Deduplicate or merge SBOM records by `purl` plus version evidence,
  never by CPE: matching CPE alone never authorizes merging component
  instances.
- Key file correlation on the SHA-512 artifact identity and the
  `yocto-file:` references, which are stable across reruns.

## Terminology

The generated document is a build-time delivery-item SBOM, and the
existing `CYCLONEDX_RUNTIME_PACKAGES_ONLY` filter is runtime package
selection - a build-time filter that never observes executing
software. Neither is a "Runtime SBOM"; documentation and integrations
must not reintroduce that label.

## Related documents

- [Alignment profile guide](../alignment-profile.md)
- [Release notes](../release-notes.md)
- [Release-branch support policy](release-branches.md)

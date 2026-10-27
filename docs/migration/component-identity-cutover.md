# Breaking change: logical component identity cutover

Audience: consumers diffing SBOMs across this upgrade and recipe authors.
This fragment collects the observable identity changes; the
[consolidated migration guidance](tr-03183-alignment.md) links the
fragments for consumers. Development branch only; not backported to
Wrynose or Scarthgap.

## What changed

All generated SBOMs stop treating CVE aliases as component identity
(ADR-0006, ADR-0009). There is no compatibility switch: ordinary output
and alignment-profile output share the corrected model.

1. **Component names.** Components are named by creator-assigned logical
   identity, not by `CVE_PRODUCT` tokens:
   - default: the recipe's `BPN`,
   - override: `CYCLONEDX_COMPONENT_NAME` (takes precedence verbatim).
   Recipes whose `CVE_PRODUCT` differed from `BPN` (e.g. `tiff.bb` with
   `CVE_PRODUCT = "libtiff"`) now emit the recipe/BPN name; the CVE
   alias survives only as a `yocto:cve:product` property and in the
   correlation CPE. Vendor-qualified aliases (`vendor:name`) no longer
   set the component `group`; the vendor qualifies only the CPE.

2. **Component counts.**
   - Recipes with several whitespace-separated `CVE_PRODUCT` aliases
     previously emitted one component per alias and now emit exactly
     **one** component: alias-generated components and their duplicated
     VEX findings disappear.
   - Recipes that previously collapsed onto another recipe's component
     through CPE-equality deduplication now each contribute their own
     component instance: counts **grow** where independently assessable
     instances had been silently merged.
   - Imported and embedded graphs use name, version and purl only to
     nominate merge candidates. Conflicting artifact hashes, build
     metadata, licences, dependency instances or VEX analyses keep
     instances separate, even when all package coordinates match.

3. **Component versions.** The version is the creator-assigned logical
   version: `CYCLONEDX_COMPONENT_VERSION` when set, otherwise the short
   `PV` (with `+git...` suffixes dropped) when semantically valid.
   Validity is deliberately narrow: the name must be a single
   identifier-like token (letters/digits plus `.+_~-`), the version an
   identifier-like token containing at least one digit. Degenerate
   defaults degrade to `"unknown"`; an explicit override is authoritative
   verbatim. `CVE_VERSION` never changes the logical version — backports
   are expressed through VEX status, and a patched CVE leaves the
   upstream version untouched.

4. **References.** Every `bom-ref` was already regenerated per build
   (random UUIDs); this cutover does not change that. What changes is
   which refs exist: one stable logical component per recipe instead of
   one per CVE alias, and no refs silently rewritten through the removed
   deduplication map. VEX `affects` references target exactly these
   logical component-instance refs.

5. **Package identity.** Yocto/package identity remains on every logical
   component as the package purl `pkg:yocto/...` (the purl type
   OpenEmbedded's `oe.purl.get_base_purl` mints; the ecosystem
   convention already used across this layer). It supplements, never
   replaces, the logical name and version.

6. **Collisions.** CPE equality never deduplicates components. When
   component instances share CPEs, they stay separate; with differing
   artifact, build, dependency, licence or vulnerability evidence the
   separation is explained (build log note, `REQ-IDEN-001` verified),
   while indistinguishable duplicates are reported as an unmet
   `REQ-IDEN-001` alignment finding naming the affected bom-refs and a
   build warning, and strict enforcement rejects them.
   Ordinary output retains this model by default. Integrators targeting
   CPE-keyed tools may explicitly opt into the lossy
   [`CYCLONEDX_DEDUPLICATE_CPE_COLLISIONS`](../../README.md#cpe-collision-deduplication-opt-in)
   and/or view-only
   [`CYCLONEDX_EXPAND_CVE_PRODUCT_ALIASES`](../../README.md#cve-product-alias-expansion-opt-in)
   projections. Together the flags expand aliases first, then deduplicate
   the projected rows across recipes; neither flag changes the fragment
   identity model, and alignment-profile output accepts neither flag
   ([ADR-0013](../adr/0013-keep-cpe-projections-at-render-boundary.md)).


7. **Winning correlation alias.** For multi-alias recipes the component
   `cpe` now uses the first declared `CVE_PRODUCT` token crossed with the
   first declared `CVE_VERSION` token, not the alphabetically first.
   CPE-keyed findings may re-key to that alias; no findings are lost
   from in-layer matching because all aliases remain in `yocto:cve:*`
   properties in declaration order.

7. **Winning correlation alias.** For multi-alias recipes the component
   `cpe` now uses the first declared `CVE_PRODUCT` token crossed with the
   first declared `CVE_VERSION` token, not the alphabetically first.
   CPE-keyed findings may re-key to that alias; no findings are lost
   from in-layer matching because all aliases remain in `yocto:cve:*`
   properties in declaration order.

## Consumer migration

- Expect different component `name`/`version` values and different
  component counts when diffing against pre-upgrade SBOMs; this is the
  correction, not data loss.
- Correlate vulnerabilities through `purl`, the component `cpe` and the
  `yocto:cve:*` properties; do not key tooling on `name` alone.
- Matching `purl` and version alone does not establish instance identity.
  Check artifact, build, licence, dependency and VEX evidence before
  reconciling records; never deduplicate on CPE equality.

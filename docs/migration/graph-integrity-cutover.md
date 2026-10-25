# Breaking change: core graph integrity cutover

Audience: consumers diffing SBOMs across this upgrade and recipe authors.
This fragment collects the observable dependency-graph changes for the
final migration guidance (ticket #13 reuses it). Development branch only;
isolated lossless-graph correctness fixes may be considered for Wrynose or
Scarthgap only after separate risk assessment.

## What changed

The dependency graph became complete and truthful without ever repairing
inconsistencies silently (ADR-0004). Ordinary output and alignment-profile
output share one graph model; there is no compatibility switch.

1. **Graph completeness.** Every component in `components` now appears
   exactly once in `dependencies`, leaves with an empty `dependsOn` list.
   Diff tools will see many new single-entry nodes; they mark known
   leaves, not lost edges.

2. **Scope-of-delivery boundary components.** Dependencies naming a
   recipe that is not part of the delivery item were previously dropped
   with a debug-level "not in this image" note. They are now followed to
   the first external component, which is published as an identified
   component: the recipe name, version `unknown`, `pkg:yocto/<name>`
   purl, scope `excluded` and a `yocto:delivery:scope: external`
   property. Component counts and graph size grow wherever evidence had
   been pruned. Resolution stops at the boundary; no deeper edges are
   claimed.

3. **Statically linked edges.** Recipes whose pkgdata debug-source
   records contain `/usr/src/debug/<other-BPN>/<PV>/` paths gain
   dependency edges to that other recipe's logical component, marked
   with a `yocto:dependency:evidence: debugsrc` property on the
   depending component. Edges derived from build records that package
   metadata missed make graphs larger, not wrong; no binary is parsed.

4. **Composition declarations.** SBOMs now carry a `compositions` array
   declaring, per component, whether the dependency evidence behind its
   graph entry is `complete`, `incomplete` or `unknown`. Components
   without usable debug-source evidence are declared `unknown` - never
   `complete` - so a structurally valid graph is not mistaken for a
   complete one.

5. **No silent repair.** Dependency entries whose own `bom-ref` named no
   component were previously discarded during assembly, and embedded
   image edges pointing at absent nodes were pruned during merge. Both
   are now published as the build evidence states them and surface as
   `REQ-REF-001` alignment findings (duplicate `bom-ref`s, dangling
   references, ambiguous graph roots) with the affected references.
   Under `strict` enforcement such graphs fail; under `report`
   enforcement they publish with their defects visible.

## What did not change

- VEX reference resolution stays as before: statements affecting only
  absent components are still dropped from the separate VEX document.
  This ticket's no-repair rule covers the dependency graph.
- bom-ref values remain random UUIDs, regenerated on every build;
  compare graphs by component identity, not by ref values.

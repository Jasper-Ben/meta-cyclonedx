# Release-branch support for the TR-03183-2 alignment capability

Audience: manufacturers choosing a branch and maintainers deciding what
lands where. Delivery of the alignment capability follows one policy;
it does not promise feature parity across branches.

## Development-first delivery

The complete clean cutover - the corrected identity model, graph
integrity, file inventory, creator and licence evidence, validation
and both enforcement modes - is developed and verified on the
development branch first, and only there by default. Release branches
receive reviewed changes from that verified line; they never carry a
parallel implementation.

## Per-branch policy

| Branch | Alignment support | Policy |
| --- | --- | --- |
| Development branch (`main`) | Complete capability, verified | Full implementation and the acceptance evidence below |
| Wrynose | None as of this release | Conditional: additive alignment and validation changes may be backported after development-branch verification, each with independently backported behavior and independent verification. Non-additive changes (the identity and graph cutovers) are not backported. |
| Scarthgap | None as of this release | Low-risk by default: documentation, validators and low-risk correctness guidance only. Larger changes require an explicit branch decision and independent evidence. |
| EOL branches | None | No new CRA or TR-03183 functionality, ever. Older branches do not acquire an assurance claim nobody maintains. |

The identity cutover and the graph-integrity cutover are breaking and
stay development-branch only (see the
[migration guidance](migration/tr-03183-alignment.md)); a release
branch must never half-adopt them, because a partial identity
correction produces exactly the ambiguity the cutover removes.

## Independent verification before any branch advertises support

An alignment claim is never inherited from another Yocto generation.
A branch may be advertised as supporting the alignment capability only
when it links, from that branch itself:

1. **Schema evidence** - its documents validated against the official
   CycloneDX schemas of the supported versions,
2. **Renderer evidence** - its renderer behavior test suite passing on
   that branch's code, and
3. **Completed-build evidence** - a completed BitBake acceptance build
   deploying the SBOM, VEX and alignment report, with the strict
   scenario observed failing at the public task surface.

How those checks run: the unit tier (`python3 -m pytest`, whose renderer
suite is the primary behavioral seam) and the kas acceptance tier
(`pytest -m integration`) are documented in [docs/testing.md](testing.md).
Until a branch links all three, it advertises none of the capability,
whatever another branch proves.

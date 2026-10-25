<!-- SPDX-License-Identifier: MIT -->
<!-- SPDX-FileCopyrightText: meta-cyclonedx contributors -->

# Vendored official CycloneDX JSON schemas

Schema files used to validate every generated and deployed SBOM and VEX
document: the renderer evaluates its `REQ-FMT-002`/`REQ-FMT-003`
alignment findings through `lib/schema_validation.py`, and the
integration tier validates deployed documents
(`tests/integration/test_deployed_artifact_oracle.py`) with the same
module. They are vendored so schema validation needs neither network
access nor a schema bundled by a third-party library's defaults — see
the acceptance-harness spec, "Schema validation".

| File | Role |
| --- | --- |
| `bom-1.6.schema.json` | The CycloneDX 1.6 JSON schema (validates SBOM and VEX output generated with `CYCLONEDX_SPEC_VERSION = "1.6"`) |
| `bom-1.7.schema.json` | The CycloneDX 1.7 JSON schema (validates both the SBOM and the VEX document) |
| `spdx.schema.json` | Transitive `$ref` of both bom schemas (SPDX license identifiers) |
| `jsf-0.82.schema.json` | Transitive `$ref` of both bom schemas (JSON Schema Form) |
| `cryptography-defs.schema.json` | Transitive `$ref` of `bom-1.7.schema.json` (cryptographic argument definitions) |

## Provenance and license

All five schemas come unmodified from the CycloneDX specification
repository <https://github.com/CycloneDX/specification>, directory `schema/`,
pinned at commit
[`0bd48c88d1b1877c7a3536252e06893850763190`](https://github.com/CycloneDX/specification/commit/0bd48c88d1b1877c7a3536252e06893850763190)
(2026-02-25, newest revision of `bom-1.7.schema.json`; the 1.6 schema and
the transitive reference files are taken from that same commit so the
whole set is one pinned snapshot).

The schemas are licensed under the Apache License, Version 2.0 — the full
text is in [`LICENSE`](LICENSE), the specification repository's license file.
The schema files themselves carry `"license": [{ "id": "Apache-2.0" }]`
declarations. This repository's own MIT license applies only to the
validation code around them.

Refresh the pin by re-downloading the files from a newer `schema/`
revision and updating the commit above. Profiles never float: a schema
refresh only changes what a *new* profile baseline evaluates.

# SPDX License List Data

This folder contains known SPDX licenses, as published [here](https://github.com/spdx/license-list-data).

While poky comes with it's own spdx license list (poky/meta/files/spdx-licenses.json),
the license list data version must align with the CycloneDX spec version.

## Version Mapping

- **CycloneDX 1.6** uses [SPDX License List v3.23](https://github.com/CycloneDX/specification/blob/1.6/schema/spdx.schema.json#L4) → `licenses-1.6.json`
- **CycloneDX 1.7** uses [SPDX License List v3.27](https://github.com/CycloneDX/specification/blob/1.7/schema/spdx.schema.json#L4) → `licenses-1.7.json`

The matching exception vocabularies are vendored unmodified from
[v3.23 exceptions.json](https://github.com/spdx/license-list-data/blob/v3.23/json/exceptions.json)
and [v3.27.0 exceptions.json](https://github.com/spdx/license-list-data/blob/v3.27.0/json/exceptions.json)
as `exceptions-1.6.json` and `exceptions-1.7.json`. SPDX's
[generated-data licensing notes](https://github.com/spdx/license-list-data#licensing-information)
identify the source definitions and publishing tool for licensing information.
The renderer uses both lists for explicit distribution/effective licence
expressions, including `WITH` exceptions; the adapter only collects assertions.


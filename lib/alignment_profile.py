# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: Copyright (C) 2026 iris-GmbH infrared & intelligent sensors.

"""Versioned BSI TR-03183-2 alignment profiles and requirements matrix.

This module owns the project-owned alignment profile data: every supported
alignment profile names its exact profile baseline (the TR-03183-2 guideline
version, the BSI CycloneDX property taxonomy version and the supported
CycloneDX schema versions) and carries the versioned requirements matrix
that maps each normative requirement of that baseline to its CycloneDX
representation and evaluation rule.

The matrix is data, not control flow scattered through the renderer:
findings are produced by evaluating the rows against a rendered document.
Adding a requirement means adding a row here and bumping the matrix
version; a profile never floats to a later guideline, taxonomy or CycloneDX
schema.

meta-cyclonedx uses this to produce an alignment report; it never labels an
SBOM, product or manufacturer conformant with TR-03183-2 or the CRA.
"""

# Evaluation rules return a verdict for one requirement against one
# rendered document set; they live next to the rows they evaluate.

TR03183_2_REQUIREMENTS = []

PROFILES = {
    # The versioned TR-03183-2 alignment profile. The name carries the
    # exact baseline: an existing profile never moves to a newer guideline,
    # property taxonomy or CycloneDX schema.
    "tr03183-2.1": {
        "alignmentProfile": "tr03183-2.1",
        "guideline": "BSI TR-03183-2",
        "guidelineVersion": "2.1.0",
        "propertyTaxonomyVersion": "0.1.2",
        "requirementsMatrixVersion": "2.1.0-r1",
        "specVersions": ["1.6", "1.7"],
        "requirements": TR03183_2_REQUIREMENTS,
    },
}

# Supported alignment enforcement values: "report" publishes the documents
# and the alignment report despite known gaps; "strict" fails the build on
# every machine-detectable violation or missing required assertion.
ENFORCEMENT_VALUES = ["report", "strict"]

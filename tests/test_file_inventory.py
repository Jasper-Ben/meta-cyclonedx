"""The root-filesystem file inventory at the renderer seam.

With the alignment profile selected, every delivered executable and
archive arrives as a normalized artifact fact and must be composed into
an exact file component: delivered filename, SHA-512 artifact identity,
the pinned BSI file properties, and a traceable owning relationship -
without ever copying the owning logical component's identity. Ordinary
(non-profile) output stays a logical-component-only document (ADR-0005),
and artifact inspection never analyzes binary contents (ADR-0002).
"""

import helpers
from helpers import (default_facts, dep_entry, file_components,
                     file_entry, file_component, file_ref, finding_by_id,
                     fragment, pkg, profile_config, ref_of, render_all,
                     render_docs)


def test_delivered_files_become_file_components_with_artifact_identity():
    facts = default_facts(
        config=profile_config(),
        file_inventory={"busybox": [
            file_entry("/bin/sh", sha512="a" * 128),
            file_entry("/var/pkg/app.rpm", sha512="b" * 128,
                       executable="non-executable", archive="archive",
                       structured="structured"),
        ]},
    )
    sbom, _vex, _logs = render_docs(facts)

    sh = file_component(sbom, "busybox", "/bin/sh")
    assert sh["name"] == "sh"
    assert sh["hashes"] == [{"alg": "SHA-512", "content": "a" * 128}]
    assert sh["properties"] == [
        {"name": "bsi:component:filename", "value": "sh"},
        {"name": "bsi:component:executable", "value": "executable"},
        {"name": "bsi:component:archive", "value": "no archive"},
        {"name": "bsi:component:structured", "value": "unstructured"},
    ]

    rpm = file_component(sbom, "busybox", "/var/pkg/app.rpm")
    assert rpm["name"] == "app.rpm"
    assert rpm["properties"] == [
        {"name": "bsi:component:filename", "value": "app.rpm"},
        {"name": "bsi:component:executable", "value": "non-executable"},
        {"name": "bsi:component:archive", "value": "archive"},
        {"name": "bsi:component:structured", "value": "structured"},
    ]

"""Fact builders and document queries for the renderer behavioral tests.

Tests build normalized facts here and assert on the rendered SBOM/VEX
documents (content and graph relationships), never on renderer internals.
"""

import meta_cyclonedx

TIMESTAMP = "2026-10-12T00:00:00+00:00"
PLACEHOLDER = "<SBOM_SERIAL>"


def pkg(name, version, bom_ref, cpe=None, purl=None, **extra):
    component = {
        "name": name,
        "version": version,
        "type": "library",
        "cpe": cpe or f"cpe:2.3:*:*:{name}:{version}:*:*:*:*:*:*:*",
        "purl": purl or f"pkg:yocto/{name}@{version}",
        "bom-ref": bom_ref,
    }
    component.update(extra)
    return component


def fragment(pkgs=(), cves=(), dependencies=(), **extra):
    """A recipe fragment in the on-disk do_populate_cyclonedx format."""
    result = {"pkgs": list(pkgs), "cves": list(cves)}
    if dependencies:
        result["dependencies"] = list(dependencies)
    result.update(extra)
    return result


def dep(ref, depends_on=()):
    return {"ref": ref, "dependsOn": list(depends_on)}


def vuln(cve_id, *refs, state="resolved", detail="STATE: fixed\n"):
    """A VEX statement exactly as recipe fragments carry it (placeholder refs)."""
    return {
        "id": cve_id,
        "source": {"name": "NVD", "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"},
        "analysis": {
            "detail": detail,
            "state": state,
            "firstIssued": TIMESTAMP,
            "lastUpdated": TIMESTAMP,
        },
        "affects": [{"ref": f"urn:cdx:{PLACEHOLDER}/1#{r}"} for r in refs],
    }


def document(serial, components, dependencies, metadata_component=None,
             spec_version="1.7", version=1):
    """A completed SBOM document, e.g. of an embedded image."""
    doc = {
        "bomFormat": "CycloneDX",
        "specVersion": spec_version,
        "serialNumber": f"urn:uuid:{serial}",
        "version": version,
        "metadata": {"timestamp": TIMESTAMP, "components": []},
        "components": list(components),
        "dependencies": list(dependencies),
    }
    if metadata_component is not None:
        doc["metadata"]["component"] = metadata_component
    return doc


def vex_document(vulnerabilities, spec_version="1.7"):
    return {
        "bomFormat": "CycloneDX",
        "specVersion": spec_version,
        "version": 1,
        "metadata": {"timestamp": TIMESTAMP},
        "vulnerabilities": list(vulnerabilities),
    }


def default_config(**overrides):
    config = {
        "spec_version": "1.7",
        "add_component_scopes": True,
        "add_citation": False,
        "tlp_marking": "",
        "add_vuln_timestamps": True,
        "sbom_serial_placeholder": PLACEHOLDER,
    }
    config.update(overrides)
    return config


def default_facts(**overrides):
    """Facts for a minimal image: one runtime recipe, one component."""
    facts = {
        "config": default_config(),
        "timestamp": TIMESTAMP,
        "primary": {"type": "firmware", "name": "core-image", "version": "1.0"},
        "fragments": {
            "busybox": fragment(
                pkgs=[pkg("busybox", "1.36", "ref-busybox")]),
        },
        "runtime_recipes": ["busybox"],
        "image_install_recipes": ["busybox"],
        "runtime_edges": {},
        "included_images": [],
    }
    facts.update(overrides)
    return facts


def render_docs(facts):
    """Render and capture diagnostics; returns (sbom, vex, logs)."""
    logs = []
    facts.setdefault("log", lambda level, message: logs.append((level, message)))
    docs = meta_cyclonedx.render(facts)
    return docs["sbom"], docs["vex"], logs


def render_all(facts):
    """Render and capture diagnostics; returns (docs, logs).

    Use when the test needs the full renderer return value, e.g. the
    alignment report or a strict-enforcement failure.
    """
    logs = []
    facts.setdefault("log", lambda level, message: logs.append((level, message)))
    return meta_cyclonedx.render(facts), logs


def profile_config(**overrides):
    """Renderer config that selects the TR-03183-2.1 alignment profile."""
    config = default_config(profile="tr03183-2.1", enforcement="report")
    config.update(overrides)
    return config


def file_entry(path, sha512=None, executable="executable",
               archive="no archive", structured="unstructured", error=None):
    """One delivered-file artifact fact (adapter-normalized classification).

    Values carry the pinned taxonomy's spellings directly; error entries
    record why a mandatory artifact could not be inventoried (missing,
    unreadable or ambiguous-classification) instead of vanishing.
    """
    entry = {"path": path, "executable": executable, "archive": archive,
             "structured": structured}
    if sha512 is not None:
        entry["sha512"] = sha512
    if error is not None:
        entry["error"] = error
    return entry


def file_ref(recipe, path):
    """The bom-ref convention for inventoried delivered files."""
    return f"yocto-file:{recipe}:{path}"


def file_components(sbom):
    return [c for c in sbom["components"] if c.get("type") == "file"]


def file_component(sbom, recipe, path):
    ref = file_ref(recipe, path)
    matches = [c for c in sbom["components"] if c.get("bom-ref") == ref]
    assert len(matches) == 1, f"expected exactly one file component {ref}, got {len(matches)}"
    return matches[0]


def component_names(sbom):
    return [c["name"] for c in sbom["components"]]


def component_by_name(sbom, name):
    matches = [c for c in sbom["components"] if c["name"] == name]
    assert len(matches) == 1, f"expected exactly one component {name!r}, got {len(matches)}"
    return matches[0]


def ref_of(sbom, name):
    return component_by_name(sbom, name)["bom-ref"]


def root_entry(sbom):
    """The root graph node: the metadata.component reference, first in list."""
    entry = sbom["dependencies"][0]
    assert entry["ref"] == sbom["metadata"]["component"]["bom-ref"]
    return entry


def dep_entry(sbom, ref):
    matches = [e for e in sbom["dependencies"] if e["ref"] == ref]
    assert len(matches) == 1, f"expected exactly one dependency entry for {ref}, got {len(matches)}"
    return matches[0]


def vuln_by_id(vex, cve_id):
    matches = [v for v in vex["vulnerabilities"] if v["id"] == cve_id]
    assert len(matches) == 1, f"expected exactly one statement {cve_id}, got {len(matches)}"
    return matches[0]


def affect_refs(vuln):
    return [a["ref"] for a in vuln["affects"]]


def finding_by_id(report, requirement_id):
    matches = [f for f in report["findings"] if f["requirementId"] == requirement_id]
    assert len(matches) == 1, f"expected exactly one finding {requirement_id}, got {len(matches)}"
    return matches[0]

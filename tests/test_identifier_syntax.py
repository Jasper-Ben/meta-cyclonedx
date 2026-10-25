# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: Copyright (C) 2026 iris-GmbH infrared & intelligent sensors.

"""purl, CPE and SHA-512 syntax and placement at the renderer seam
(ticket #11, user story 48).

Identifiers the generator emits must be usable by downstream tools:
every purl parses as a Package URL, every CPE is a formatted CPE 2.3
string, every SHA-512 is lowercase hex of 512 bits riding
`components[].hashes[]` under the SHA-512 algorithm name. Defects are
machine-detectable findings and reject strict enforcement.
"""
import alignment_profile
from helpers import (default_facts, file_entry, file_ref, finding_by_id,
                     fragment, pkg, profile_config, render_all)

SYNTAX_ROWS = ("REQ-IDEN-002", "REQ-IDEN-003", "REQ-IDEN-004")


def test_valid_identifiers_pass_the_syntax_rules():
    facts = default_facts(
        config=profile_config(),
        file_inventory={"busybox": [
            file_entry("/usr/bin/busybox", sha512="a" * 128)]},
    )
    docs, _logs = render_all(facts)
    for requirement in SYNTAX_ROWS:
        finding = finding_by_id(docs["report"], requirement)
        assert finding["verdict"] == "verified", requirement


def test_purl_syntax_accepts_the_supported_ecosystem_spellings():
    for index, purl in enumerate((
        "pkg:yocto/busybox@1.36",
        "pkg:github/openssl/openssl@3.0",
        "pkg:npm/%40angular/core@1.2.3",
        "pkg:deb/ubuntu/bash@5.1-6ubuntu1?arch=amd64",
        "pkg:generic/Acme/product@1.0#src/main.c",
    )):
        ref = f"ref-{index}"
        facts = default_facts(
            config=profile_config(),
            fragments={f"recipe{index}": fragment(
                pkgs=[pkg(f"recipe{index}", "1.0", ref, purl=purl)])},
            runtime_recipes=[f"recipe{index}"],
            image_install_recipes=[f"recipe{index}"],
        )
        docs, _logs = render_all(facts)
        finding = finding_by_id(docs["report"], "REQ-IDEN-002")
        assert finding["verdict"] == "verified", purl


def test_invalid_purls_are_unmet_findings_naming_the_component():
    facts = default_facts(
        config=profile_config(),
        fragments={"busybox": fragment(pkgs=[pkg(
            "busybox", "1.36", "ref-busybox", purl="busybox-1.36.tgz")])})
    docs, _logs = render_all(facts)
    finding = finding_by_id(docs["report"], "REQ-IDEN-002")
    assert finding["verdict"] == "unmet"
    assert finding["bomRefs"] == ["ref-busybox"]


def test_components_without_a_purl_are_not_syntax_violations():
    facts = default_facts(config=profile_config())
    facts["fragments"] = {
        "busybox": {"pkgs": [{"name": "busybox", "version": "1.36",
                              "type": "library", "bom-ref": "ref-busybox"}],
                    "cves": []},
    }
    docs, _logs = render_all(facts)
    assert finding_by_id(docs["report"],
                         "REQ-IDEN-002")["verdict"] == "verified"


def test_cpe_fields_must_be_formatted_cpe_23_strings():
    facts = default_facts(
        config=profile_config(),
        fragments={"busybox": fragment(pkgs=[pkg(
            "busybox", "1.36", "ref-busybox",
            cpe="cpe:/a:busybox:busybox:1.36")])})
    docs, _logs = render_all(facts)
    finding = finding_by_id(docs["report"], "REQ-IDEN-003")
    assert finding["verdict"] == "unmet"
    assert finding["bomRefs"] == ["ref-busybox"]


def test_malformed_alias_cpes_are_reported_too():
    facts = default_facts(
        config=profile_config(),
        fragments={"busybox": fragment(pkgs=[pkg(
            "busybox", "1.36", "ref-busybox",
            properties=[{"name": "yocto:cve:cpe",
                         "value": "cpe:2.3:not-enough-fields"}])])})
    docs, _logs = render_all(facts)
    finding = finding_by_id(docs["report"], "REQ-IDEN-003")
    assert finding["verdict"] == "unmet"
    assert "ref-busybox" in finding["bomRefs"]


def test_sha512_must_be_lowercase_512_bit_hex():
    for defect in ("A" * 128, "z" * 128, "abc123"):
        facts = default_facts(
            config=profile_config(),
            file_inventory={"busybox": [
                file_entry("/usr/bin/busybox", sha512=defect)]},
        )
        docs, _logs = render_all(facts)
        finding = finding_by_id(docs["report"], "REQ-IDEN-004")
        assert finding["verdict"] == "unmet", defect
        assert file_ref("busybox", "/usr/bin/busybox") in finding["bomRefs"]


def test_valid_sha512s_are_verified():
    facts = default_facts(
        config=profile_config(),
        file_inventory={"busybox": [
            file_entry("/usr/bin/busybox", sha512="0123456789abcdef" * 8)]},
    )
    docs, _logs = render_all(facts)
    assert finding_by_id(docs["report"],
                         "REQ-IDEN-004")["verdict"] == "verified"


def test_sha512_outside_component_hashes_is_unmet():
    sbom = {
        "bomFormat": "CycloneDX", "specVersion": "1.7", "version": 1,
        "metadata": {
            "component": {"type": "firmware", "name": "core-image",
                          "version": "1.0", "bom-ref": "ref-primary"},
            "properties": [{"name": "yocto:artifact:sha512",
                            "value": "a" * 128,
                            "alg": "SHA-512"}],
        },
        "components": [],
    }
    _baseline, findings = alignment_profile.evaluate(
        "tr03183-2.1", "1.7", sbom, {}, {})
    finding = finding_by_id({"findings": findings}, "REQ-IDEN-004")
    assert finding["verdict"] == "unmet"


def test_strict_enforcement_rejects_identifier_syntax_defects():
    facts = default_facts(
        config=profile_config(enforcement="strict"),
        fragments={"busybox": fragment(pkgs=[pkg(
            "busybox", "1.36", "ref-busybox", purl="not a purl!!")])})
    docs, _logs = render_all(facts)
    assert "failure" in docs
    assert "REQ-IDEN-002" in docs["failure"]["unmetRequirementIds"]

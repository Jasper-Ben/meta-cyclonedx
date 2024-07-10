# SPDX-License-Identifier: MIT
# Copyright 2022 BG Networks, Inc.
# Copyright (C) 2024 Savoir-faire Linux Inc. (<www.savoirfairelinux.com>).

# The product name that the CVE database uses.  Defaults to BPN, but may need to
# be overriden per recipe (for example tiff.bb sets CVE_PRODUCT=libtiff).
CVE_PRODUCT ??= "${BPN}"
CVE_VERSION ??= "${PV}"

CYCLONEDX_EXPORT_DIR ??= "${DEPLOY_DIR}/cyclonedx-export"
CYCLONEDX_EXPORT_SBOM ??= "${CYCLONEDX_EXPORT_DIR}/bom.json"
CYCLONEDX_EXPORT_VEX ??= "${CYCLONEDX_EXPORT_DIR}/vex.json"
CYCLONEDX_EXPORT_TMP ??= "${TMPDIR}/cyclonedx-export"
CYCLONEDX_EXPORT_LOCK ??= "${CYCLONEDX_EXPORT_TMP}/bom.lock"

python do_cyclonedx_init() {
    import uuid
    from datetime import datetime

    timestamp = datetime.now().astimezone().isoformat()
    sbom_dir = d.getVar("CYCLONEDX_EXPORT_DIR")
    bb.debug(2, "Creating cyclonedx directory: %s" % sbom_dir)
    bb.utils.mkdirhier(sbom_dir)

    bb.debug(2, "Creating empty sbom")
    write_json(d.getVar("CYCLONEDX_EXPORT_SBOM"), {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "serialNumber": "urn:uuid:" + str(uuid.uuid4()),
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": [{"name": "yocto"}]
        },
        "components": []
    })

    bb.debug(2, "Creating empty patched CVEs VEX file")
    write_json(d.getVar("CYCLONEDX_EXPORT_VEX"), {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "serialNumber": "urn:uuid:" + str(uuid.uuid4()),
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": [{"name": "yocto"}]
        },
        "vulnerabilities": []
    })
}
addhandler do_cyclonedx_init
do_cyclonedx_init[eventmask] = "bb.event.BuildStarted"

python do_cyclonedx_package_collect() {
    import uuid
    import oe.cve_check

    # load the bom
    name = d.getVar("CVE_PRODUCT")
    version = d.getVar("CVE_VERSION")
    sbom = read_json(d.getVar("CYCLONEDX_EXPORT_SBOM"))
    vex = read_json(d.getVar("CYCLONEDX_EXPORT_VEX"))

    for pkg in generate_packages_list(name, version):
        if not next((c for c in sbom["components"] if c["cpe"] == pkg["cpe"]), None):
            sbom["components"].append(pkg)
            bom_ref = pkg["bom-ref"]

     # populate vex file with patched CVEs
            for _, patched_cve in enumerate(oe.cve_check.get_patched_cves(d)):
                bb.debug(2, f"Found patch for CVE {patched_cve} in {name}@{version}")
                vex["vulnerabilities"].append({
                    "id": patched_cve,
                    # vex documents require a valid source, see https://github.com/DependencyTrack/dependency-track/issues/2977
                    # this should always be NVD for yocto CVEs.
                    "source": {"name": "NVD", "url": "https://nvd.nist.gov/"},
                    "analysis": {"state": "resolved"},
                    # ref needs to be in bom-link format, however the uuid does not actually have to match the SBOM document uuid,
                    # see https://github.com/DependencyTrack/dependency-track/issues/1872#issuecomment-1254265425
                    # This is not ideal, as "resolved" will be applied to all components within the project containing the CVE,
                    # however component specific resolving seems not to work at the moment.
                    "affects": [{"ref": f"urn:cdx:{str(uuid.uuid4())}/1#{bom_ref}"}]
                })
            # populate vex file with ignored CVEs defined in CVE_CHECK_IGNORE
            # TODO: In newer versions of Yocto CVE_CHECK_IGNORE is deprecated in favour of CVE_STATUS, which we should also take into account here
            cve_check_ignore = d.getVar("CVE_CHECK_IGNORE")
            if cve_check_ignore is not None:
                for ignored_cve in cve_check_ignore.split():
                    bb.debug(2, f"Found ignore statement for CVE {ignored_cve} in {name}@{version}")
                    vex["vulnerabilities"].append({
                        "id": ignored_cve,
                        # vex documents require a valid source, see https://github.com/DependencyTrack/dependency-track/issues/2977
                        # this should always be NVD for yocto CVEs.
                        "source": {"name": "NVD", "url": "https://nvd.nist.gov/"},
                        # setting not-affected state for ignored CVEs
                        "analysis": {"state": "not_affected"},
                        # ref needs to be in bom-link format, however the uuid does not actually have to match the SBOM document uuid,
                        # see https://github.com/DependencyTrack/dependency-track/issues/1872#issuecomment-1254265425
                        # This is not ideal, as "resolved" will be applied to all components within the project containing the CVE,
                        # however component specific resolving seems not to work at the moment.
                        "affects": [{"ref": f"urn:cdx:{str(uuid.uuid5())}/1#{bom_ref}"}]
                    })
    
    # write it back to the deploy directory
    write_json(d.getVar("CYCLONEDX_EXPORT_SBOM"), sbom)
    write_json(d.getVar("CYCLONEDX_EXPORT_VEX"), vex)


}

addtask do_cyclonedx_package_collect before do_build after do_fetch
do_cyclonedx_package_collect[nostamp] = "1"
do_cyclonedx_package_collect[lockfiles] += "${CYCLONEDX_EXPORT_LOCK}"
do_rootfs[recrdeptask] += "do_cyclonedx_package_collect"

def read_json(path):
    import json
    from pathlib import Path
    return json.loads(Path(path).read_text())

def write_json(path, content):
    import json
    from pathlib import Path
    Path(path).write_text(
        json.dumps(content, indent=2)
    )

def generate_packages_list(products_names, version):
    """
    Get a list of products and generate CPE and PURL identifiers for each of them.
    """
    import uuid

    packages = []

    # keep only the short version which can be matched against vulnerabilities databases
    version = version.split("+git")[0]

    # some packages have alternative names, so we split CVE_PRODUCT
    for product in products_names.split():
        # CVE_PRODUCT in recipes may include vendor information for CPE identifiers. If not,
        # use wildcard for vendor.
        if ":" in product:
            vendor, product = product.split(":", 1)
        else:
            vendor = ""

        pkg = {
            "name": product,
            "version": version,
            "type": "library",
            "cpe": 'cpe:2.3:*:{}:{}:{}:*:*:*:*:*:*:*'.format(vendor or "*", product, version),
            "purl": 'pkg:{}/{}@{}'.format(vendor or "generic", product, version),
            "bom-ref": str(uuid.uuid4())
        }
        if vendor != "":
            pkg["group"] = vendor
        packages.append(pkg)
    return packages

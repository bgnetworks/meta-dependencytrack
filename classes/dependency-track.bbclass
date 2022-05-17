# SPDX-License-Identifier: MIT
# Copyright 2022 BG Networks, Inc.

# The product name that the CVE database uses.  Defaults to BPN, but may need to
# be overriden per recipe (for example tiff.bb sets CVE_PRODUCT=libtiff).
CVE_PRODUCT ??= "${BPN}"
CVE_VERSION ??= "${PV}"

DEPENDENCYTRACK_DIR ??= "${DEPLOY_DIR}/dependency-track"
DEPENDENCYTRACK_SBOM ??= "${DEPENDENCYTRACK_DIR}/bom.json"
DEPENDENCYTRACK_TMP ??= "${TMPDIR}/dependency-track"
DEPENDENCYTRACK_LOCK ??= "${DEPENDENCYTRACK_TMP}/bom.lock"

DEPENDENCYTRACK_PROJECT ??= ""
DEPENDENCYTRACK_API_URL ??= "http://localhost:8081/api"
DEPENDENCYTRACK_API_KEY ??= ""

python do_dependencytrack_init() {
    import uuid
    from datetime import datetime

    sbom_dir = d.getVar("DEPENDENCYTRACK_DIR")
    bb.debug(2, "Creating cyclonedx directory: %s" % sbom_dir)
    bb.utils.mkdirhier(sbom_dir)

    bb.debug(2, "Creating empty sbom")
    write_sbom(d, {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "serialNumber": "urn:uuid:" + str(uuid.uuid4()),
        "version": 1,
        "metadata": {
            "timestamp": datetime.now().isoformat(),
        },
        "components": []
    })
}
addhandler do_dependencytrack_init
do_dependencytrack_init[eventmask] = "bb.event.BuildStarted"

python do_dependencytrack_collect() {
    import json
    import oe.cve_check
    from pathlib import Path

    # load the bom
    name = d.getVar("CVE_PRODUCT")
    version = d.getVar("CVE_VERSION")
    sbom = read_sbom(d)

    # update it with the new package info
    names = name.split()
    for index, cpe in enumerate(oe.cve_check.get_cpe_ids(name, version)):
        bb.debug(2, f"Collecting pagkage {name}@{version} ({cpe})")
        if not next((c for c in sbom["components"] if c["cpe"] == cpe), None):
            sbom["components"].append({
                "name": names[index],
                "version": version,
                "cpe": cpe
            })

    # write it back to the deploy directory
    write_sbom(d, sbom)
}

addtask dependencytrack_collect before do_build after do_fetch
do_dependencytrack_collect[nostamp] = "1"
do_dependencytrack_collect[lockfiles] += "${DEPENDENCYTRACK_LOCK}"
do_rootfs[recrdeptask] += "do_dependencytrack_collect"

python do_dependencytrack_upload () {
    import json
    import base64
    import urllib
    from pathlib import Path

    sbom_path = d.getVar("DEPENDENCYTRACK_SBOM")
    dt_project = d.getVar("DEPENDENCYTRACK_PROJECT")
    dt_url = f"{d.getVar('DEPENDENCYTRACK_API_URL')}/v1/bom"

    bb.debug(2, f"Loading final SBOM: {sbom_path}")
    sbom = Path(sbom_path).read_text()

    payload = json.dumps({
        "project": dt_project,
        "bom": base64.b64encode(sbom.encode()).decode('ascii')
    }).encode()
    bb.debug(2, f"Uploading SBOM to project {dt_project} at {dt_url}")
    
    headers = {
        "Content-Type": "application/json",
        "X-API-Key": d.getVar("DEPENDENCYTRACK_API_KEY")
    }
    req = urllib.request.Request(
        dt_url,
        data=payload,
        headers=headers,
        method="PUT")
    
    try:
        urllib.request.urlopen(req)
    except urllib.error.HTTPError as e:
        bb.error(f"Failed to upload SBOM to Dependency Track server at {dt_url}. [HTTP Error] {e.code}; Reason: {e.reason}")
    except urllib.error.URLError as e:
        bb.error(f"Failed to upload SBOM to Dependency Track server at {dt_url}. [URL Error] Reason: {e.reason}")
    else:
        bb.debug(2, f"SBOM successfully uploaded to {dt_url}")
}
addhandler do_dependencytrack_upload
do_dependencytrack_upload[eventmask] = "bb.event.BuildCompleted"

def read_sbom(d):
    import json
    from pathlib import Path
    return json.loads(Path(d.getVar("DEPENDENCYTRACK_SBOM")).read_text())

def write_sbom(d, sbom):
    import json
    from pathlib import Path
    Path(d.getVar("DEPENDENCYTRACK_SBOM")).write_text(
        json.dumps(sbom, indent=2)
    )

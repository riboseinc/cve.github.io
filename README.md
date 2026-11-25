# cve.ribose.com

This repository publishes machine-readable Open Source Vulnerability (OSV), GitHub Security Advisory (GHSA), Common Security Advisory Framework (CSAF 2.0), and OpenVEX JSON feeds for tracked Ribose packages on `https://cve.ribose.com`.

## Sources

- `_data/packages.yml`: Tracked Tier A package registry (`rnpgp/rnp`, `metanorma/metanorma`, `riboseinc/cla`, `ribosei/identity`) with PURLs and feed paths aligned with `ribosei/provenance-instance`.
- `_data/cves/*.json`: Authoritative CVE JSON 5.0 and 5.1 records.
- `_advisories/*.adoc`: Ribose security advisories linked to CVE records.

## Endpoints

- `/feeds/osv/index.json`: OSV feed index keyed by package and PURL.
- `/feeds/osv/<package>.json`: Per-package OSV feed (`rnp`, `metanorma`, `cla`, `identity`).
- `/feeds/osv/<CVE-ID>.json`: Individual OSV-schema vulnerability records.
- `/feeds/ghsa/index.json`: GHSA feed index.
- `/feeds/ghsa/<package>.json`: Per-package GHSA feed (`rnp`, `metanorma`, `cla`, `identity`).
- `/feeds/csaf/index.json`: CSAF 2.0 feed index keyed by package and PURL.
- `/feeds/csaf/<package>.json`: Per-package CSAF 2.0 `csaf_vex` document (`rnp`, `metanorma`, `cla`, `identity`).
- `/feeds/csaf/<CVE-ID>.json`: Individual CSAF 2.0 `csaf_vex` documents.
- `/feeds/vex/index.json`: OpenVEX 0.2.0 feed index keyed by package and PURL.
- `/feeds/vex/<package>.json`: Per-package OpenVEX 0.2.0 feed (`rnp`, `metanorma`, `cla`, `identity`).
- `/feeds/vex/<CVE-ID>.json`: Individual OpenVEX 0.2.0 documents.

## Build and validation

```sh
make feeds
make test
make _site
```

Every generated OSV, CSAF 2.0, and OpenVEX 0.2.0 record is validated against the vendored JSON Schemas (`schemas/osv-schema.json`, `schemas/csaf-2.0-schema.json`, and `schemas/openvex-0.2.0-schema.json`) before publication.

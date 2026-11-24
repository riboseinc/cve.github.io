# cve.ribose.com

This repository publishes machine-readable Open Source Vulnerability (OSV) and GitHub Security Advisory (GHSA) JSON feeds for tracked Ribose packages on `https://cve.ribose.com`.

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

## Build and validation

```sh
make feeds
make test
make _site
```

Every generated OSV record is validated against the vendored OSV JSON Schema (`schemas/osv-schema.json`) before publication.

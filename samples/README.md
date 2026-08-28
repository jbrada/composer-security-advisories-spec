# Sample third-party repository with a security-advisories feed

Examples for [`SPEC.md`](../SPEC.md). Static JSON only — what a self-hosted Composer repository at
`https://packages.example.com` would serve so that `composer audit` (Composer
>= 2.4) reports the repository's **own** advisories. Three packages:

| package | versions | advisories |
|---|---|---|
| `acme/vuln-ext` | 1.0.0, 1.0.1 | `ACME-SA-2026-001` (high, CVE) affects `>=1.0.0,<1.0.1` |
| `acme/http-client` | 2.0.0, 2.1.3, 2.2.0 | `ACME-SA-2025-004` (critical, CVE) `>=2.0.0,<2.1.3`; `ACME-SA-2026-002` (low, no CVE) `<2.2.0` |
| `acme/clean-lib` | 3.4.0 | none |

The consumer side is always the same:

```json
"repositories": [ { "type": "composer", "url": "https://packages.example.com" } ]
```

## `metadata-mode/` — advisories embedded in the package files (fully static)

```
packages.json                 metadata-url + available-package-patterns + security-advisories:{metadata:true}
p2/acme/vuln-ext.json         "packages" + top-level "security-advisories": [ ... ]
p2/acme/http-client.json      two advisories
p2/acme/clean-lib.json        "security-advisories": []   (empty array = "asked and clean")
```

For every locked package Composer re-reads `p2/<name>.json` and evaluates the
`security-advisories` array against the locked version. No server logic needed —
works from any static host (S3, GitHub Pages, nginx, a Satis output dir).
`available-packages` / `available-package-patterns` is **mandatory** in this mode
(Composer refuses the repo otherwise) and also limits which names Composer asks about.

## `api-mode/` — advisories served by a POST endpoint

```
packages.json                          security-advisories:{api-url: https://packages.example.com/api/security-advisories}
p2/acme/*.json                         package metadata only, no advisories inside
api/security-advisories.request.txt    what Composer sends: one POST, body as built by PHP http_build_query
                                       (decoded: packages[]=acme/vuln-ext&packages[]=acme/http-client&packages[]=acme/clean-lib)
api/security-advisories.response.json  what the endpoint must answer: {"advisories": {"<name>": [ ... ]}}
```

Return only the names that were requested (Composer warns about extra ones);
names without advisories can be omitted or given `[]`. Same advisory object
format as metadata mode. This is what packagist.org and packages.drupal.org do.

## `mirror-mode/` — proxy/mirror of Packagist

`packages.json` only: declares `metadata: true` for the packages it embeds
advisories for **and** delegates `api-url` to `https://packagist.org/api/security-advisories/`.
Composer uses the api-url for `composer audit` (metadata mode is only consulted
when there is no api-url), so a mirror gets Packagist's advisories for the
packages it proxies without hosting any advisory data itself (cf. packagist.jp,
mirrors.aliyun.com/composer).

## `advisory-only/` — a repository that hosts no packages

```
packages.json         "packages": {} + metadata-url + available-packages: ["psr/log"] + security-advisories:{metadata:true}
p2/psr/log.json       "packages": {} + one advisory for psr/log <1.1.1
```

Added next to packagist.org, this repository contributes only advisories:
`psr/log` installs from packagist.org, `composer audit` reports
`ACME-SA-2026-009`, and Composer ≥ 2.9 refuses to install `psr/log 1.1.0`
(SPEC §11, test C10). The same works with `api-url` and no p2 files at all.

## Advisory object

```json
{
  "advisoryId": "ACME-SA-2026-001",              // required — your id (PKSA-…, GHSA-…, SA-CONTRIB-…)
  "affectedVersions": ">=1.0.0,<1.0.1",          // required — Composer constraint
  "title": "…",                                  // required
  "sources": [ { "name": "…", "remoteId": "…" } ], // required, non-empty
  "reportedAt": "2026-08-28 12:00:00",           // required, parsed as UTC
  "packageName": "acme/vuln-ext",                // optional (implied by the map key)
  "cve": "CVE-2026-00000",                       // optional, or null
  "link": "https://…",                           // optional
  "severity": "high"                             // optional: low | medium | high | critical
}
```

Missing any required field ⇒ `composer audit` aborts with
*"Advisory for acme/vuln-ext could not be loaded as a full advisory"*.

## Verified

Both `metadata-mode/` and `api-mode/` were served locally and audited with
Composer 2.10.3 and 2.8.10 using a lock pinning `acme/vuln-ext 1.0.0`, `acme/http-client 2.1.0`, `acme/clean-lib 3.4.0`:
`Found 3 security vulnerability advisories affecting 2 packages`, exit code 1.

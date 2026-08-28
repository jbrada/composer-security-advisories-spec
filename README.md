# Composer Repository Security-Advisories Feed — implementation spec

How a **third-party Composer repository** (a marketplace, an extension vendor's
repository, a private mirror) publishes its own security advisories so that
`composer audit` on the consumer's side reports them. This is the mechanism
packagist.org and packages.drupal.org use; it is implemented in Composer ≥ 2.4
but not documented on getcomposer.org. Derived from Composer's source (2.10.3;
line references in SPEC.md Appendix A) and verified by running Composer 2.10.3
and 2.8.10 against local repositories and the live feeds of packagist.org and
packages.drupal.org (2026-08-28).

Why it matters for merchants: packages installed from a vendor repository are
not on packagist.org, so without this feed `composer audit` reports **nothing**
for them — "No security vulnerability advisories found" means *nobody told
Composer*, not *nothing is vulnerable*.

## Contents

| | |
|---|---|
| [`SPEC.md`](./SPEC.md) | The specification (RFC 2119): discovery, advisory object, both transports, client behaviour, security, compatibility, conformance tests, implementer notes. |
| [`samples/`](./samples/README.md) | Example documents for a three-package repository in metadata mode, api-url mode and mirror mode, plus an advisory-only repository (no packages), accepted by Composer 2.10.3. |

## The feed

`packages.json` — declare one or both transports (a v2 repository with
`metadata-url` is required; `available-packages` or `-patterns` is required
for metadata-only feeds and recommended always):

```json
{
  "metadata-url": "/p2/%package%.json",
  "available-package-patterns": ["acme/*"],
  "security-advisories": { "metadata": true, "api-url": "https://packages.example.com/api/security-advisories" }
}
```

**Metadata mode** — static: `p2/acme/vuln-ext.json` gets a top-level array (`[]` when clean):

```json
{
  "packages": { "acme/vuln-ext": [ "...versions..." ] },
  "security-advisories": [
    {
      "advisoryId": "ACME-SA-2026-001",
      "affectedVersions": ">=1.0.0,<1.0.1",
      "title": "acme/vuln-ext: unauthenticated command execution in Runner::run()",
      "reportedAt": "2026-08-28 12:00:00",
      "sources": [ { "name": "acme-security-team", "remoteId": "ACME-SA-2026-001" } ],
      "cve": "CVE-2026-00000",
      "link": "https://security.example.com/advisories/ACME-SA-2026-001",
      "severity": "high"
    }
  ]
}
```

**API mode** — dynamic: Composer sends one `POST api-url` with
`Content-Type: application/x-www-form-urlencoded` and body
`packages[]=acme/vuln-ext&packages[]=…` (all audited names it knows you host),
and expects `{"advisories": {"acme/vuln-ext": [ …same objects… ]}}` with only
the requested names.

The first five fields of the advisory are mandatory; an advisory missing any of
them makes `composer audit` **abort** for every consumer. `affectedVersions` is
a Composer constraint. Full rules: SPEC §3–§6.

## Implement and verify

1. Produce the documents (SPEC §3–§6; copy the shape from `samples/`).
2. Check what Composer sees: `curl https://packages.example.com/packages.json`
   must show the `security-advisories` object; in metadata mode
   `curl …/p2/acme/vuln-ext.json` must show the array; in api mode
   `curl -d 'packages[]=acme/vuln-ext' <api-url>` must return `{"advisories": {…}}`.
3. Prove it with Composer, with your repository as the only source:

   ```json
   { "repositories": [ { "type": "composer", "url": "https://packages.example.com" }, { "packagist.org": false } ],
     "require": { "acme/vuln-ext": "1.0.0" } }
   ```
   `composer update --no-security-blocking --no-audit && composer audit` → the
   advisory is listed, exit status 1; with `1.0.1` → "No security vulnerability
   advisories found", exit 0 (SPEC §10, tests C1–C3). Then drop
   `--no-security-blocking`: on Composer ≥ 2.9 the exact `1.0.0` requirement is
   refused, naming your advisory id (test C9).

Satis users: Satis emits no feed; add `"security-advisories": {"metadata": true}`
to `packages.json` and the `security-advisories` array to the affected
`p2/<vendor>/<name>.json` after **every** `satis build` (SPEC §11).

Consumers need Composer ≥ 2.4 (≥ 2.6 if a package can also be covered by
another repository's feed) and must run `composer audit` explicitly —
`composer install` does not audit. Since 2.9 the feed also **blocks**
`update`/`require` from selecting affected versions (`policy.advisories.block`,
default on). Audit exit status: 2.10+ `0`/`1`; 2.8.4–2.9 bitmask `1` =
vulnerabilities, `2` = abandoned, `3` = both.

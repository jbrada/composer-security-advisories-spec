# Composer Repository Security-Advisories Feed — implementation spec

How a **third-party Composer repository** (a marketplace, an extension vendor's
repository, a private mirror) publishes its own security advisories so that
`composer audit` on the consumer's side reports them. This is the mechanism
packagist.org and packages.drupal.org use; it is implemented in Composer ≥ 2.4
but not documented on getcomposer.org. Every statement here was verified against
Composer's source and live repositories (table at the end).

Why it matters for merchants: packages installed from a vendor repository are
not on packagist.org, so without this feed `composer audit` reports **nothing**
for them — "No security vulnerability advisories found" means *nobody told
Composer*, not *nothing is vulnerable*.

## Contents

| | |
|---|---|
| [`SPEC.md`](./SPEC.md) | The specification (RFC 2119): discovery, advisory object, both transports, client behaviour, security, compatibility, conformance tests, implementer notes. |
| [`samples/`](./samples/README.md) | Example documents for a three-package repository in metadata mode, api-url mode and mirror mode, accepted by Composer 2.8.10. |

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

## Verified statements

Verified 2026-08-28 by executing Composer **2.10.3** (2026-08-27) and 2.8.10,
inspecting the source of tags 2.3.10 / 2.4.0 / 2.5.1 / 2.5.2 / 2.8.10 / 2.10.3
(line numbers below refer to `src/Composer/Repository/ComposerRepository.php`
@ 2.10.3), and Satis 3.0.0-dev (`main` @ 2373b9d).

| # | statement | evidence |
|---|---|---|
| 1 | Available since **Composer 2.4.0** (2022-08-16); 2.3.x ignores the key. | `security-advisories` handling absent in tag 2.3.10, present in 2.4.0 (lines 615–673, 1245); CHANGELOG 2.4.0, PR #10798. |
| 2 | Not documented on getcomposer.org. | https://getcomposer.org/doc/05-repositories.md fetched 2026-08-28 and `doc/` of tag 2.10.3: no description of the feed (05-repositories.md documents only the `filter` malware-list block). Only public mention: Packagist blog, "Drupal's own repository, packages.drupal.org, provides security advisories". |
| 3 | Metadata-only feed without `available-packages`/`-patterns` ⇒ repository rejected. | `loadRootServerFile()` lines 1537–1543: `UnexpectedValueException: Invalid security advisory configuration … available-packages or available-package-patterns are required`. |
| 4 | Metadata mode works end to end. | Local repo served with `php -S`, Composer 2.10.3 and 2.8.10: `composer audit` → "Found 1 security vulnerability advisory", exit 1 for 1.0.0; "No security vulnerability advisories found", exit 0 for 1.0.1. `samples/metadata-mode/` with a 3-package lock: 3 advisories / 2 packages, exit 1 on both versions. |
| 5 | API mode works; **one** un-batched POST, form-encoded, all names. | Lines 774–778: `method=POST`, `Content-type: application/x-www-form-urlencoded`, `timeout=10`, `content=http_build_query(['packages'=>…])` — no chunking. Raw body `packages%5B0%5D=acme%2Fvuln-ext&packages%5B1%5D=…`. Local endpoint: exit 1 with the advisory (2.10.3 and 2.8.10). |
| 6 | `advisoryId` + `affectedVersions` always required; `title` + `sources` + `reportedAt` make it *full*; `composer audit` aborts on partial ones. | `PartialSecurityAdvisory::create()`; line 727: `RuntimeException('Advisory for … could not be loaded as a full advisory from …')` unless `--format=summary` (`Auditor` lines 77–84). Observed on 2.10.3: sample with `title` removed → "Advisory for acme/vuln-ext could not be loaded as a full advisory", exit 1; `--format=summary` on the same repo → "Found 3 security vulnerability advisories". |
| 7 | Both transports declared ⇒ `composer audit` uses api-url only; summary mode reads metadata first. | Line 736: `if ($metadata && ($allowPartialAdvisories \|\| $apiUrl === null))`; line 774: api-url for the remaining names. |
| 8 | Feeds of all repositories are merged, **not de-duplicated**; a custom feed still reports with packagist.org enabled. | `RepositorySet::getSecurityAdvisoriesForConstraints()`: `array_merge_recursive`, no id-based dedup; CHANGELOG 2.6.0 (#11436). `-vvv` run: local p2 + `repo.packagist.org/packages.json` + `packagist.org/api/security-advisories/` all requested, local advisory reported. |
| 9 | A repository is only asked about names matching its `available-packages`/`-patterns` (`*` → `.*`, case-insensitive, anchored). | Lines 710–716 + `lazyProvidersRepoContains()`, `BasePackage::packageNameToRegexp()`. `-vvv` against packages.drupal.org: only `packages.json` and the api-url POST. |
| 10 | `composer audit` reuses a cached `packages.json` younger than **600 s**. | Line 699 `loadRootServerFile(600)` and the age check in `loadRootServerFile()`. Observed: newly added key invisible until `composer clear-cache`. |
| 11 | **Satis** emits no feed and cannot be configured to; injection works; every `satis build` wipes it. | `grep -ri advisor src/ res/` empty; `res/satis-schema.json` `additionalProperties: false`; `PackagesBuilder::dump()` fixed key set. Injected repo: audit exit 1; after rebuild `grep -c security-advisories` → 0. composer/satis#1035 open since 2025-09-08. |
| 12 | **packages.drupal.org** runs both transports in production; packagist.org too; mirrors delegate. | `packages.drupal.org/8/packages.json`: `{"metadata": true, "api-url": ".../8/security-advisories"}`; POST returns 89 advisories for `drupal/core`, 11 for `drupal/webform`; p2 file has the array. `composer audit --locked` with only that repository and a lock pinning `drupal/webform 5.10.0` → 10 advisories, exit 1; `6.3.0` → exit 0. packagist.jp, mirrors.aliyun.com/composer, packagist.pages.dev: `api-url` → packagist.org. |
| 13 | Repositories **without** a feed: composer.typo3.org, wpackagist.org, asset-packagist.org, repo.mage-os.org, mirror.mage-os.org. | `packages.json` fetched 2026-08-28: no `security-advisories` key. Not verified (credentials required): repo.magento.com (401), packages.shopware.com, Private Packagist. |
| 14 | `composer update` audits by default, `composer install` does not; audit exit status is a 1/2/3 bitmask in 2.8.4–2.9.x and 0/1 since 2.10.0. | CHANGELOG 2.4.0 (`--no-audit`, `install --audit`), 2.8.4 (#12203), 2.10.0 "BC Break … exit code is now always 0 or 1" (#12881). Observed on 2.10.3: `update` ends with "Found 1 security vulnerability advisory affecting 1 package. Run \"composer audit\" …"; every vulnerable audit exits 1. |
| 15 | `"cve": null` and unknown fields are tolerated. | Drupal advisories carry `cve: null` and `composerRepository`; rendered as `CVE \| NO CVE`; `create()` reads `$data['cve'] ?? null`. |
| 16 | Composer ≥ 2.5.2 accepts a p2 document with advisories but no `packages` entry for the name. | PR #11257 (merged 2023-01-13, fixes #11256); condition `!isset($response['packages'][$packageName]) && !isset($response['security-advisories'])` present in tag 2.5.2, absent in 2.5.1. |
| 17 | `audit.ignore` matches `advisoryId`, `cve` or any `sources[].remoteId`. | `Auditor::processAdvisories()` lines 179–198. |
| 18 | The `samples/` documents are accepted by Composer 2.10.3 and 2.8.10. | `samples/metadata-mode/` and `samples/api-mode/` served locally; a lock of `acme/vuln-ext 1.0.0`, `acme/http-client 2.1.0`, `acme/clean-lib 3.4.0` → "Found 3 security vulnerability advisories affecting 2 packages", exit 1, in both modes; `composer update` resolves and locks all three packages. |
| 19 | Since 2.9.0 the feed **blocks** `update`/`require` from selecting affected versions; `install` from a lock is not blocked. | CHANGELOG 2.9.0 (#11956), 2.9.2 (`--no-security-blocking`, #12617), 2.10.0 (`config.policy`, #12804); `doc/06-config.md` @ 2.10.3 "policy → advisories → block, defaults to true". Observed on 2.10.3 against the local feed: exact `acme/vuln-ext 1.0.0` → "found acme/vuln-ext[1.0.0] but these were not loaded, because they are affected by security advisories ("PKSA-poc-0001")", exit 2; `^1.0` → locks 1.0.1; `--no-security-blocking` or `"policy": {"advisories": {"block": false}}` → locks 1.0.0. |
| 20 | An api-url response with an unrequested name produces a warning and the name is ignored. | Line 788. Observed on 2.10.3: "composer repo (http://127.0.0.1:8093) returned names which were not requested in response to the security-advisories API. acme/http-client was not requested but is present in the response. Requested names were: acme/vuln-ext"; advisories for the requested name still reported. |
| 21 | Since 2.8.11 an unparsable `affectedVersions` no longer aborts the audit (source only, not executed). | CHANGELOG 2.8.11 (#12507); `PartialSecurityAdvisory::create()` @ 2.10.3 trims the constraint to its leading operator+number or falls back to `==0.0.0-invalid-version`. |

Live feed re-checked with 2.10.3: packages.drupal.org `drupal/webform 5.10.0`
→ 10 advisories, exit 1; `6.3.0` → exit 0; only `packages.json` and the
api-url POST requested. Re-run steps 2–3 above against `samples/` and check
`https://packages.drupal.org/8/packages.json` when a new Composer version ships.

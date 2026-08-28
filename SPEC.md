# Composer Repository Security-Advisories Feed — Specification

**Version:** 1.1 (2026-08-28)
**Status:** Descriptive specification of behaviour implemented by Composer ≥ 2.4;
normative for repository implementers.
**Reference client:** Composer 2.10.3 (2026-08-27) — `src/Composer/Repository/ComposerRepository.php`,
`src/Composer/Repository/RepositorySet.php`, `src/Composer/Advisory/*`. Line references
below are to that tag. Behaviour was also executed against Composer 2.8.10; differences
between the two are called out explicitly.

The key words MUST, MUST NOT, REQUIRED, SHOULD, SHOULD NOT, MAY are to be
interpreted as described in RFC 2119.

---

## 1. Scope

This document specifies how a Composer repository of type `composer` (a "v2"
repository serving `packages.json`) publishes **security advisories** for the
packages it hosts, so that Composer's `audit` command and its update-time audit
report them. It covers:

- discovery of the feed in the repository root document (§3),
- the advisory object (§4),
- two transports: embedded metadata (§5) and a query API (§6),
- the client processing model implementers must design against (§7),
- security, compatibility and conformance requirements (§8–§10).

The feature is implemented in Composer since 2.4.0 but is not described on
getcomposer.org (as of 2.10.3, `doc/05-repositories.md` documents only the
neighbouring `filter` block, whose `summary-url`/`api-url` serve malware lists
in a different wire format); this document is derived from the reference
client's source and verified against it (Appendix A) and against the production
feeds of packagist.org and packages.drupal.org.

It does **not** cover the separate `filter` / `config.policy` malware-list
mechanism (Composer ≥ 2.9/2.10, `summary-url`, PURL wire format), nor the
FriendsOfPHP `security-advisories` YAML format (see Appendix B).

## 2. Terminology

| term | meaning |
|---|---|
| **repository** | An HTTP(S) endpoint serving a Composer `packages.json` root document. |
| **root document** | The JSON document at `<repository-url>/packages.json`. |
| **v2 repository** | A repository whose root document declares `metadata-url`. Only v2 repositories can serve this feed. |
| **package metadata document** | The per-package JSON document reached by substituting `%package%` in `metadata-url`. |
| **feed** | The set of advisories a repository publishes, via one or both transports. |
| **advisory** | A JSON object describing one vulnerability in one package (§4). |
| **full advisory** | An advisory carrying all REQUIRED fields of §4.1. |
| **partial advisory** | An advisory carrying only `advisoryId` and `affectedVersions`. |
| **client** | Composer, or any tool implementing §7. |

## 3. Discovery — the root document

### 3.1 Declaration

A repository advertises its feed with a top-level `security-advisories` **object**
in the root document:

```json
{
  "metadata-url": "/p2/%package%.json",
  "available-package-patterns": ["acme/*"],
  "security-advisories": {
    "metadata": true,
    "api-url": "https://packages.example.com/api/security-advisories"
  }
}
```

| key | type | meaning |
|---|---|---|
| `metadata` | boolean | `true`: package metadata documents carry a `security-advisories` array (§5). |
| `api-url` | string | Absolute URL, or a path starting with `/` (resolved against the repository's scheme and host), of a POST endpoint (§6). |

Requirements:

- R3.1 The repository MUST be a v2 repository (`metadata-url` present). The
  feed is ignored on v1-only repositories.
- R3.2 `security-advisories` MUST be a JSON object. At least one of `metadata`
  (`true`) or `api-url` MUST be present; both MAY be present (§7.4).
- R3.3 If `metadata` is `true` **and** `api-url` is absent, the root document
  MUST declare `available-packages` (array of exact names) or
  `available-package-patterns` (array of glob patterns, `*` matching any
  substring, case-insensitive, anchored). A client MUST reject the repository
  otherwise. *(Composer: `UnexpectedValueException: Invalid security advisory
  configuration … available-packages or available-package-patterns are required
  to be provided for performance reason`, line 1543.)*
- R3.4 When `available-packages`/`available-package-patterns` is present (in
  any mode), clients only ask the repository about names it lists (§7.2). A
  repository SHOULD therefore declare it so it is never queried for foreign
  packages.
- R3.5 Root documents SHOULD be served with `Last-Modified`; clients cache them
  (§7.6).

### 3.2 Non-normative: what the reference client parses

`ComposerRepository::loadRootServerFile()` (lines 1537–1543):
`metadata` is read with `?? false` (any truthy value counts), `api-url` must be a
string and is canonicalised (`/path` → `scheme://host/path`).

## 4. The advisory object

### 4.1 Fields

```json
{
  "advisoryId": "ACME-SA-2026-001",
  "affectedVersions": ">=1.0.0,<1.0.1",
  "title": "acme/vuln-ext: unauthenticated command execution in Runner::run()",
  "sources": [ { "name": "acme-security-team", "remoteId": "ACME-SA-2026-001" } ],
  "reportedAt": "2026-08-28 12:00:00",
  "packageName": "acme/vuln-ext",
  "cve": "CVE-2026-00000",
  "link": "https://security.example.com/advisories/ACME-SA-2026-001",
  "severity": "high"
}
```

| field | type | full advisory | partial advisory | notes |
|---|---|---|---|---|
| `advisoryId` | string | REQUIRED | REQUIRED | Publisher's stable identifier. Used for `audit.ignore` matching and display. |
| `affectedVersions` | string | REQUIRED | REQUIRED | A Composer version constraint (see §4.2). |
| `title` | string | REQUIRED | absent | One-line summary. |
| `sources` | array of `{name: string, remoteId: string}` | REQUIRED | absent | Provenance. MAY be empty but SHOULD contain at least one entry; `remoteId` values are matched by `audit.ignore`. |
| `reportedAt` | string | REQUIRED | absent | Date-time; interpreted as UTC unless it carries an offset. Any format accepted by PHP `DateTimeImmutable` works; publishers SHOULD use `YYYY-MM-DD HH:MM:SS` or RFC 3339. |
| `packageName` | string | OPTIONAL | OPTIONAL | Informational; the package is identified by the map key (§5/§6). |
| `cve` | string \| null | OPTIONAL | — | `CVE-YYYY-NNNNN` or `null`. Matched by `audit.ignore`. |
| `link` | string | OPTIONAL | — | URL of the advisory. |
| `severity` | string | OPTIONAL | — | SHOULD be one of `low`, `medium`, `high`, `critical` (values used by `--ignore-severity`). |

Requirements:

- R4.1 An advisory MUST carry `advisoryId` and `affectedVersions`. A missing key
  is a hard error in the reference client (undefined array key).
- R4.2 The presence of **all three** of `title`, `sources`, `reportedAt` makes an
  advisory *full*; otherwise it is *partial*. The `composer audit` command
  requires full advisories and aborts with *"Advisory for `<name>` could not be
  loaded as a full advisory from `<repo>`"* when it meets a partial one.
  Publishers MUST publish full advisories unless they only target the
  summary-mode audit (§7.5).
- R4.3 Unknown fields MUST be ignored by clients. Publishers MAY add fields
  (e.g. packagist.org and packages.drupal.org add `composerRepository`).
- R4.4 A publisher SHOULD keep `advisoryId` unique within its feed and stable
  over time; clients de-duplicate nothing (§7.4), so republishing the same
  advisory under two ids yields two findings.

### 4.2 `affectedVersions` semantics

- Parsed with `Composer\Semver\VersionParser::parseConstraints()`. All Composer
  constraint syntax is valid: `<1.2.3`, `>=1.0,<1.1`, `^2.0`, `~1.2`, `||`, `1.0.*`.
- An advisory *matches* an installed package when its constraint matches the
  package's **exact** version (§7.3).
- Publishers SHOULD state closed ranges with an explicit fix version
  (`>=1.0.0,<1.0.1`) rather than open ones (`>=1.0.0`), and SHOULD use a
  `||`-joined list when several branches are affected
  (`>=7.0,<7.57 || >=8.0.0,<8.4.5`).
- Pre-release subtlety: a lower bound `>=X` also admits `X-alpha1` etc., and
  a bare `=X` matches pre-releases of `X`; add explicit bounds if that matters.
- An unparsable constraint aborts `composer audit` in Composer < 2.8.11. Since
  2.8.11 (#12507) the client keeps only the leading operator and number
  (`<=3.20-test2` → `<=3.20`) or, failing that, treats the advisory as matching
  nothing. Publishers MUST NOT rely on this fallback; validate constraints
  before publishing.

## 5. Transport A — embedded metadata (`"metadata": true`)

### 5.1 Document

The package metadata document at `metadata-url` (with `%package%` replaced by
the lowercased package name) carries a top-level `security-advisories` **array**
next to `packages`:

```json
{
  "packages": {
    "acme/vuln-ext": [ { "name": "acme/vuln-ext", "version": "1.0.0", "...": "..." } ]
  },
  "security-advisories": [
    { "advisoryId": "ACME-SA-2026-001", "affectedVersions": ">=1.0.0,<1.0.1", "...": "..." }
  ]
}
```

Requirements:

- R5.1 The array MUST contain only advisories for the package the document
  describes. Each element MUST satisfy §4.
- R5.2 A document for a package **without** advisories SHOULD contain
  `"security-advisories": []`. A document without the key is treated as
  "unknown" (the name is not marked as found and, if an `api-url` exists, is
  forwarded to it — §7.4).
- R5.3 The key MUST be top-level, i.e. a sibling of `packages` (and of
  `minified` when the `composer/2.0` minification is used). Minification
  applies to `packages` only; advisories are never minified.
- R5.4 Only the main document (`%package%`) is consulted. The `%package%~dev`
  document MAY omit the key.
- R5.5 A document MAY carry `security-advisories` with an empty `packages`
  object (`"packages": {}`) (Composer ≥ 2.5.2, PR #11257). This lets a
  repository publish advisories for packages whose releases it does not host —
  an **advisory-only repository** (§11). Verified with Composer 2.10.3: the
  package then resolves from the next repository (e.g. packagist.org) while
  the advisory is reported and blocks affected versions (§7.1). Do not list the
  name with an empty version array (`"packages": {"acme/x": []}`) — declare no
  entry at all.
- R5.6 Documents SHOULD be served with `Last-Modified` and honour
  `If-Modified-Since` (`304`), as clients cache them (§7.6).

### 5.2 Properties

Fully static. No server-side logic; suitable for object storage, static hosts
and generated repositories (Satis output + post-processing). Cost: one GET per
audited package that the repository lists (cached across runs).

## 6. Transport B — query API (`"api-url"`)

### 6.1 Request

```
POST <api-url>
Content-Type: application/x-www-form-urlencoded

packages[]=acme/vuln-ext&packages[]=acme/http-client&packages[]=acme/clean-lib
```

- R6.1 The endpoint MUST accept `POST` with `application/x-www-form-urlencoded`
  bodies and a repeated `packages[]` parameter (PHP-style array; body built by
  PHP `http_build_query(['packages' => [...]])`, so the raw form is
  `packages%5B0%5D=acme%2Fvuln-ext&packages%5B1%5D=…`; servers MUST accept both
  the indexed and un-indexed bracket forms).
- R6.2 The client sends **all** package names in a single request (no batching
  in the reference client). Endpoints MUST accept requests carrying the full
  dependency set of a project (hundreds of names).
- R6.3 The client applies a 10-second HTTP timeout and the repository's normal
  HTTP options — including `auth.json` credentials and custom headers
  configured for the repository. Endpoints on the same host as the repository
  therefore receive the same authentication as `packages.json`.
- R6.4 Endpoints MUST NOT require a `GET` variant; they MAY offer one for humans.

### 6.2 Response

```json
{
  "advisories": {
    "acme/vuln-ext":    [ { "advisoryId": "ACME-SA-2026-001", "affectedVersions": ">=1.0.0,<1.0.1", "...": "..." } ],
    "acme/http-client": [ { "...": "..." }, { "...": "..." } ],
    "acme/clean-lib":   []
  }
}
```

- R6.5 The response MUST be a JSON object with an `advisories` key whose value
  is an object mapping **package name → array of advisories** (§4).
- R6.6 The map MUST only contain names that were requested. A client warns on
  extra names (*"returned names which were not requested in response to the
  security-advisories API"*) and ignores them.
- R6.7 Requested names without advisories MAY be omitted or mapped to `[]`.
  Every name present in the map is marked *found* by the client.
- R6.8 Responses are not cached by the client; each audit issues a fresh POST.
  Endpoints SHOULD be cheap (indexed lookup) and SHOULD set an explicit
  `Content-Type: application/json`.
- R6.9 Advisories in the response SHOULD be full (§4.2 R4.2).

### 6.3 Properties

Dynamic; one request per audit regardless of project size; the publisher sees
which package names are audited (see §8). This is the transport used by
packagist.org (`https://packagist.org/api/security-advisories/`) and
packages.drupal.org.

## 7. Client processing model (normative for clients, informative for publishers)

This section describes what the reference client does; publishers MUST design
feeds that behave correctly under it, and alternative clients SHOULD reproduce
it.

### 7.1 When audits run

- `composer audit` — audits installed packages (`vendor/composer/installed.json`),
  or the lock file with `--locked`; `--no-dev` skips dev packages.
- `composer update`, `require`, `remove`, `create-project` — audit at the end
  unless `--no-audit` / `COMPOSER_NO_AUDIT=1`, using the **summary** format
  (§7.5).
- `composer install` — no audit unless `--audit`.
- **Blocking (Composer ≥ 2.9.0).** Before resolving, `update`/`require`/`remove`
  query the same feeds and **exclude package versions with an active advisory**
  from the resolver pool. An exact requirement on such a version fails:
  *"found acme/vuln-ext[1.0.0] but these were not loaded, because they are
  affected by security advisories ("ACME-SA-2026-001")"*; a range such as
  `^1.0` silently resolves to the first unaffected release. `composer install`
  from an existing lock is **not** blocked by advisories. Controls:
  `config.policy.advisories.block` (2.10, default `true`; legacy
  `audit.block-insecure` in 2.9), the `--no-security-blocking` flag
  (2.9.2 on `update`/`require`/`remove`, 2.9.3 also on `install`),
  `COMPOSER_NO_SECURITY_BLOCKING=1`, and
  `policy.advisories.ignore-id` / `ignore` for individual advisories or
  packages. A feed therefore not only reports vulnerabilities but stops new
  installations of affected versions — publishers must keep
  `affectedVersions` tight (§4.2); a wrong range blocks customers.

### 7.2 Name selection per repository

For each repository advertising a feed, the client builds a map
`name → constraint`:

- **audit:** from the installed/locked packages, constraint = `=<exact version>`
  (several installed versions of a name are OR-ed; root package aliases skipped);
- **blocking (≥ 2.9):** from every candidate version in the resolver pool that
  is not the root package, a platform package or an already-locked package —
  i.e. the OR of all versions the resolver may choose
  (`DependencyResolver\SecurityAdvisoryPoolFilter`).

Then:

1. If the consumer configured `only` / `exclude` on the repository entry in
   `composer.json`, names not allowed by those rules are dropped first
   (`FilterRepository::getSecurityAdvisories()`); with nothing left, no
   advisory request (p2 GET or api-url POST) is made — only the root document
   is read. The filters therefore gate advisories
   and blocking exactly as they gate packages: `"exclude": ["*"]` or a
   non-matching `only` silences the feed completely (Composer ≥ 2.5.2, #11281).
2. If the repository declares `available-packages`/`available-package-patterns`,
   names not matching are **dropped for this repository**.
3. In metadata mode, platform packages (`php`, `ext-*`, `lib-*`, `composer-*`)
   and `__root__` are skipped.

Consequence for publishers: a repository is only ever asked about names it
declares it hosts (R3.4).

### 7.3 Matching

An advisory is reported for a package when
`affectedVersions` (parsed constraint) **matches** the exact installed/locked
version. Non-matching advisories are dropped silently at fetch time.

### 7.4 Transport precedence and merging

Given `metadata` (M) and `api-url` (A) on one repository:

| mode | `composer audit` (full advisories required) | update-time summary audit, `--format=summary`, and blocking (partial allowed) |
|---|---|---|
| M only | metadata documents | metadata documents |
| A only | api-url | api-url |
| M + A | **api-url only** (metadata ignored) | metadata documents first; names whose document lacks the key are then sent to api-url |

Across repositories: every repository advertising a feed is queried; results
are concatenated per package name (`array_merge_recursive`) with **no
de-duplication**. If your repository mirrors packages that packagist.org also
covers, both feeds are reported (Composer ≥ 2.6.0, #11436).

### 7.5 Full vs partial advisories

- Full mode (`composer audit`, any format except `summary`): partial advisory ⇒
  abort with an error (R4.2).
- Summary mode (post-update audit; `--format=summary`) and **blocking**
  (≥ 2.9): partial advisories are accepted. If an ignore list (by CVE or
  `remoteId`) is configured and something matched, the client re-queries in
  full mode to evaluate ignores; the resolver's error message for a blocked
  version also loads full advisories. A feed that only ever serves partial
  advisories therefore still blocks installs but breaks `composer audit`
  (R4.2) — do not ship partial advisories.

### 7.6 Caching

- Root document: cached; for audits a cached copy younger than **600 s** is
  reused without a request (`loadRootServerFile(600)`). Changes to
  `security-advisories` in the root document may take up to 10 minutes to be
  seen by a client that recently used the repository (`composer clear-cache`
  forces a refresh).
- Package metadata documents: cached with `If-Modified-Since` revalidation on
  every audit.
- api-url responses: never cached.

### 7.7 Ignores and severities

Ignore entries (`config.policy.advisories.ignore-id` in 2.10, `audit.ignore`
in 2.6–2.9, still honoured as fallback) match `advisoryId`, `cve`, or any
`sources[].remoteId`; since 2.9.2 an entry can be scoped to `on-block` or
`on-audit`. `--ignore-severity` / `policy.advisories.ignore-severity` compare
the `severity` string. `composer audit --ignore-unreachable` (2.9.0) and
`policy.ignore-unreachable` (audit/update scopes, 2.10) skip repositories that
cannot be reached instead of failing, with a warning. Publishers SHOULD
therefore fill `cve` when one exists and use the canonical severity vocabulary.

### 7.8 Exit status

- Composer 2.8.4 – 2.9.x: bitmask — `1` = vulnerabilities found, `2` = abandoned
  packages found, `3` = both, `0` = clean.
- Composer ≥ 2.10.0: always `0` (nothing failed the audit) or `1` (anything
  failed), per `policy.advisories.audit` (`fail` default, `report` = list but
  exit 0, `ignore`).
- Failure to reach a repository is an error, not a clean result (unless
  `--ignore-unreachable`).

## 8. Security considerations

- S1 Feeds SHOULD be served over HTTPS. Composer refuses plain `http` unless
  `secure-http: false` is configured.
- S2 The api-url transport reveals the audited project's package names (for
  the names the repository lists, R3.4) to the endpoint operator; publishers
  SHOULD document this. Metadata mode reveals the same set via per-package GETs.
- S3 An attacker who can alter the feed can hide advisories (omit them) or
  cause denial of service (a malformed advisory aborts `composer audit`). The
  feed has the same trust level as the package metadata it accompanies; protect
  it with the same integrity controls (TLS, authenticated hosting, signed
  deploys).
- S4 Endpoints MUST validate and bound input (`packages[]` count and length)
  and MUST NOT reflect unrequested names (R6.6).
- S5 Publishers SHOULD NOT include secrets or internal hostnames in `link`
  values of public feeds.

## 9. Compatibility

| Composer | feed support |
|---|---|
| < 2.4 | none (`security-advisories` key ignored) |
| **2.4.0** (2022-08-16) | `audit` command; root-document discovery; both transports (#10798) |
| 2.4.3 | `--format=json` carries `affectedVersions`; `reportedAt` RFC 3339 in JSON (#11120) |
| **2.5.2** (2023-02-04) | metadata documents may carry advisories without releases (R5.5, #11257); works with `exclude`/`only` repository filters (#11281) |
| **2.6.0** (2023-09-01) | advisories for one package merged from multiple repositories (#11436); `audit.ignore` (#11556) |
| 2.7.0 | `severity` shown in output; `audit.abandoned` defaults to `fail` |
| 2.8.0 | `--ignore-severity`, `--abandoned` |
| 2.8.4 | exit-status bitmask 1/2/3 (#12203) |
| 2.8.11 | invalid `affectedVersions` no longer aborts the audit (#12507) |
| **2.9.0** (2025-11-13) | **update-time blocking** of versions with advisories, default on (`audit.block-insecure`, #11956); `audit --ignore-unreachable` (#12470) |
| 2.9.2 | `--no-security-blocking` flag (#12617); ignore entries scoped `on-block`/`on-audit` (#12618) |
| **2.10.0** (2026-05-28) | `config.policy` block replaces `config.audit` (#12804); audit exit status now 0/1 only (#12881); separate `filter` malware lists (#12786) — not this feed |
| 2.10.2 | audit result written to stdout (#12904) |
| 2.10.3 (2026-08-27) | reference client for this document; no feed changes |

Publishers SHOULD state "Composer ≥ 2.4" as the requirement, and "≥ 2.6" when
their packages may also be covered by another repository's feed. From 2.9 the
feed also affects resolution (§7.1 blocking); test ranges before publishing.

## 10. Conformance

A repository conforms to this specification when:

1. its root document satisfies §3;
2. every published advisory satisfies §4;
3. for metadata mode, every package metadata document satisfies §5;
4. for api-url mode, the endpoint satisfies §6;
5. the following black-box tests pass with Composer ≥ 2.4, using a consumer
   project whose only repository is the one under test
   (`{ "packagist.org": false }`) and a lock pinning the versions named:

| test | setup | expected |
|---|---|---|
| C1 vulnerable | lock a version inside `affectedVersions` | `composer audit` lists the advisory; exit status has bit 1 set |
| C2 fixed | lock a version outside the range | `No security vulnerability advisories found.`; exit 0 |
| C3 clean package | lock a package the repo hosts with no advisories | not listed; no error |
| C4 foreign name | lock a package the repo does not list | repository not queried for it (`-vvv` shows no request / name absent from POST) |
| C5 both transports (if both declared) | as C1 | reported once by `composer audit`; reported by `update` summary |
| C6 partial rejection | publish an advisory missing `title` | `composer audit` fails with "could not be loaded as a full advisory" (i.e. do not ship this) |
| C7 extra names (api-url) | endpoint returns an unrequested name | warning emitted, name ignored |
| C8 update-time audit | `composer update --no-security-blocking` without `--no-audit` on C1 | "Found N security vulnerability advisor(y|ies)…" summary line |
| C9 update-time blocking (≥ 2.9) | `composer update` with an exact requirement on the vulnerable version | resolution fails naming the advisory id; with a range (`^1.0`) the fixed version is locked; with `--no-security-blocking` the vulnerable one installs |
| C10 advisory-only repository (§11) | repository with `"packages": {}` documents, added next to the repository that hosts the package | package installs from the other repository; C1, C2 and C9 hold for the advisory-only feed |
| C11 consumer filters | repository entry with `"exclude": ["<name>"]` (or an `only` that does not match) | no advisory and no blocking for that name from this repository; with `only`/`exclude` that allow the name, C1 and C9 hold |

## 11. Implementer notes (informative)

**Static host / object storage:** use metadata mode. Write `security-advisories`
into `p2/<vendor>/<name>.json`; set `"security-advisories": {"metadata": true}`
and `available-package-patterns` in `packages.json`. Regenerate the p2 document
whenever an advisory is added; keep `Last-Modified` accurate.

**Satis:** Satis (3.x) does not emit the key
([composer/satis#1035](https://github.com/composer/satis/issues/1035)). Run a
post-build step that patches `packages.json` and the affected `p2/*.json`
after every `satis build` (the build rewrites both): add
`"security-advisories": {"metadata": true}` to `packages.json` and the
`security-advisories` array to each affected `p2/<vendor>/<name>.json`
(a ~30-line script reading a curated `advisories.json`). Satis already emits
`metadata-url` and `available-packages`, satisfying R3.3.

**Dynamic server (Repman-style, in-house registry):** implement api-url backed by
an indexed table `(package_name, advisory)`; optionally also emit metadata mode
for static-cache friendliness. Remember the M + A precedence (§7.4).

**Advisory-only repository (no packages):** a repository may publish nothing
but advisories — e.g. a security team or marketplace curating advisories for
packages that install from packagist.org or a vendor repository. Root document:
`{"packages": {}, "metadata-url": "/p2/%package%.json", "available-packages":
[<names with advisories>], "security-advisories": {"metadata": true}}` and one
`p2/<vendor>/<name>.json` per listed name containing `"packages": {}` plus the
`security-advisories` array (example: [`samples/advisory-only/`](./samples/advisory-only/)).
With `api-url` instead of `metadata`, no p2 files are needed at all; Composer's
p2 requests for the listed names return 404, which it treats as "not hosted
here". Consumers add the repository next to their normal ones; `metadata-url`
is still REQUIRED (R3.1) and `available-packages`/`-patterns` limits both the
names queried and the names Composer probes for packages. A consumer-side
`only`/`exclude` on the entry applies to the advisories too (§7.2): an
advisory-only repository with `"exclude": ["*"]` contributes nothing, and
`"only": ["psr/*"]` restricts its advisories to those names. Verified with
Composer 2.10.3 in both transports: `psr/log 1.1.0` installed from packagist.org,
`composer audit` reported the repository's advisory (exit 1), an exact
requirement on 1.1.0 was blocked, `^1.1` resolved to 1.1.4.

**Mirror / proxy of packagist.org:** set `"api-url": "https://packagist.org/api/security-advisories/"`
(and `metadata: true` if you embed advisories for your own packages). Composer
will only send names the mirror lists (R3.4). This is what packagist.jp and
mirrors.aliyun.com do.

**Reference implementations in production:** packagist.org
(`https://repo.packagist.org/packages.json`) and packages.drupal.org
(`https://packages.drupal.org/8/packages.json`, both transports; Drupal issue
[#3399877](https://git.drupalcode.org/project/project_composer/-/issues/3399877)).

---

## Appendix A — Reference client source map (Composer 2.10.3)

| behaviour | location |
|---|---|
| root-document parsing, R3.3 check | `ComposerRepository::loadRootServerFile()` 1537–1543 |
| `hasSecurityAdvisories()` | `ComposerRepository` 691 |
| root cache 600 s for audits | `ComposerRepository` 699 (`loadRootServerFile(600)`) |
| name filtering by consumer `only`/`exclude` | `FilterRepository::getSecurityAdvisories()` 204–217, `isAllowed()` 258–273 |
| name filtering by `available-packages` | `ComposerRepository` 710–716, `lazyProvidersRepoContains()` 2050 |
| full-advisory requirement | `ComposerRepository` 727 |
| metadata transport (M / M+A precedence) | `ComposerRepository` 736–770 |
| api-url POST, 10 s timeout, form encoding, extra-name warning | `ComposerRepository` 774–788 |
| p2 document accepted with advisories but no releases | `ComposerRepository` 1393 |
| pattern → regex (`*` → `.*`, `{^…$}i`) | `BasePackage::packageNameToRegexp()` |
| advisory object → full/partial, constraint fallback | `Advisory\PartialSecurityAdvisory::create()` |
| exact-version constraint map, cross-repository merge | `RepositorySet::getMatchingSecurityAdvisories()` / `getSecurityAdvisoriesForConstraints()` 285–298 |
| summary-mode partial advisories (77–84), ignores (282–290), output, exit status | `Advisory\Auditor` |
| update-time blocking: candidate-version constraint map, partial-first lookup | `DependencyResolver\SecurityAdvisoryPoolFilter` 52–88 |

Composer 2.8.10 equivalents: root parsing 1264–1271, `getSecurityAdvisories()` 627–724, merge in `RepositorySet` 268–280.

## Appendix B — Relationship to other advisory formats

The JSON object in §4 is the **wire format Composer reads**. It is not the
FriendsOfPHP `security-advisories` YAML (`branches:`/`versions:` per release),
nor OSV, nor GHSA JSON. Public chain today:

```
FriendsOfPHP YAML + GitHub Advisory DB  ──ingested by──►  packagist.org
        packagist.org  ──serves──►  api-url + metadata feed  ──►  composer audit
```

A third-party repository implementing this specification serves the same wire
format itself, for its own packages, without going through packagist.org.
Converters from OSV/GHSA/FriendsOfPHP YAML to §4 objects are straightforward:
map id → `advisoryId`, affected ranges → one Composer constraint string
(`||`-joined), summary → `title`, published date → `reportedAt`, database name
+ id → `sources[]`.

## Appendix C — Examples

Complete example documents for all three modes (metadata, api-url, mirror),
accepted by Composer 2.10.3 and 2.8.10, live in [`samples/`](./samples/README.md).

# Security Policy

## Current support status

The supported tree contains the dependency-free in-memory policy, collision,
corpus, receipt, and verified offline-report layers plus one installed POSIX
command boundary. The CLI provides explicit-policy analysis, receipt replay,
descriptor-relative stable regular-file reads, and durable no-clobber mode-0600
publication of receipts and static HTML reports.

There is no interactive or served browser UI, network service, Windows
race-safety claim, stdin corpus or receipt, stdout receipt or report, overwrite
mode, implicit policy, or configuration discovery. The renderer accepts caller
data only after exact receipt replay and emits a bounded, static, ASCII-source
HTML artifact. The separate Chromium lane uses reviewed synthetic data only and
is evidence infrastructure, not a package runtime dependency or product
service. The historical Flask prototype is unsupported and must not be
deployed.

## Current trust boundary

Every identifier, record ID, policy object, source byte string, receipt byte
string, argument, and pathname is untrusted. The public byte APIs retain their
pure exact-type boundaries. The installed CLI pins and walks path components
with directory descriptors, rejects traversal, links and special files, captures
a single stable descriptor once, and trust-reconstructs receipts only by replay.

The CLI does not read stdin, emit a receipt or report to stdout, discover
configuration, open sockets, invoke a shell, or overwrite a destination.
Success and handled-failure channels are canonical ASCII and never echo paths,
identifiers, transformed values, source lines, parser tokens, or policy strings.
The report command is intentionally different: after verifying exact receipt
and source bytes, it visibly represents source-derived values as escaped,
logical-indexed code-point metadata and publishes the complete artifact at mode
0600. A report is sensitive and is not a redacted export.

Record IDs are limited to 64 lowercase ASCII characters matching
`[a-z][a-z0-9._-]*` and must be unique. They define canonical record ordinals;
the caller's record tuple order is non-semantic. Policy tuple order remains
explicit and determines policy ordinals.

Identifier equality and collision membership are decided from complete,
validated Python strings. SHA-256 values identify canonical metadata and the
semantic corpus; hashes are never used as a substitute for equality.

## Implemented bounds and accounting

The analyzer fails closed when any configured bound is exceeded:

| Resource | Current limit | Accounting rule |
| --- | ---: | --- |
| Identifier input | 2,048 UTF-8 bytes; 1,024 code points | Each occurrence before transformation |
| Policy length | 8 stages | Each ordered policy |
| Stage output | 8,192 UTF-8 bytes; 4,096 code points | Every intermediate stage |
| Records | 2,048 | All occurrences, including exact duplicates |
| Policies | 8 | At least one policy is required |
| Aggregate input | 524,288 UTF-8 bytes | Sum of raw identifier bytes once per occurrence |
| Transform applications | 65,536 | Record count multiplied by the total stages across all policies |
| Aggregate transformed data | 33,554,432 UTF-8 bytes | Sum of every stage output for every record and policy |
| Policy collision groups | 8,192 | Cumulative across policies |
| Witnesses | 20,480 | Exact-duplicate and transform witnesses combined |
| Global components | 1,024 | Non-singleton union components |
| Corpus source | 4,194,304 bytes | Complete caller-supplied byte string |
| Corpus physical line | 8,192 bytes | Including LF/CRLF, or through final EOF |
| Corpus physical lines | 2,049 | One header plus at most 2,048 records |
| JSON nesting | 16 levels | Preflight depth outside strings |
| Canonical receipt | 16,777,216 bytes | Complete ASCII JSON plus final LF |
| Descriptor read request | 65,536 bytes | Maximum per already-open regular-file read |
| CLI policy argument | 256 ASCII bytes | Complete explicit hazard-and-step specification |
| Report records | 256 | Canonical records presented after verified replay |
| Report code-point tokens | 8,192 | Record inputs plus transformed collision values |
| Report groups | 4,096 | Exact and per-policy groups combined |
| Report witnesses | 4,096 | Witness rows presented |
| Report components | 1,024 | Cross-policy component cards |
| Offline report | 8,388,608 bytes | Complete ASCII HTML artifact |

Limits are part of the implementation, not capacity guidance for a hostile
multi-tenant service. The library runs synchronously in the caller's process;
callers remain responsible for process-level CPU, memory, concurrency, and
deadline isolation.

Analysis is atomic at the API boundary: a rejected record, policy, stage, or
output budget returns no partial `CollisionGraph`. Validation also rechecks
factory-created object state instead of trusting dataclass fields that could
have been forged through low-level Python operations.

## Errors and ordinals

`CollisionAnalysisError` exposes stable codes and bounded numeric context
without echoing record IDs or identifiers:

- `input_record_ordinal` refers to the original tuple position during record
  validation and aggregate-input accounting;
- `canonical_record_ordinal` refers to the record-ID-sorted position during
  policy evaluation; and
- `policy_ordinal` refers to the caller's policy tuple position.

These namespaces are intentionally distinct. A caller must not relabel an input
ordinal as a canonical ordinal in logs or reports. Corpus and receipt failures
similarly expose stable enums plus physical-line, input-record, or policy
ordinals only. Underlying transformation failures are represented by a stable
`transform_error_code`; library-owned errors do not include rejected values,
JSON tokens, or source lines.

`HazardHandling.PRESERVE` is an explicit analytical choice. It retains raw
control or format content and records hazard locations; it does not make that
content safe to display, log, export, or paste into a terminal.

## Sensitive values and Python object exposure

The following fields can contain sensitive namespace data:

- `IdentifierRecord.record_id` and `IdentifierRecord.identifier`;
- `TransformResult.transformed`;
- `CollisionGraph.record_ids`; and
- `PolicyCollisionGroup.transformed`.

Those values use `repr=False` where practical to reduce accidental exposure in
ordinary dataclass representations. This is an ergonomic safeguard, **not a
privacy or serialization boundary**. Direct attribute access,
`dataclasses.asdict`, pickle and similar serializers, debuggers, generic
introspection, exception frame locals, caller-owned objects, logging helpers,
and memory inspection can reveal the values. Frozen dataclasses do not make
their fields secret. Python strings cannot be reliably zeroized, and the
library makes no memory-erasure guarantee.

Do not pass a graph or record object to an unreviewed generic serializer. Do not
commit private identifier corpora, production usernames, routing tables,
credentials, personal data, or derived artifacts from them.

## Semantic digest boundary

`CollisionGraph.semantic_corpus_sha256` is domain-separated and uses
length-prefixed canonical record IDs and UTF-8 identifier values, ordered by
record ID. It binds the semantic in-memory record model and avoids delimiter
ambiguity.

It does **not** bind original source bytes, encoding markers, delimiters, line
endings, or JSON representation. The implemented receipt therefore keeps a
separate `source.sha256` and `source.byte_count` over the complete accepted
byte string. It deliberately does not bind a filename or path because the
library has no filesystem boundary.

The semantic digest is not a MAC, signature, authentication mechanism,
authorization decision, trusted timestamp, freshness proof, or anonymity
mechanism. Low-entropy identifiers and record IDs can be guessed, and reuse can
reveal equality between canonical corpora. Policy IDs and witness IDs have
similarly limited identity and indexing roles.

## Unicode and security non-claims

Casefold Observatory explains exact equality under explicitly selected
normalization and case operations. It does not currently implement or claim:

- Unicode Technical Standard #39 confusable skeletons or spoof detection;
- script restriction, mixed-script policy, or visual-glyph equivalence;
- IDNA/domain-name validation or browser URL semantics;
- locale-specific casing or downstream database/filesystem collation;
- complete `Default_Ignorable_Code_Point` property coverage;
- grapheme-cluster, font, terminal, or bidirectional display equivalence; or
- proof that a selected policy is safe for a particular authorization system.

Current reject/preserve handling covers the documented control, format, and
bidirectional-control classifications. Preserved text still requires safe,
visible rendering before a human can review it.

## Implemented POSIX filesystem and offline-report boundaries

The in-memory boundaries use strict bounded decoding, a versioned canonical
schema, exact-source and semantic digests, complete policy documents, producer
identity, and Unicode data binding. Receipts remain integrity evidence, not
proof of origin, unless separately signed or authenticated.

The POSIX CLI requires directory-descriptor and no-follow primitives. Directory
and final components are checked before and after descriptor opening; source
files must be stable, regular, and single-link. Reads stop at the configured
limit plus one byte. Receipt publication uses a same-directory exclusive 0600
temporary file, complete-write loop, file fsync, no-clobber hard-link publish,
two directory fsyncs, and invocation-owned temporary cleanup. An existing
destination, link, special file, alias, pathname race, mutation, or I/O failure
is rejected without exposing its path. See the
[portable receipt contract](docs/portable-receipt-contract.md).

The implemented HTML renderer verifies exact receipt and source bytes before it
parses and renders. It accepts at most 256 records, 8,192 presented code-point
tokens, 4,096 groups, 4,096 witnesses, 1,024 components, and 8 MiB of output.
The source and decoded DOM text remain ASCII. Printable ASCII glyphs are escaped;
all other code points are represented by logical position and metadata,
including U+ value, Unicode name, category, bidi class, combining class, UTF-8
bytes, engine hazard, and display flags. No raw bidirectional control, combining
mark, invisible, private-use, unassigned, noncharacter, or non-ASCII glyph is
placed in the DOM.

The document contains no script, form, image, media, font, worker, frame,
manifest, URL-bearing attribute, inline event handler, or remote asset. Its
Content Security Policy denies all default loads and permits only the exact
SHA-256-bound inline stylesheet. The policy is meaningful for an offline file,
but meta CSP cannot express frame-ancestors: if a report is served, anti-framing
requires an HTTP Content-Security-Policy response header. Rendering is not
authentication, freshness, authorization, or proof that an identifier is safe.

The evidence-only Chromium workflow uses reviewed synthetic data, an immutable
Linux-amd64 OCI platform digest, hash-locked automation wheels, a non-root
read-only container, and no network during capture. The hosted Docker boundary
does not expose a usable Chromium user namespace, so the Chromium process
sandbox is explicitly disabled and recorded rather than granting `SYS_ADMIN`
or broader container privileges. Only the trusted locally generated static
report is opened. JavaScript stays enabled so negative CSP probes are real. One
local document and zero subresources are required. Real desktop,
mobile-emulation, full-page, and scroll captures are independently verified
before manual adoption.

Published fixtures, screenshots, recordings, and generated diagrams must use
reviewed synthetic or openly licensed data, contain no secrets or personal
information, and include reproducible generation instructions. A visual is
evidence only for behavior produced by the checked-in code and input.

## Reporting a vulnerability

Use GitHub private vulnerability reporting for this repository when available.
Do not open a public issue containing an exploit, private corpus, credential, or
personal data.

Include the affected revision, policy and Unicode version, a minimal
non-sensitive reproduction, observed impact, and suggested mitigation. Reports
will be assessed before coordinated public disclosure.

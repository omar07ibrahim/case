# Security Policy

## Current support status

The supported tree contains two implemented, dependency-free library layers:

- bounded evaluation of explicit Unicode normalization and case policies; and
- bounded, deterministic in-memory collision analysis with exact-duplicate
  groups, per-policy minimal witness trees, and cross-policy union components.

There is currently no source-file ingestion, portable receipt format, CLI,
browser UI, network service, or general-purpose renderer for caller data. The
repository does include a deterministic documentation renderer for its fixed,
reviewed synthetic fixtures; it is not a product interface. Controls described
below for future surfaces are requirements, not claims about existing
functionality. The historical Flask prototype is unsupported and must not be
deployed.

## Current trust boundary

Every identifier, record ID, policy object, and caller-provided container is
untrusted. The public analyzer accepts exact tuples of validated
`IdentifierRecord` and `TransformPolicy` objects and returns Python objects in
the same process. It does not read files, write reports, open sockets, invoke a
shell, or render untrusted text.

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
ordinal as a canonical ordinal in logs or reports. Underlying transformation
failures are represented by a stable `transform_error_code`; a library-owned
collision error does not include the rejected value.

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

It does **not** bind original source bytes, file encoding markers, delimiters,
comments, line endings, filenames, record tuple order, or ingestion settings.
The current API has already received decoded Python strings, so it cannot prove
what source representation produced them. A future ingestion receipt must
separately bind exact source bytes.

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

## Requirements for future ingestion and rendering

Future file and CLI layers must use strict, bounded decoding and must account
for source bytes, lines, records, fields, and aggregation independently.
Portable receipts must use a versioned canonical schema and bind exact source
bytes, policy documents, implementation identity, and Unicode data version.
Unless separately signed or authenticated, those receipts will still be
integrity evidence rather than proof of origin. The design-only
[portable receipt contract](docs/portable-receipt-contract.md) makes this future
boundary concrete; it is **not implemented yet** and does not expand the current
support status.

Terminal output must prevent ANSI/control interpretation and show controls,
bidirectional marks, invisible code points, and ambiguous whitespace visibly.
CSV export must defend against formula injection. HTML and SVG must escape
untrusted text rather than interpreting it as markup or script. Any future
browser interface must work offline, load no remote runtime assets, and enforce
a restrictive Content Security Policy.

Filesystem output must use safe atomic publication, reject or explicitly handle
links and special files, avoid input/output aliasing, and prevent path
traversal. Analysis and evidence regeneration must not require network access.

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

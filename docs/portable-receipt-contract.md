# Portable Corpus and Receipt Contract

## Status

> **DESIGN CONTRACT — NOT IMPLEMENTED YET.**
>
> The current supported package accepts bounded in-memory IdentifierRecord and
> TransformPolicy tuples and returns a CollisionGraph. It has no corpus-file
> parser, portable receipt serializer or verifier, installed command-line
> entry point, or filesystem output layer. This document specifies a proposed
> version 1 boundary for a future milestone; it does not expand the current
> support statement or turn the checked-in visual-evidence JSON into a receipt.

Normative words such as MUST and MUST NOT describe the future implementation.
Until that implementation, no command, file extension, exit code, or persistence
guarantee in this document is available.

The design preserves the existing collision algorithm, canonical record
ordinals, policy order, resource accounting, redacted errors, semantic corpus
digest, and Unicode database binding. It adds a separate binding to exact source
bytes without changing the meaning of CollisionGraph.semantic_corpus_sha256.

## Intended scope

Version 1 is intended to provide one deliberately narrow offline workflow:

1. read one bounded, regular UTF-8 JSON Lines corpus;
2. create explicitly ordered policies for the active Unicode database;
3. run the existing in-memory collision analyzer;
4. serialize the complete graph and execution identity into canonical JSON;
5. publish that receipt without overwriting an existing path; and
6. verify it by rereading the exact source bytes and recomputing the result.

The proposed layer has no network access, service mode, browser interface,
plugin system, user configuration, signing key, implicit policy, stdin corpus,
stdout receipt, overwrite flag, or generic renderer for caller-controlled data.

## Corpus JSON Lines schema

The format identifier is
casefold-observatory.identifier-corpus-jsonl and its format version is 1.

The first physical line MUST be one header object. Every following physical line
MUST contain one record object:

~~~json
{"schema":"casefold-observatory.identifier-corpus","schema_version":1}
{"identifier":"SS","record_id":"upper"}
{"identifier":"\u00df","record_id":"eszett"}
{"identifier":"ss","record_id":"lower"}
~~~

The example is synthetic and illustrative. It is not a checked-in input fixture
and cannot be processed by the current package.

### Encoding and line rules

- The complete source MUST be strict UTF-8. A UTF-8 byte-order mark is rejected.
- A line terminator MAY be LF or CRLF. Bare CR is rejected. The final line MAY
  end at EOF without a terminator.
- The header MUST be the first line. Empty lines and comments are rejected.
- Each line MUST contain exactly one JSON object. Trailing non-whitespace data
  on a line is rejected.
- Duplicate object keys, unknown keys, missing keys, JSON constants such as NaN
  or Infinity, and values of the wrong exact JSON type are rejected.
- schema_version MUST be the integer 1; a JSON Boolean is not an integer for
  this contract.
- A header has exactly the keys schema and schema_version.
- A record has exactly the keys identifier and record_id. Both values are JSON
  strings.
- JSON whitespace, object-key order, and escape spelling are source
  representation details. If accepted, their exact bytes remain significant to
  the source digest.
- Decoded identifiers MUST contain Unicode scalar values. An unpaired surrogate
  escape is rejected through the existing identifier validation boundary.

record_id retains the existing grammar [a-z][a-z0-9._-]{0,63} and MUST be
unique. identifier retains the existing non-empty, 1,024-code-point and
2,048-UTF-8-byte limits. The header-only corpus is valid and represents zero
records.

### Proposed ingestion bounds

| Resource | Version 1 limit | Accounting rule |
| --- | ---: | --- |
| Complete source | 4,194,304 bytes | Every original byte, including header, JSON syntax, whitespace, and line terminators |
| One physical line | 8,192 bytes | Bytes through its terminator, or through EOF for the final line |
| Physical lines | 2,049 | One header plus at most 2,048 record lines |
| JSON nesting | 16 levels | Preflight depth outside JSON strings before object decoding |
| Read chunk | 65,536 bytes | Maximum requested from the already-open descriptor per read |
| Records | 2,048 | Existing analyzer limit |
| Aggregate decoded identifiers | 524,288 UTF-8 bytes | Existing analyzer limit |

All existing policy, transform-application, transformed-data, group, witness,
and component limits continue to apply. File limits are additional rejection
boundaries, not enlarged analyzer capacity.

The future reader may consume a file in fixed-size chunks, but version 1 does
not claim arbitrary, unbounded, asynchronous, or constant-memory streaming. It
may retain at most the bounded source bytes while producing the in-memory
record tuple.

## Two separate corpus digests

A future receipt MUST keep these identities distinct:

- source.sha256 is lowercase SHA-256 of the complete original source byte
  sequence, without normalization or domain rewriting. source.byte_count is
  the length of that same sequence.
- graph.semantic_corpus_sha256 remains the existing domain-separated,
  length-prefixed digest of canonical record IDs and decoded identifiers sorted
  by record ID.

Changing LF to CRLF, JSON whitespace, key order, escape spelling, or record-line
order changes source.sha256. When the decoded record set is otherwise identical,
those representation changes do not change semantic_corpus_sha256 or canonical
record ordinals. Neither digest decides identifier equality.

## Canonical receipt schema

The receipt schema identifier is casefold-observatory.analysis-receipt and its
schema version is 1. The top-level object has exactly six keys:

~~~json
{
  "graph": {
    "algorithm": "stage-partition-witness-v1",
    "components": [],
    "duplicate_groups": [],
    "isolated_record_ordinals": [],
    "policy_groups": [],
    "policy_ids": [],
    "record_ids": [],
    "semantic_corpus_sha256": "<64 lowercase hexadecimal characters>",
    "unicode_version": "<active runtime Unicode database version>",
    "witnesses": []
  },
  "policies": [
    {
      "document": {
        "bounds": {},
        "hazard_handling": "reject",
        "schema": "casefold-observatory.transform-policy",
        "schema_version": 1,
        "steps": ["case:lower", "case:casefold"],
        "unicode_version": "<active runtime Unicode database version>"
      },
      "policy_id": "<64 lowercase hexadecimal characters>"
    }
  ],
  "producer": {
    "distribution": "casefold-observatory",
    "version": "<installed distribution version>"
  },
  "schema": "casefold-observatory.analysis-receipt",
  "schema_version": 1,
  "source": {
    "byte_count": 0,
    "format": "casefold-observatory.identifier-corpus-jsonl",
    "format_version": 1,
    "sha256": "<64 lowercase hexadecimal characters>"
  }
}
~~~

Angle-bracketed strings above describe fields; they are not literal accepted
values. The future implementation MUST emit the complete existing canonical
policy document, including its current bounds. policies preserves command-line
policy order, and each policy_id MUST equal SHA-256 of the existing canonical
policy bytes.

The graph object is a portable projection of every current CollisionGraph
field. Its nested objects have these exact fields:

- duplicate group: group_id, member_record_ordinals, witness_ids;
- policy group: group_id, member_record_ordinals, output_codepoints,
  output_utf8_bytes, policy_id, policy_ordinal, transformed, witness_ids;
- witness: kind, left_record_ordinal, policy_id, policy_ordinal,
  right_record_ordinal, stage_index, step, witness_id;
- component: component_id, duplicate_group_ids, member_record_ordinals,
  policy_group_ids, policy_ordinals, witness_tree_ids.

Exact-input witnesses retain explicit JSON null values for policy_id,
policy_ordinal, stage_index, and step. Derived convenience counts are not part of
the graph projection. transformed and record_ids are included, so a complete
receipt is sensitive even though it does not repeat every raw identifier in a
separate source array.

### Canonical receipt bytes

A conforming serializer MUST produce:

- JSON encoded as ASCII bytes with every non-ASCII string character escaped;
- object keys in ascending order;
- no insignificant whitespace;
- no NaN or Infinity values;
- one LF byte after the top-level object and no other trailing bytes; and
- at most 16,777,216 bytes in total.

The intended Python serialization parameters are ensure_ascii=True,
sort_keys=True, separators=(",", ":"), and allow_nan=False, followed by one LF.
The schema admits only objects, arrays, strings, exact integers, and null, so it
does not depend on floating-point formatting.

A receipt larger than the bound is rejected before publication. A verifier MUST
reject noncanonical receipt bytes even if a generic JSON parser would assign
them similar values.

The receipt MUST NOT contain timestamps, local or absolute paths, hostnames,
usernames, environment variables, Python patch versions, machine identifiers,
or an embedded digest of itself. A command may report lowercase SHA-256 of the
complete canonical receipt bytes after successful publication.

## Unicode database and policy contract

The existing Unicode database rule remains authoritative:

- policy creation binds a policy to unicodedata.unidata_version;
- CollisionGraph.unicode_version records that active version;
- canonical policy documents include that same version; and
- policy IDs deliberately change when the Unicode version changes.

Receipt creation requires every policy version and graph.unicode_version to
equal the active runtime version. Verification requires the receipt graph,
every embedded policy document, and the verifying runtime to agree exactly. A
mismatch fails closed before collision analysis. Version 1 has no ignore,
upgrade, reinterpret, or best-effort option.

The currently committed visual bundle is separate evidence bound to Unicode
database 15.0.0 and replayed exactly on Python 3.12. This design document does
not change those files, their generator-owned schema, their hashes, or their
documented skip behavior on another Unicode database.

## Proposed installed command

> **NOT IMPLEMENTED YET:** there is currently no casefold-observatory console
> script and no python -m casefold_observatory command.

The proposed commands are:

~~~console
casefold-observatory analyze --source CORPUS.jsonl --policy reject@case:lower,case:casefold --receipt RESULT.receipt.json

casefold-observatory verify --source CORPUS.jsonl --receipt RESULT.receipt.json
~~~

A policy argument has the exact ASCII grammar:

~~~text
(reject|preserve)@STEP[,STEP...]
~~~

STEP is one existing TransformStep value. One policy contains one through eight
steps. analyze requires one through eight repeated --policy arguments and
preserves their order. Hazard handling is explicit in every argument; there is
no implicit policy or locale.

Version 1 deliberately does not accept a source or receipt through -, emit a
receipt to stdout, overwrite an existing destination, read configuration from
the working directory or home directory, invoke a shell, or use the network.

### Terminal output

Successful analyze writes one bounded ASCII JSON line to stdout after the
receipt is durable:

~~~json
{"colliding_record_count":3,"component_count":1,"policy_group_count":1,"receipt_sha256":"<64 lowercase hexadecimal characters>","record_count":3,"status":"analyzed","witness_count":2}
~~~

Successful verify writes:

~~~json
{"receipt_sha256":"<64 lowercase hexadecimal characters>","status":"verified"}
~~~

On a handled failure stdout is empty and stderr contains one bounded canonical
ASCII JSON line with a stable code and, where applicable, only numeric ordinal
context. It MUST NOT echo a path, record ID, identifier, transformed value,
source line, policy argument, or raw parser token. Help and version output are
static ASCII text. No output contains ANSI control sequences or color.

Proposed exit statuses are:

| Status | Meaning |
| ---: | --- |
| 0 | Successful analysis or verification |
| 1 | Redacted unexpected internal failure |
| 2 | Command usage, corpus syntax, or receipt schema rejection |
| 3 | Policy, collision-analysis, or resource-limit rejection |
| 4 | Source digest, receipt replay, producer version, algorithm, or Unicode version mismatch |
| 5 | Filesystem type, link, alias, race, or I/O rejection |

## POSIX filesystem boundary

These requirements apply only to the future file command. The current
in-memory API performs no filesystem access.

### Safe reads

- Path traversal through a .. component is rejected.
- Path components are opened from a pinned directory descriptor rather than
  accepted after string resolution.
- Directory components use O_DIRECTORY, O_NOFOLLOW, and O_CLOEXEC.
- Before opening the final name, stat with follow_symlinks=False and require a
  regular file. Then open it with O_RDONLY, O_NONBLOCK, O_NOFOLLOW, and
  O_CLOEXEC, and use fstat to require the same device and inode and a regular
  file again. This closes the type-swap race without blocking on a FIFO.
- Symlinks, directories, FIFOs, sockets, devices, and other special files are
  rejected before content reads. O_NONBLOCK may be cleared only after fstat has
  established a regular file.
- A size check is only an early rejection. The reader still reads at most the
  configured limit plus one byte so a growing file cannot bypass accounting.
- The already-open descriptor is the source of both parsing and hashing.
  Pre-read and post-read fstat values must retain the same device, inode, size,
  mtime_ns, and ctime_ns; otherwise the operation fails as a concurrent
  mutation.
- Captured bytes are parsed once. Verification does not reopen a path between
  digest comparison and analysis.
- POSIX support MUST fail closed when the required no-follow or directory-
  descriptor primitives are unavailable; version 1 makes no portable Windows
  race-safety claim.

### No-clobber atomic receipt output

Version 1 never replaces an existing destination. Before any analysis result is
published:

1. Open and pin the existing parent directory with no-follow directory flags.
2. Reject an existing destination of every type, including a regular file,
   hard link, symlink, FIFO, socket, or directory.
3. Reserve a randomly named same-directory temporary regular file with
   O_WRONLY, O_CREAT, O_EXCL, O_NOFOLLOW, and O_CLOEXEC at mode 0600.
4. Write the complete bounded canonical bytes with a short-write loop, set mode
   0600, flush, and fsync the temporary file.
5. Publish without clobber through a same-directory hard link from the temporary
   inode to the absent destination name. FileExistsError is a rejection, not a
   reason to replace.
6. fsync the directory, remove the temporary name, and fsync the directory
   again.
7. On every failure path, close descriptors and remove only the temporary name
   created by this invocation.

The success summary is printed only after publication and directory durability.
Because the destination must be absent, input/output pathname and hard-link
aliasing fail rather than overwriting input. The receipt default mode is 0600
because record IDs and transformed strings can be private.

Atomic publication prevents readers from seeing a partially written receipt. It
does not make the directory trustworthy against a privileged actor or another
process that already has authority to mutate that directory, and it is not a
transaction spanning the source file and output filesystem.

## Verification algorithm

A conforming future verifier performs these steps in order:

1. Safe-open and bounded-read the receipt.
2. Preflight JSON depth, reject duplicate keys and wrong exact types, and
   require exact schema keys and canonical bytes.
3. Require the receipt producer distribution and version to equal the executing
   installed distribution.
4. Recreate every policy only through validated current-runtime policy
   construction. Compare its full canonical document and policy ID with the
   embedded values while preserving policy order.
5. Require the graph, policies, and active runtime Unicode versions to match.
6. Safe-open and bounded-read the source once.
7. Compare byte_count and source SHA-256 using constant-time digest comparison.
8. Parse the captured source bytes and invoke the existing analyzer.
9. Build the expected canonical receipt from that trusted result.
10. Require exact byte equality with the supplied canonical receipt and emit
    only the safe success summary.

Receipt JSON is never deserialized directly into a trusted CollisionGraph.
Trusted graph state comes from recomputing the current analyzer over the
captured source. Any rejection is atomic: no partial graph or replacement
receipt is returned.

## Privacy and error boundary

A receipt is not a redacted export. It contains record IDs, policy documents,
semantic and source digests, collision relations, and transformed values.
Transformed values can equal or reveal source identifiers. Mode 0600 reduces
accidental local disclosure but provides no encryption, memory isolation, or
secure erasure.

Library- and CLI-owned errors must expose stable categories and bounded numeric
context only. Generic JSON exceptions, Unicode decode exceptions, OSError path
messages, argument parser echoes, and tracebacks must not cross the CLI
boundary. Caller-owned exception context and process inspection remain outside
that guarantee.

Do not publish a receipt derived from a private namespace merely because the
raw source file is absent. Low-entropy identifiers, record IDs, source digests,
semantic digests, and transformed outputs can be guessed or correlated.

## Evidence required after implementation

No new screenshot, terminal image, animation, or receipt fixture should be
published before the corresponding installed workflow exists and passes its
tests. The implementation milestone must later provide real, reproducible
evidence generated from the built wheel:

- a reviewed synthetic corpus with no private or personal identifiers;
- exact captured argv, stdout, stderr, exit status, package version, Unicode
  version, and receipt hash in a machine-readable manifest;
- a committed receipt produced by the installed command, not hand-authored;
- a static PNG alternative and a short GIF derived only from the captured CLI
  bytes;
- an updated offline SVG architecture and result diagram generated from the
  receipt;
- byte-for-byte regeneration and safe-file-mode checks in CI;
- no remote fonts, scripts, images, styles, tracking, timestamps, absolute
  paths, machine identifiers, secrets, or copied third-party assets; and
- clear captions distinguishing an actual capture, receipt-derived result, and
  explanatory architecture.

A deterministic renderer may use a separately pinned development-only image
encoder after license review. It must not add a package runtime dependency.
Existing visuals remain evidence only for the current in-memory API until they
are regenerated from an implemented surface.

## Security and correctness nonclaims

The future receipt, even when implemented and successfully verified, will not
be:

- a signature, MAC, proof of origin, trusted timestamp, freshness proof,
  authorization record, or proof that a trusted machine ran the command;
- encryption, anonymization, confidential computation, memory erasure, or a
  safe publication format for private namespaces;
- Unicode Technical Standard #39 confusable detection, mixed-script policy,
  IDNA validation, locale-specific casing, visual-glyph equivalence, or a model
  of database or filesystem collation;
- evidence that every pair in a cross-policy global component is equal under
  one policy;
- a sandbox, deadline mechanism, multi-tenant service boundary, or protection
  from a privileged local actor; or
- a browser UI, network service, generic Unicode security verdict, or
  replacement for application-specific authorization review.

A missing collision still means only that supplied identifiers did not become
exactly equal under the explicitly supplied policies and active Unicode data.

# Portable Corpus and Receipt Contract

## Status

> **IN-MEMORY BYTE CONTRACT IMPLEMENTED IN 0.3.0; POSIX CLI AND CLI
> EVIDENCE IN 0.4.0; VERIFIED OFFLINE REPORT IN 0.5.0.**
>
> The supported package accepts a bounded JSON Lines corpus as exact caller-owned
> bytes, creates and replays a canonical portable receipt, and exposes analysis,
> verified static-HTML reporting, and replay through installed
> `casefold-observatory` and module entry points. The command, terminal, POSIX
> filesystem, report, CSP, and two-stage visual-evidence sections below are
> implemented. CI reproduces adopted evidence byte-for-byte and stages drift for
> review without editing the checkout.

Normative words in the corpus, receipt, command, terminal, verification, error,
and POSIX filesystem sections describe implemented version 1 behavior.

The design preserves the existing collision algorithm, canonical record
ordinals, policy order, resource accounting, redacted errors, semantic corpus
digest, and Unicode database binding. It adds a separate binding to exact source
bytes without changing the meaning of CollisionGraph.semantic_corpus_sha256.

## Intended scope

Version 1 provides one deliberately narrow offline workflow:

1. capture one bounded UTF-8 JSON Lines corpus from a stable POSIX descriptor or
   accept the same exact `bytes` through the library API;
2. accept explicitly ordered policies for the active Unicode database;
3. run the in-memory collision analyzer;
4. project the complete graph and execution identity into canonical JSON bytes;
5. durably publish a new receipt without clobber, or return those bytes to a
   library caller;
6. verify canonical receipt bytes against the same captured source by replay;
   and
7. render and durably publish a bounded static HTML report only after that exact
   verification succeeds.

The implemented layer has no network access, service mode, served or interactive
browser interface, plugin system, user configuration, signing key, implicit
policy, stdin corpus, stdout receipt or report, or overwrite mode. The package
does not launch a browser; Chromium is used only by the isolated evidence lane.

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

The example is synthetic and illustrative. It is not a checked-in input
fixture; callers can pass the equivalent bytes to
`create_collision_receipt(source_bytes, policies)`.

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

### Corpus and descriptor bounds

| Resource | Version 1 limit | Accounting rule |
| --- | ---: | --- |
| Complete source | 4,194,304 bytes | Every original byte, including header, JSON syntax, whitespace, and line terminators |
| One physical line | 8,192 bytes | Bytes through its terminator, or through EOF for the final line |
| Physical lines | 2,049 | One header plus at most 2,048 record lines |
| JSON nesting | 16 levels | Preflight depth outside JSON strings before object decoding |
| Descriptor read request | 65,536 bytes | Maximum requested from an already-open regular-file descriptor |
| CLI policy argument | 256 ASCII bytes | Complete explicit hazard-and-step specification |
| Records | 2,048 | Existing analyzer limit |
| Aggregate decoded identifiers | 524,288 UTF-8 bytes | Existing analyzer limit |

All existing policy, transform-application, transformed-data, group, witness,
and component limits continue to apply. Corpus-byte limits are additional rejection boundaries, not enlarged analyzer
capacity.

The filesystem reader consumes the already-open descriptor in fixed-size chunks,
but version 1 does not claim arbitrary, unbounded, asynchronous, or
constant-memory streaming. It retains at most the bounded source bytes while
producing the in-memory record tuple.

## Two separate corpus digests

A receipt keeps these identities distinct:

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
values. The implementation emits the complete existing canonical
policy document, including its current bounds. policies preserves caller or CLI
argument order, and each policy_id MUST equal SHA-256 of the existing canonical
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

Creation rejects a receipt larger than the bound before returning it. A verifier
rejects an oversized receipt before parsing and rejects noncanonical bytes even
if a generic JSON parser would assign them similar values. The analyze command
completes the same check before publication.

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

## Installed command

The console script and module entry point are byte-for-byte equivalent:


~~~console
casefold-observatory analyze --source CORPUS.jsonl --policy reject@case:lower,case:casefold --receipt RESULT.receipt.json

casefold-observatory report --source CORPUS.jsonl --receipt RESULT.receipt.json --output RESULT.report.html

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

The exact top-level forms are `--help`, `--version`, `analyze`,
`report`, and `verify`. Options use separate tokens; short options and
`--option=value` forms are rejected. Analyze requires exactly one `--source`,
exactly one `--receipt`, and one through eight `--policy` pairs in any option
order. Report requires exactly one `--source`, one `--receipt`, and one
`--output` pair in any option order. Verify requires exactly one `--source`
and one `--receipt` pair in either order. A subcommand accepts `--help` only
as its sole following token.

Version 1 does not accept a source or receipt through `-`, emit a receipt or
report to stdout, overwrite an existing destination, read configuration from
the working directory or home directory, invoke a shell, launch a browser, or
use the network.

### Terminal output

Successful analyze writes one bounded ASCII JSON line to stdout after the
receipt is durable:

~~~json
{"colliding_record_count":3,"component_count":1,"policy_group_count":1,"receipt_sha256":"<64 lowercase hexadecimal characters>","record_count":3,"status":"analyzed","witness_count":2}
~~~

Successful report writes one bounded ASCII JSON line only after the HTML file is
durable:

~~~json
{"receipt_sha256":"<64 lowercase hexadecimal characters>","report_bytes":12345,"report_sha256":"<64 lowercase hexadecimal characters>","status":"reported"}
~~~

The integer above illustrates the exact type; its value is the complete emitted
HTML byte count.

Successful verify writes:

~~~json
{"receipt_sha256":"<64 lowercase hexadecimal characters>","status":"verified"}
~~~

On a handled failure stdout is empty and stderr contains one bounded canonical
ASCII JSON line. Its exact base object is
`{"code":"<namespace.code>","status":"error"}`; applicable numeric
`physical_line_ordinal`, `input_record_ordinal`,
`canonical_record_ordinal`, and `policy_ordinal` keys are added and the
complete object is serialized with sorted keys, compact separators, ASCII
escaping, and one final LF. It never echoes a path, record ID, identifier,
transformed value, source line, policy argument, or raw parser token. Help and
version output are static ASCII text. No output contains ANSI controls or color.

Exit statuses are:

| Status | Meaning |
| ---: | --- |
| 0 | Successful analysis or verification |
| 1 | Redacted unexpected internal failure |
| 2 | Command usage, corpus syntax, or receipt schema rejection |
| 3 | Policy, collision-analysis, or resource-limit rejection |
| 4 | Source digest, receipt replay, producer version, algorithm, or Unicode version mismatch |
| 5 | Filesystem type, link, alias, race, or I/O rejection |

## POSIX filesystem boundary

The installed command implements this boundary. It fails closed on non-POSIX
systems or when required descriptor-relative, no-follow, link, or directory
primitives are unavailable. The in-memory APIs remain filesystem-free.

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

The report command captures the source and receipt exactly once, rejects source,
receipt, and destination inode aliasing, verifies and renders completely in
memory, and then uses the same no-clobber publication primitive. The report is
also mode 0600 because it visibly includes record IDs, transformed values, and
source-derived code-point metadata. Success is printed only after publication
and directory durability. A render or publication failure leaves no final
destination.

## Verification algorithm

A conforming verifier performs these steps in order:

1. Require exact receipt `bytes` and enforce the complete byte bound.
2. Preflight ASCII JSON depth, reject duplicate keys and wrong exact types, and
   require exact schema keys and canonical bytes.
3. Require the receipt producer distribution to be
   `casefold-observatory` and its version to be exactly one of the implemented
   compatibility tuple `("0.4.0", "0.5.0")`. New receipts use 0.5.0.
4. Recreate every policy only through validated current-runtime policy
   construction. Compare its full canonical document and policy ID with the
   embedded values while preserving policy order.
5. Require the graph, policies, and active runtime Unicode versions to match.
6. Require exact source `bytes` and enforce the complete byte bound.
7. Compare byte_count and source SHA-256 using constant-time digest comparison.
8. Parse those captured source bytes and invoke the existing analyzer.
9. Build the expected canonical receipt from that trusted result while
   preserving the accepted input receipt's producer version.
10. Require exact byte equality with the supplied canonical receipt and emit
    only the safe success summary.

Receipt JSON is never deserialized directly into a trusted CollisionGraph.
Trusted graph state comes from recomputing the current analyzer over the
captured source. Any rejection is atomic: no partial graph or replacement
receipt is returned.

## Privacy and error boundary

A receipt is not a redacted export. It contains record IDs, policy documents,
semantic and source digests, collision relations, and transformed values.
Transformed values can equal or reveal source identifiers. A report is even more
visibly source-derived: it includes record IDs plus logical code-point metadata
for identifiers and collision outputs. The byte APIs make no persistence or
file-mode guarantee. The installed analyze and report commands publish new
artifacts at mode 0600; that reduces accidental local disclosure but provides
no encryption, memory isolation, or secure erasure.

Library-owned errors expose stable categories and bounded numeric context only.
The CLI preserves that rule. Generic JSON exceptions, Unicode decode
exceptions, OSError path messages, argument echoes, and tracebacks do not cross
the command boundary. Caller-owned exception context and process inspection
remain outside that guarantee.

Do not publish a receipt derived from a private namespace merely because the
raw source file is absent. Low-entropy identifiers, record IDs, source digests,
semantic digests, and transformed outputs can be guessed or correlated.

## Verified offline HTML report

`render_offline_report(receipt_bytes, source_bytes)` first performs the exact
verification algorithm above and maps identifiers to the analyzer's canonical
record ordinals. It parses the source once and renders only factory-owned,
recomputed state. The resulting document has schema
`casefold-observatory.offline-report` version 1.

Presentation is separately bounded at 256 records, 8,192 total displayed
code-point tokens, 4,096 exact-plus-policy groups, 4,096 witnesses, 1,024
components, and 8,388,608 output bytes. Exceeding a presentation bound does not
change analysis semantics; rendering fails atomically with a stable non-echoing
report error.

The HTML source and browser-decoded DOM text are ASCII. Printable ASCII is HTML
escaped. Every other code point is represented without its raw glyph by logical
index, U+ value, Unicode name, general category, bidi class, canonical combining
class, UTF-8 hexadecimal bytes, the engine's hazard classification, and explicit
display flags. This applies to bidirectional controls, format characters,
combining marks, separators, emoji sequences, private-use values, unassigned
values, and noncharacters.

The document contains no JavaScript, form, image, font, media, object, frame,
worker, manifest, connection, event handler, URL-bearing attribute, or remote
asset. One inline stylesheet is allowed only by its exact SHA-256 CSP hash;
default, script, attribute-style, image, font, media, connection, worker, child,
frame, object, form-action, base, and manifest capabilities are denied. Meta CSP
does not support `frame-ancestors`; serving the file requires an equivalent
HTTP Content Security Policy response header for anti-framing.

The report is deterministic for exact receipt bytes, exact source bytes, the
package implementation, and active Unicode database. It is not a signature,
proof of origin, trusted timestamp, freshness proof, authorization decision, or
generic Unicode safety verdict.

## Chromium report evidence

The evidence lane builds the 0.5.0 wheel from a clean source archive and runs it
inside an immutable Linux-amd64 Playwright image selected by platform-manifest
digest. Automation packages are hash locked. Two fresh non-root, read-only
containers run with no network, no added capabilities, no-new-privileges,
private temporary storage, and no repository credentials or Docker socket.

JavaScript remains enabled. Each page must make one local document request and
zero subresource requests, remain inside responsive layout bounds, contain only
the reviewed DOM allowlist, and preserve ASCII decoded text. Negative probes
must demonstrate that an appended inline script and altered inline style are
blocked. Real 1440 x 1000 desktop, 390 x 844 mobile-emulation, full-page, and
four-position scroll captures are recorded. The GIF uses actual browser
`scrollTo` positions and viewport screenshots, not a crop of the full-page
image.

A generator-owned eight-file candidate is rendered twice, independently
verified without importing the generator or project package, and compared
byte-for-byte. Drift is uploaded and the workflow fails; the checkout is never
rewritten. Artifact upload is not adoption. A separate human-reviewed adoption
record binds the hosted archive and exact committed bytes only after structural,
privacy, provenance, and pixel inspection.

## Adopted CLI visual evidence

The installed command contract was green before visual adoption. Evidence then
passed two distinct gates: a candidate capture was hosted without changing the
repository, and an independent review adopted those exact bytes only after
validating their provenance, structure, content, and privacy boundary.

The reviewed source fixture is
`docs/cli-evidence/fixtures/cli-demo.v1.jsonl` (SHA-256
`a77c90ed5e767a4e0a8029cad14ed347354a3b939b62ad75c0da091b522a259f`). It
contains only seven synthetic identifiers selected to exercise lower, case-fold,
and NFKC-plus-case-fold collisions.

The canonical capture environment is exact CPython 3.12.3 on Linux x86-64,
Unicode database 15.0.0, package 0.5.0 installed from the built wheel, and
Pillow 12.3.0 used only by the renderer. Pillow is installed binary-only from
`requirements/cli-visuals.txt` with the canonical CPython 3.12 manylinux wheel
SHA-256
`78cb2c6865a35ab8ff8b75fd122f6033b92a62c82801110e48ddd6c936a45d91`.
It is not a package runtime dependency. The renderer also requires
`ImageFont.load_default(...).getname()` to resolve exactly to
`("Aileron", "Regular")`. License, wheel, source, and embedded-font provenance
are recorded in `THIRD_PARTY_NOTICES.md`.

The adopted bundle has exactly six files:

1. `docs/cli-evidence/evidence/cli-evidence.v1.json`;
2. `docs/cli-evidence/evidence/cli-demo.receipt.v1.json`;
3. `docs/cli-evidence/cli-transcript.png`;
4. `docs/cli-evidence/cli-demo.gif`;
5. `docs/cli-evidence/cli-result.svg`; and
6. `docs/cli-evidence/cli-workflow.svg`.

`docs/cli-evidence/README.md` is the human-readable index and reproduction
guide, not a seventh bundle member. The machine manifest records exact argv,
stdout bytes, stderr bytes, exit status, and channel digests for installed-console
analyze, installed-module verify, no-clobber rejection, and source-mismatch
rejection. It also records the installed package identity, wheel filename,
installed-runtime per-file digests and aggregate runtime-tree digest, Python and
Unicode versions, exact build-tool versions, canonical Pillow wheel filename and
digest, resolved font family and style, source commit and tree identities, source
bindings, fixture identity, real receipt identity, renderer identity, and the
acyclic hash/size inventory of the other five files. The manifest lists itself
in the artifact inventory but deliberately does not hash itself.

The analyze capture proves that the runtime-created receipt was a regular,
single-link mode-0600 file before its bytes were copied into the candidate. Git
cannot preserve mode 0600 for a normal blob: the adopted synthetic receipt is a
regular `100644` repository file. Captions and manifests state both facts and
do not imply that checkout preserves the runtime mode.

The frozen candidate provenance is:

- source commit `03c6f16c03e3d3e1a5230afe58f478da12228d4a`;
- source tree `78f789909de47ab5b8121f5acc510d758c241492`;
- workflow run `31293264288`, attempt `1`, job `93194112959`;
- artifact `generated-cli-evidence-31293264288`, ID `9032120081`; and
- archive size `188273` bytes with SHA-256
  `2d9f3f8aee1f95868bfb656d17468b14854a75be606aa8a45df246ec3e04d4d4`.

The candidate job was pinned to `ubuntu-24.04`, checked out the explicit
pull-request head SHA, asserted the 40-hex source revision and HEAD tree, built
the wheel from a clean `git archive` copy with fixed source epoch, and passed
both source objects into two fresh runner-temporary renders. A merge ref or
`refs/pull/*/merge` SHA was not accepted as provenance.

Every renderer input is captured through an `O_NOFOLLOW` and close-on-exec
descriptor. The bounded reader compares descriptor identity, type, link count,
size, modification time, and change time before and after a maximum-plus-one
read, then confirms the pathname still names that same inode.

The PNG decodes at its exact RGB dimensions with no text, time, EXIF, ICC, or
other metadata. Every GIF frame fully decodes at the exact full-canvas
dimensions with the reviewed duration, loop count zero, disposal method two, and
no transparency, comment, EXIF, or ICC metadata. Transcript wrapping is
measured with the exact font's pixel bounding boxes rather than character
counts. The font bounding box uses the exact Pillow raster mode derived from
the target drawing surface (`"1"` for the palette GIF and `"L"` for the RGB
PNG), and equals `ImageDraw.textbbox` before drawing. The renderer normalizes
every requested text position to the actual ink bounding-box top-left, including
glyphs with negative horizontal or vertical bearings. Every drawn line is
rejected if its measured left, top, right, or bottom edge escapes the reviewed
panel and canvas padding; captured text is continued without truncation and
reconstructs to the exact original channel text. The GIF uses one deterministic
full-canvas height derived from the tallest measured phase: the exact line
boxes, inter-line gaps, receipt-footer gap and height, panel bottom padding, and
canvas bottom padding are all included and asserted.

The hosted archive was independently downloaded and checked for an exact
six-entry inventory, regular `100644` modes, manifest and receipt consistency,
source bindings, per-file identities, PNG/GIF/SVG structure, complete unclipped
rendering, and absence of host paths, secrets, email addresses, remote assets,
or personal data. Commit
`fca957b24f45031f651d918636294874b18e3251` adopted the reviewed six-file bundle state, changing only the two drifting
blobs without rerendering either one. The separate canonical record
`docs/cli-evidence/evidence/cli-evidence-adoption.v1.json` preserves the
artifact archive identity, every adopted file hash and size, capture source
commit and tree, and review outcomes.

The README therefore embeds the assets with distinct captions: a verified
rasterized CLI transcript (not an OS screenshot), a four-phase observed-command
GIF, a receipt-derived result, and an explanatory workflow. Current CI checks
out the explicit pull-request head, builds and installs its wheel outside the
checkout, performs two fresh captures, audits and compares them, and then
compares all six outputs byte-for-byte with the adopted files. Any bound runtime
source drift fails the check, and the checkout must remain clean. On drift, the final job uploads only the bounded review candidate; it never
substitutes generated media into the repository.

No evidence file contains a remote font, script, image, stylesheet, tracking
identifier, timestamp, absolute host path, machine identifier, secret, or copied
third-party asset. Existing `docs/visuals` files remain evidence for the
in-memory API; the CLI evidence is a separate source-bound bundle.

## Security and correctness nonclaims

The implemented receipt, even when successfully verified, is not:

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
- an interactive or served browser UI, network service, generic Unicode security verdict, or
  replacement for application-specific authorization review.

A missing collision still means only that supplied identifiers did not become
exactly equal under the explicitly supplied policies and active Unicode data.

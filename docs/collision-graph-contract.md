# Collision Graph Contract

This document specifies the Phase 2a collision-analysis API implemented by
`casefold_observatory.collision`. It covers in-memory `IdentifierRecord` values,
ordered `TransformPolicy` values, collision groups, witness forests, and global
components. It does not describe a corpus file format, byte-preserving ingestion,
a command-line interface, a receipt format, or a canonical graph serializer;
those layers are not implemented in this phase.

The algorithm identifier returned in every graph is
`stage-partition-witness-v1`.

## Records, policies, and ordinals

An `IdentifierRecord` represents one namespace occurrence. Its `record_id` is a
stable, caller-supplied label, while its `identifier` is the exact Unicode scalar
string being analyzed. Repeated raw identifiers are retained as separate
occurrences; the analysis never deduplicates them away.

Record IDs must be unique within an analysis and must match
`[a-z][a-z0-9._-]{0,63}`. The caller must pass records as an exact tuple. The
tuple's order is deliberately non-semantic: after validation, records are sorted
by `record_id`, and that order defines all canonical record ordinals in the
returned graph.

Policies must also be supplied as an exact tuple, but their order is semantic.
Each policy is evaluated independently from the raw identifier; the output of
one policy is never fed into the next policy. The tuple order determines policy
ordinals, the order of `policy_ids` and policy groups, generated group and
witness IDs, and the precedence used when selecting a global component's
spanning tree. Duplicate policy IDs are rejected.

The three ordinal fields have distinct meanings:

| Field | Meaning |
| --- | --- |
| `input_record_ordinal` | Zero-based position in the caller's record tuple. It is used only in failures discovered while validating that input tuple. |
| `canonical_record_ordinal` | Zero-based position after sorting valid records by `record_id`. Every record reference in a returned graph uses this order; policy-evaluation failures use it too. |
| `policy_ordinal` | Zero-based position in the caller's policy tuple. Policy order is never canonicalized or sorted. |

Consequently, permuting a valid record tuple does not change its graph, but it
can change the `input_record_ordinal` reported for invalid input. Permuting
policies changes their ordinals and other order-dependent graph metadata even
when the same set of policies is present.

## Collision classes

Identifier equality is always exact Python-string equality. Identifier hashes
are never used to decide whether two records collide.

### Exact duplicate groups

An `ExactDuplicateGroup` contains two or more occurrences whose raw identifiers
are exactly equal before any policy step. Canonically equivalent but
code-point-distinct strings are not exact duplicates. Every duplicate occurrence
is preserved in `member_record_ordinals`.

For a group with \(n\) occurrences, the implementation creates \(n-1\)
`EXACT_INPUT` witnesses: a star from the lowest canonical ordinal to every other
member. These witnesses have no policy, stage, or transform step. Exact
duplicates remain visible even if no policy produces a distinct-raw collision.

### Per-policy collision groups

A `PolicyCollisionGroup` is one final-output bucket under one policy that:

1. contains at least two record occurrences; and
2. contains at least two distinct raw identifier strings.

The second condition keeps raw duplicates and transformation-induced collisions
as separate classifications. A final bucket containing only repeated copies of
one raw string appears as an exact duplicate group, not as a policy collision
group. If duplicate occurrences and a distinct raw identifier share a final
bucket, the policy group's witness tree references the existing exact-duplicate
witnesses and adds only the transform witnesses needed to connect the remaining
parts.

`PolicyCollisionGroup.transformed` is the exact shared final string. Its
code-point and UTF-8 byte counts are recorded separately. The transformed value
is excluded from the dataclass representation but remains accessible and
sensitive.

### Isolated records

Canonical record ordinals with no exact-duplicate or per-policy collision edge
are returned in `isolated_record_ordinals`. Empty corpora, singleton corpora, and
corpora with no collisions are valid analyses. `colliding_record_count` is the
total record count minus the number of isolated ordinals.

## Why stage partitions only coarsen

Fix one policy and let \(f_j\) be its deterministic unary transform at stage
\(j\). Let \(v_{-1}(r)\) be record \(r\)'s raw identifier and

\[
v_j(r) = f_j(v_{j-1}(r)).
\]

At every stage, exact equality partitions the records into buckets. If
\(v_{j-1}(a) = v_{j-1}(b)\), applying the same deterministic function to both
sides gives \(v_j(a) = v_j(b)\). Records that are equal therefore cannot become
unequal at a later stage. Each stage partition is a coarsening of, or is equal
to, the preceding partition.

This property depends only on evaluating a fixed sequence of unary functions.
It does not assert that normalization or case mapping is injective; their
non-injective merges are exactly what the graph records.

## Minimal per-policy witness construction

Within each final collision bucket, a disjoint-set structure starts with one
component per occurrence. Exact-duplicate witnesses first join occurrences that
were equal at raw stage \(-1\).

The implementation then visits policy stages in order. For each exact-equality
bucket at the current stage, it finds the \(k\) distinct components entering
that bucket. If \(k > 1\), it sorts their canonical roots, selects the smallest
root as an anchor, and adds one edge from that anchor to each of the other
\(k-1\) roots. Every transform witness therefore connects values that were
different immediately before its recorded stage and exactly equal immediately
after it.

Adding fewer than \(k-1\) edges cannot connect \(k\) previously separate
components; adding exactly \(k-1\) is sufficient. Repeating this operation at
each first merge produces a connected, acyclic explanation with exactly
\(n-1\) witnesses for a final group of \(n\) occurrences. It is a minimal
witness tree, not the quadratic set of all colliding pairs.

### First-stage path property

Give an exact-input witness stage rank \(-1\), and give each transform witness
the zero-based stage index stored on that witness. For any two members of a
policy collision group, there is one path between them in the group's witness
tree. The maximum stage rank on that path equals the first stage at which those
two records are equal.

The reason is inductive: after processing stage \(j\), disjoint-set connectivity
is exactly equality under \(v_j\). A path whose maximum edge rank is at most
\(j\) exists precisely when both records are in the same stage-\(j\) component.
The smallest such \(j\) is their first equality stage. Raw duplicates have first
equality rank \(-1\).

This property applies inside one policy. Stage indices from different policies
have no shared chronology and must not be compared as if the policies formed
one pipeline.

## Cross-policy union components

The global graph takes the union of:

- all exact-input witness edges; and
- all per-policy transform witness edges.

Because each group's witnesses span that group's full equality relation, this
edge union has the same connected components as a union of complete group
cliques, without storing quadratic edge sets.

A `GlobalCollisionComponent` is therefore a **risk neighborhood by
reachability**, not an equivalence class under one policy. For example, one
policy may connect A to B and another may connect B to C even though no policy
makes A and C equal. Component membership alone must never be reported as
pairwise equality, visual confusability, or proof that one production system
would merge every member.

`policy_ordinals` lists the sorted unique policies contributing collision groups
to the component. It does not describe execution order across policies.
`policy_group_ids` and `duplicate_group_ids` retain the contributing relations.

The graph retains every emitted witness because each is part of a per-policy
explanation. A component's `witness_tree_ids` is a separate deterministic
minimal spanning subset. It is selected by a Kruskal-style pass over witnesses
ordered as follows:

1. exact-input witnesses;
2. transform witnesses by policy ordinal;
3. then by stage index, left canonical ordinal, and right canonical ordinal.

That ordering makes selection reproducible; it is not a claim that one policy
or stage happened before another policy.

## Deterministic ordering and generated IDs

For the same implementation, Unicode database version, valid record set, and
ordered policy tuple, the graph is deterministic and independent of Python hash
seed or the caller's record tuple order.

The implementation uses these canonical orders:

- records: ascending `record_id`;
- exact duplicate groups: ascending member-ordinal tuple;
- policy collision groups: policy tuple order, then ascending member-ordinal
  tuple within each policy;
- stored witnesses: exact-input first, then transform witnesses by policy
  ordinal, stage index, left ordinal, and right ordinal;
- global components: ascending member-ordinal tuple;
- isolated records and each group's members: ascending canonical ordinal.

Generated IDs expose that canonical structure:

| Object | Format |
| --- | --- |
| Exact duplicate group | `dg_0000` |
| Exact-input witness | `wi_x0000_0000` |
| Policy collision group | `pc_p00_0000` |
| Transform witness | `wi_p00_s00_0000_0001` |
| Global component | `gc_0000` |

These IDs are deterministic labels for one complete analysis, not durable
database keys. Adding, removing, or renaming a record, or reordering policies,
can renumber ordinals and generated IDs. Consumers that compare analyses must
not assume append stability.

`CollisionGraph.unicode_version` records the active runtime database version,
and every accepted policy must be bound to that same version.
`CollisionGraph.policy_ids` preserves the ordered SHA-256 identities of the
validated canonical policy documents. The algorithm label allows a later
algorithm change to be distinguished from `stage-partition-witness-v1`.

## Bounds and accounting

All limits are enforced before a `CollisionGraph` is returned:

| Limit | Current value | Accounting rule |
| --- | ---: | --- |
| `MAX_RECORD_ID_CHARS` | 64 | Characters in each canonical lowercase-ASCII record ID. |
| `MAX_ANALYSIS_RECORDS` | 2,048 | Record occurrences; zero records are allowed. |
| `MAX_ANALYSIS_POLICIES` | 8 | Policies per analysis; at least one is required. |
| `MAX_ANALYSIS_TOTAL_INPUT_UTF8_BYTES` | 524,288 | Sum of strict UTF-8 byte lengths of all raw identifiers. |
| `MAX_ANALYSIS_TRANSFORM_APPLICATIONS` | 65,536 | `record_count * sum(len(policy.steps) for policy in policies)`. |
| `MAX_ANALYSIS_TRANSFORMED_UTF8_BYTES` | 33,554,432 | Sum of every successful stage's output byte count across every record and every policy, not merely final outputs. |
| `MAX_ANALYSIS_POLICY_GROUPS` | 8,192 | Total `PolicyCollisionGroup` objects across all policies; exact duplicate groups are classified separately. |
| `MAX_ANALYSIS_WITNESSES` | 20,480 | Unique stored exact-input plus transform witness objects. Reusing an exact witness ID in a policy group does not allocate or count another witness. |
| `MAX_ANALYSIS_COMPONENTS` | 1,024 | Non-singleton global components. Isolated records are returned separately. |

The underlying policy engine also enforces these per-value limits:

| Limit | Current value |
| --- | ---: |
| Raw identifier code points | 1,024 |
| Raw identifier UTF-8 bytes | 2,048 |
| Steps in one policy | 1–8 |
| Output code points at each stage | 4,096 |
| Output UTF-8 bytes at each stage | 8,192 |
| Canonical Unicode-version field | 32 characters |

Raw identifiers must be non-empty exact `str` objects containing valid Unicode
scalar values. Records and policies are revalidated at the analysis boundary
even though their public constructors already validate them; forged, partially
initialized, subclassed, or otherwise malformed model objects are rejected.

## Atomic failure

Analysis is all-or-nothing. It validates every record and policy, checks the
aggregate transform-application budget, evaluates all required record-policy
pairs, constructs bounded output, and only then returns a graph. A policy
rejection, transformed-data limit, output limit, or any other validation failure
raises `CollisionAnalysisError`; no partial `CollisionGraph` is returned and no
record is silently skipped.

Stable collision error codes cover invalid or duplicate records and policies,
record and policy counts, total raw input size, transform-application and
transformed-data budgets, policy-rejected records, and output budgets. A policy
rejection reports the canonical record ordinal, policy ordinal, and the
underlying redacted `TransformErrorCode`. Library-owned error messages do not
echo record IDs, raw identifiers, or transformed identifiers.

Atomicity is an API-result guarantee, not transactional persistence: this phase
does not write a receipt, corpus, report, or graph to disk.

## Semantic corpus digest

`semantic_corpus_sha256` is computed over the validated records in canonical
record-ID order. Define:

```text
domain = b"casefold-observatory.semantic-corpus.v1\x00"
frame(payload) = uint64_big_endian(len(payload)) || payload

digest_input =
    domain
    || frame(record_id_0 ASCII) || frame(identifier_0 strict UTF-8)
    || frame(record_id_1 ASCII) || frame(identifier_1 strict UTF-8)
    || ...
```

The graph stores the lowercase hexadecimal SHA-256 digest of `digest_input`.
Eight-byte length prefixes make adjacent fields unambiguous. Each occurrence is
included with its unique record ID, so adding or removing a duplicate occurrence
changes the digest. Permuting the caller's valid record tuple does not.

This is a digest of the API's **semantic record set**, not a source-byte receipt.
In particular, it does not bind:

- original file bytes, encoding declarations, a byte-order mark, line endings,
  separators, quoting, headers, comments, filenames, or file metadata;
- the decoding or parsing process that created the Python strings;
- the ordered policies, algorithm output, implementation version, Unicode data,
  timestamps, freshness, or an execution environment.

Those values are exposed separately where applicable, but this phase does not
combine them into a signed or authenticated receipt. The digest provides no
provenance, authorization, authenticity, freshness, or proof that an analysis
was executed. It is not a MAC or a digital signature.

The digest is also not an anonymity mechanism. Low-entropy identifiers and
record IDs can be guessed and checked offline, and equality of complete corpus
digests can reveal reuse. It must not be published as a supposedly safe
substitute for a private namespace. Most importantly, this global digest is
never consulted when determining identifier equality or graph connectivity.

## Sensitivity and privacy boundary

`repr` omission is a display precaution, not a privacy boundary:

- `IdentifierRecord` retains its raw `identifier` and `record_id`;
- `PolicyCollisionGroup` retains the exact transformed string;
- `CollisionGraph` retains the ordered record IDs and semantic corpus digest.

Those fields remain available through normal Python attribute access,
introspection, debuggers, generic serializers, process memory, and caller-owned
references. Python strings are not reliably zeroizable. Traceback frame locals
and caller-supplied exception context can retain sensitive values even when the
library-owned exception payload is redacted.

Treat graphs, record objects, transformed outputs, digests, logs, screenshots,
and any derived visualization as sensitive whenever the namespace is private.
This phase provides neither confidential computation nor anonymous reporting.
`HazardHandling.PRESERVE` permits analysis of recognized controls and format
characters; it does not make those characters safe to print, log, embed in
markup, or render in a terminal.

## Unicode and security nonclaims

The graph reports exact equality under the explicitly selected Python
normalization and case-mapping pipeline. It is not a complete Unicode identifier
security profile or a verdict that an identifier is safe.

Specifically, this phase does not implement or claim:

- Unicode Technical Standard #39 confusable skeletons, restriction levels,
  mixed-script analysis, or whole-script confusable detection;
- IDNA domain-name mapping, validation, or contextual rules;
- visual, font-dependent, grapheme-level, or human-perceived confusability;
- locale-specific casing or application-specific namespace rules;
- complete `Default_Ignorable_Code_Point` detection.

The current hazard classifier recognizes the explicitly enumerated Unicode
`Bidi_Control` characters and general-category `Cc` and `Cf` characters. That
limited classifier must not be described as complete default-ignorable
coverage. Invisible or misleading content outside those categories can remain,
and preserved hazards remain raw untrusted text.

A missing edge means only that two records did not become exactly equal under
the policies supplied to this analysis. It does not establish that they are
visually distinct, secure for display, valid in a downstream protocol, or
non-colliding under another transformation policy or Unicode version.

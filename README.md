# Casefold Observatory

Casefold Observatory is a dependency-free Python laboratory for explaining how
explicit Unicode normalization and case policies merge identifiers. It is built
for security review of usernames, routing keys, dataset labels, package names,
and other namespaces where an unexpected equivalence can become an
authorization or integrity problem.

> **Release 0.5.0 and its offline report are implemented:** the
> dependency-free package accepts a strict, bounded UTF-8 JSON Lines corpus,
> computes the complete collision graph, emits canonical ASCII JSON receipt
> bytes, verifies them by exact replay, and renders a static ASCII-source HTML
> report only after verification. The installed POSIX CLI adds hardened
> descriptor-relative reads and durable mode-0600 no-clobber publication for
> both receipts and reports.
>
> The package never opens a browser or network connection. A separate
> evidence-only CI lane captures the real report in digest-pinned Chromium with
> JavaScript enabled and the container network disabled. The implemented byte,
> command, filesystem, HTML, CSP, and evidence boundaries are documented in the
> [portable receipt contract](docs/portable-receipt-contract.md).

It is not a generic case converter, a confusable-character detector, or a claim
that one Unicode policy is universally correct.

## Why this problem matters

Unicode-aware identifier handling is not equivalent to calling `lower()`.
Lowercasing and case folding differ; NFC, NFD, NFKC, and NFKD make different
trade-offs; and changing operation order can change the resulting equivalence
classes. Two services can therefore disagree about whether identifiers are
distinct even when both are "Unicode aware."

Casefold Observatory makes the policy explicit and records the first stage at
which previously separate values become exactly equal. Equality is always
decided from complete Python strings, never from hashes.

## Implemented capabilities

- ordered NFC, NFD, NFKC, NFKD, lower, upper, and case-fold operations;
- policies bound to the active runtime Unicode database version;
- exact duplicate occurrences preserved and classified separately;
- deterministic record ordinals derived from unique canonical record IDs, so
  record tuple order is non-semantic;
- per-policy collision groups with a minimal witness tree;
- cross-policy union components with a separate deterministic minimal tree;
- byte, code-point, stage-expansion, aggregate-work, transformed-data, group,
  witness, and component limits;
- atomic, redacted analysis failures with separate input, canonical-record, and
  policy ordinals;
- explicit reject or preserve handling for controls, format characters, and
  bidirectional controls;
- strict 4 MiB corpus-byte ingestion with bounded physical lines, line count,
  JSON depth, exact schemas, and redacted failures;
- canonical, 16 MiB-bounded ASCII JSON receipts with complete graph and policy
  projection, distinct exact-source and semantic digests, producer identity,
  active-Unicode binding, and replay verification;
- an installed `analyze`/`report`/`verify` CLI with exact grammar,
  descriptor-relative no-follow reads, single-link regular-file enforcement,
  mutation detection, mode-0600 no-clobber publication, and canonical redacted
  terminal channels;
- a verified, bounded offline HTML report with ASCII source and decoded DOM
  text, logical code-point metadata, escaped markup, no active content, and a
  hash-bound restrictive Content Security Policy;
- no runtime dependencies, implicit configuration, shell execution, browser
  launch, or network access.

The architecture and current graph semantics are illustrated with
source-controlled, reproducible assets:

![Implemented in-memory architecture](docs/visuals/architecture.svg)

![Minimal collision witness graph](docs/visuals/collision-witness-graph.svg)

![Policy collision landscape](docs/visuals/policy-collision-landscape.svg)

See the [visual evidence index](docs/visuals/README.md) for the exact public
fixtures, embedded hashes, and byte-for-byte regeneration commands. The formal
invariants, minimality argument, ordering rules, and limits are documented in
[the collision graph contract](docs/collision-graph-contract.md).

## Setup and verification

Casefold Observatory supports Python 3.11 and newer.

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e ".[dev]"
```

Run the same local gates used to review this phase:

```bash
.venv/bin/python -m ruff check .
.venv/bin/python -m ruff format --check .
.venv/bin/python -m mypy src tests scripts
.venv/bin/python -m coverage erase
.venv/bin/python -m coverage run --branch -m unittest discover -s tests
.venv/bin/python -m coverage report -m
.venv/bin/python scripts/render_collision_visuals.py --check
.venv/bin/python scripts/verify_distribution.py
```

The authoritative result is the output of these commands at the checked-out
revision. The project configuration enforces its current coverage threshold;
the README deliberately does not freeze a test count that changes as boundary
cases are added.

The installed POSIX workflow uses explicit files and never accepts `-`:

```bash
.venv/bin/casefold-observatory analyze \
  --source corpus.jsonl \
  --policy reject@case:lower,case:casefold \
  --receipt result.receipt.json

.venv/bin/casefold-observatory report \
  --source corpus.jsonl \
  --receipt result.receipt.json \
  --output result.report.html

.venv/bin/python -m casefold_observatory verify \
  --source corpus.jsonl \
  --receipt result.receipt.json
```

Both entry points emit only a bounded canonical ASCII summary on success.
Handled failures leave stdout empty, write one redacted JSON line to stderr,
and never echo a pathname, identifier, source line, or policy argument. Receipt
and report publication require an absent destination and produce durable
mode-0600 regular files. A successful report command emits:

```json
{"receipt_sha256":"<64 lowercase hexadecimal characters>","report_bytes":12345,"report_sha256":"<64 lowercase hexadecimal characters>","status":"reported"}
```

The committed visual bundle binds Unicode database 15.0.0 and is reproduced in
CI on Python 3.12. The installed package is also tested on Python 3.11, 3.13,
and 3.14. Those runtimes execute the full engine and static visual-contract
tests, while the two exact evidence-replay tests report an explicit skip when
their `unicodedata.unidata_version` differs. Policy IDs include that version by
design, so silently treating cross-version bytes as equivalent would be wrong.

## Verified CLI workflow and results

These are reviewed outputs from the installed `casefold-observatory` 0.5.0
wheel and the seven-record synthetic fixture—not speculative UI mockups. The
capture is pinned to CPython 3.12.3, Unicode database 15.0.0, Linux x86-64, and
the hash-locked Pillow 12.3.0 renderer.

### Setup and trust boundary

![Installed-wheel setup, capture, and verification workflow](docs/cli-evidence/cli-workflow.svg)

*Explanatory workflow generated from the evidence manifest. It distinguishes the
installed wheel under test from the renderer, the reviewed fixture from
temporary files, and byte-level replay from visual review.*

The evidence path builds a wheel from the selected Git tree, installs it into an
isolated environment, invokes both console and module entry points without a
shell, and captures bounded stdout/stderr. Receipt publication is checked as a
single-link mode-0600 runtime file before the synthetic receipt is committed as
a normal Git `100644` blob.

### Observed command channels

![Verified rasterized CLI transcript with success and failure channels](docs/cli-evidence/cli-transcript.png)

*Verified rasterized CLI transcript—not an operating-system screenshot. Every
visible line comes from captured argv, stdout, stderr, and exit status; wrapping
uses measured font pixels and is rejected if ink escapes the panel.*

![Four-step installed CLI demonstration](docs/cli-evidence/cli-demo.gif)

*Four deterministic full-canvas frames: analyze succeeds, replay verification
succeeds, no-clobber publication is rejected, and a changed source is rejected.
The final two frames show the redacted error channel and non-zero exit status.*

### Receipt-derived collision result

![Receipt-derived collision groups, witnesses, and components](docs/cli-evidence/cli-result.svg)

*Receipt-derived result for seven synthetic records under three explicit
policies: seven collision groups, nine minimal witnesses, and three cross-policy
components. The SVG reports stored receipt data; it does not recompute or
invent results.*

The review chain is intentionally inspectable:

- [synthetic JSONL fixture](docs/cli-evidence/fixtures/cli-demo.v1.jsonl);
- [canonical capture manifest](docs/cli-evidence/evidence/cli-evidence.v1.json);
- [real generated receipt](docs/cli-evidence/evidence/cli-demo.receipt.v1.json);
- [artifact-adoption provenance](docs/cli-evidence/evidence/cli-evidence-adoption.v1.json);
- [renderer and verifier](scripts/render_cli_evidence.py); and
- [visual evidence index and exact reproduction recipe](docs/cli-evidence/README.md).

CI performs two fresh captures, compares them to one another, compares all six
outputs byte-for-byte with the adopted files, and requires a clean checkout.

## Verified offline report

The report is generated by the installed wheel from the exact synthetic source
and a freshly created canonical receipt. It never interpolates raw non-ASCII
glyphs: each code point is shown by logical index, U+ value, Unicode name,
general category, bidi class, combining class, UTF-8 bytes, engine hazard, and
display flags. Markup-like identifiers remain inert escaped text.

![Offline report evidence architecture](docs/report-evidence/report-architecture.svg)

![Real desktop Chromium capture of the verified report](docs/report-evidence/report-desktop.png)

![Real Chromium mobile emulation of the verified report](docs/report-evidence/report-mobile.png)

![Real scrolling demonstration through the report](docs/report-evidence/report-scroll.gif)

The [report evidence index](docs/report-evidence/README.md) also includes the
real full-page capture, exact HTML, real receipt, source fixture, canonical
manifest, independent verifier, and adoption provenance. The browser lane uses
a platform-specific OCI manifest digest, a hash-locked Playwright 1.62.0 wheel,
Chromium 151.0.7922.34, offline contexts, one document request and zero
subresources. Two fresh captures must match byte-for-byte before a candidate can
be reviewed. The report remains sensitive source-derived output; a successful
replay is not authentication, freshness, or a safety verdict.

## Public API example

This example is executable against the current in-memory API. The input order is
intentionally shuffled; canonical record IDs determine the returned ordinals.

```python
from casefold_observatory import (
    TransformStep,
    analyze_collisions,
    create_identifier_record,
    create_policy,
)

records = (
    create_identifier_record("upper", "SS"),
    create_identifier_record("eszett", "ß"),
    create_identifier_record("lower", "ss"),
)
policy = create_policy((TransformStep.LOWER, TransformStep.CASEFOLD))
graph = analyze_collisions(records, (policy,))

print(graph.record_ids)
print(graph.policy_groups[0].member_record_ordinals)
for witness in graph.witnesses:
    print(
        witness.left_record_ordinal,
        witness.right_record_ordinal,
        witness.stage_index,
        witness.step.value if witness.step else None,
    )
print(graph.components[0].witness_tree_ids)
```

Output:

```text
('eszett', 'lower', 'upper')
(0, 1, 2)
1 2 0 case:lower
0 1 1 case:casefold
('wi_p00_s00_0001_0002', 'wi_p00_s01_0000_0001')
```

At stage 0, lowercasing connects `ss` and `SS`. At stage 1, case folding
connects `ß` to that existing component. The three-member group therefore needs
two witnesses, not all three pairwise edges.

## How the collision graph works

1. Records are validated, sorted by unique record ID, and assigned canonical
   ordinals. Every occurrence is retained, including exact duplicates.
2. Policies retain caller order. Each record is evaluated at every ordered
   transformation stage under fixed per-value and aggregate budgets.
3. Exact duplicate occurrences receive their own witnesses before policy work.
4. Within a final collision bucket, each stage partitions records by exact
   output. When a bucket joins `k` previously separate components, the analyzer
   emits exactly `k - 1` deterministic first-merge edges.
5. A policy group containing `n` records consequently has `n - 1` witnesses:
   enough to explain connectivity without producing a quadratic clique.
6. All exact and per-policy edges are unioned into global risk neighborhoods. A
   separate deterministic tree explains each neighborhood.

A global component is **not** an equivalence class under one policy. For
example, policy A can connect records 1 and 2 while policy B connects records 2
and 3. The union component contains all three, but records 1 and 3 need not be
equal under either policy. Stage indices are meaningful only inside their own
ordered policy; stages from different policies are not chronological.

## Determinism, evidence, and privacy

The graph carries the algorithm identifier, runtime Unicode version, policy
IDs, and a domain-separated, length-prefixed SHA-256 digest of the canonical
in-memory record model. A receipt separately carries SHA-256 and byte count for
the exact caller-supplied corpus bytes. Line endings, JSON whitespace, escape
spelling, and input order therefore change the source digest without changing
the semantic digest when they decode to the same canonical records. Neither
digest provides authentication, anonymity, or freshness.

The in-memory diagrams, installed-CLI bundle, and offline-report browser bundle
are regenerated from reviewed repository inputs and describe implemented behavior. The CLI transcript is
deliberately labeled as a verified rasterization rather than an operating-system
screenshot; the result SVG is derived from the real generated receipt; and the
workflow SVG is explanatory. The GIF and transcript preserve actual command
channels and exit statuses. No speculative mockup is used as proof.

`repr=False` keeps raw identifiers, record IDs, and transformed values out of
ordinary dataclass representations, but it is not a privacy boundary.
Attributes, `dataclasses.asdict`, serialization, debuggers, caller-owned
objects, and traceback frame locals can still expose them. Do not analyze or
commit private namespace exports without an appropriate data-handling plan.

## Current roadmap

1. **Bounded transformation policies** — implemented.
2. **In-memory collision graph and minimal witnesses** — implemented in phase
   2a. The checked-in documentation fixtures remain generator-owned evidence,
   not public receipts.
3. **Reproducible ingestion and receipts** — implemented in phase 2b as a pure
   in-memory bytes API with strict bounds, deterministic serialization, and
   bindings to exact input bytes, policies, producer version, and Unicode data.
4. **Command-line workflow** — implemented in phase 2c for POSIX systems with
   descriptor-relative stable reads, exact policy arguments, replay verification,
   redacted canonical channels, and durable no-clobber receipt publication.
5. **Verified CLI evidence** — implemented as a source-bound PNG transcript,
   four-frame GIF, receipt-derived result SVG, explanatory workflow SVG,
   canonical manifest, and independent adoption provenance.
6. **Verified offline report** — implemented in 0.5.0 as bounded static HTML
   with escaped logical code-point rendering, a hash-bound restrictive Content
   Security Policy, mode-0600 no-clobber CLI output, real desktop/mobile/full-page
   Chromium captures, and a real-scroll GIF under independent evidence review.

The historical Flask case-conversion prototype remains in Git history for
provenance. It is unsupported and must not be deployed: it used a development
server and a remote runtime asset.

## Security

Unicode input and generated analytical results are sensitive, untrusted data.
Read [SECURITY.md](SECURITY.md) before integrating the library or publishing an
artifact.

## License

[MIT](LICENSE)

# Security Policy

## Current support status

The current tree contains the phase-1 bounded transformation library. It does
not contain corpus ingestion, a command-line tool, a web application, or a
network service. The historical Flask prototype is unsupported and must not be
deployed.

The library rejects malformed scalar values, applies fixed byte/code-point and
stage bounds, binds policies to the active Unicode database version, and
redacts failures. The remaining controls below are requirements for later
corpus, report, CLI, and UI layers.

## Threat model

Casefold Observatory will treat every corpus, identifier, filename, command-line
argument, policy document, and generated report as untrusted input. The design
must account for:

- malformed UTF encodings and invalid scalar values;
- excessive bytes, lines, records, fields, code points, combining sequences, or
  transformation expansion intended to exhaust memory, CPU, or storage;
- bidirectional controls, terminal control sequences, zero-width and
  default-ignorable characters, unusual whitespace, and other content that can
  hide or reorder what a reviewer sees;
- differences between normalization forms, case-folding order, Unicode database
  versions, locales, and downstream identifier policies;
- formula injection or markup/script injection when results are exported to
  terminals, CSV files, HTML, logs, or an offline UI;
- path traversal, unsafe output replacement, symlink races, and accidental
  overwrite of an input corpus;
- privacy leaks through committed corpora, generated artifacts, screenshots,
  recordings, logs, or content-bound receipts.

## Required controls for future code

Implementations must fail closed at documented byte, line, record, field,
code-point, and expansion bounds. Streaming ingestion must not imply unbounded
aggregation. Policy choices and Unicode data versions must be explicit and bound
to deterministic receipts.

The phase-1 `PRESERVE` hazard mode is an explicit analytical choice. It returns
raw transformed text and redacted hazard locations; it does not make controls
safe to print. `TransformResult` values from private namespaces remain
sensitive. The library-owned rejection payload does not echo the identifier, and
invalid-scalar validation does not create a `UnicodeEncodeError` context that
contains it. Caller-supplied causes or ambient exception context, caller objects,
and Python traceback frame locals remain outside that boundary and can retain or
display the raw value. Python strings cannot be reliably zeroized, and this
library does not claim memory-erasure guarantees.

Controls, bidirectional marks, invisible code points, and ambiguous whitespace
must be rendered visibly in human-facing output. Raw untrusted text must never be
interpreted as terminal control data or unescaped HTML, SVG, CSV formulas, or log
markup. Any future browser interface must work offline, use no remote runtime
assets, and enforce a restrictive Content Security Policy.

Filesystem output must use safe, atomic replacement with explicit handling for
links and special files. Network access must not be required to analyze a corpus
or reproduce a published result.

Private corpora, production usernames, routing tables, access tokens, credentials,
and personal data must not be committed. Public examples and visual evidence must
use reviewed synthetic or openly licensed inputs and must include reproducible
generation instructions.

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting for this repository when it
is available. Do not open a public issue containing an exploit, private corpus,
credential, or personal data.

Include the affected revision, the policy and Unicode version involved, a minimal
reproduction using non-sensitive data, the observed impact, and any suggested
mitigation. Reports will be acknowledged and assessed before public disclosure.

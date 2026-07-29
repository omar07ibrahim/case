# Security Policy

## Current support status

The current tree is a phase-0 safety reset and does not contain a runnable
application. The historical Flask prototype is unsupported and must not be
deployed.

Security guarantees described below are requirements for future implementations,
not claims about functionality that already exists.

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

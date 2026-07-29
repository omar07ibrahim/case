# Casefold Observatory

Casefold Observatory is being rebuilt as an offline, reproducible laboratory for
finding Unicode identifier collisions. Its intended use cases are namespaces in
which visually or semantically related strings must remain distinct: usernames,
routing keys, dataset labels, and similar identifiers.
It is not a generic text case converter.

> **Phase 0 — safety reset.** There is no runnable collision engine or user
> interface in the current tree. This phase removes the old case-conversion web
> demo and records the security and reproducibility constraints for the rebuild.

## Why this problem matters

Unicode-aware identifier handling is not equivalent to calling `lower()`.
Different policies can produce different equivalence classes:

- lowercasing and Unicode case folding do not have the same semantics;
- NFC, NFD, NFKC, and NFKD normalization make different trade-offs;
- applying normalization before or after case folding can change the result;
- compatibility characters, combining marks, default-ignorable characters,
  bidirectional controls, and confusable glyphs need explicit policy decisions.

A system that silently chooses one transformation can merge identifiers that an
operator expected to remain separate. It can also miss collisions that occur in
another component using a different policy. The planned laboratory will make
those choices visible and produce evidence that can be reproduced independently.

## Current state

Phase 0 deliberately contains documentation only:

- the legacy Flask development server and remote Bootstrap dependency have been
  removed from the current tree;
- the threat model and disclosure process are documented in
  [SECURITY.md](SECURITY.md);
- the repository has an explicit license and ignores local development output.

The historical case-conversion prototype remains available in Git history for
provenance. It is not supported and must not be deployed: it ran Flask's debug
development server, had no pinned dependency set, and loaded a remote runtime
asset.

## Technical roadmap

Each phase will be implemented and tested before its results are presented as
working features.

1. **Bounded policy engine** — explicit normalization and case-folding order,
   Unicode-version metadata, configurable handling of controls and ignorables,
   and strict byte, line, record, field, and expansion limits.
2. **Collision analysis** — collision graphs, connected components, and minimal
   witness sets that explain which transformation caused each merge.
3. **Reproducible ingestion** — streaming input, deterministic output, and
   content-bound receipts covering the input digest, policy, implementation
   version, and Unicode data version.
4. **Offline interface** — a local-only UI with a restrictive Content Security
   Policy, no remote runtime assets, escaped output, and explicit rendering of
   controls, bidirectional marks, and other invisible code points.
5. **Evidence and demonstrations** — real screenshots of the implemented UI and
   CLI, source-derived graphs and outputs, and a reproducible GIF or short video
   when interaction exists.

Visual evidence will be added only after the corresponding code can generate it.
Every image or recording will document its generation command and input, avoid
private data, and be refreshed when behavior changes. This repository does not
use speculative mockups as proof of functionality.

## Intended verification standard

Future code is expected to ship with deterministic fixtures, property and
boundary tests, static analysis, package checks, and commands that regenerate
published examples. A result should be attributable to exact input bytes and an
explicit policy rather than to ambient locale, network state, or an unspecified
Unicode database.

## Security

Unicode input is untrusted, including input used only for reports. Do not commit
private identifier corpora or production namespace exports. See
[SECURITY.md](SECURITY.md) for the planned trust boundaries and for responsible
reporting instructions.

## License

[MIT](LICENSE)

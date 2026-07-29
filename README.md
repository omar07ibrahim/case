# Casefold Observatory

Casefold Observatory is being rebuilt as an offline, reproducible laboratory for
finding Unicode identifier collisions. Its intended use cases are namespaces in
which visually or semantically related strings must remain distinct: usernames,
routing keys, dataset labels, and similar identifiers.
It is not a generic text case converter.

> **Phase 1 — bounded policy engine.** The current tree ships a typed,
> dependency-free Python library for evaluating explicit Unicode normalization
> and case-mapping pipelines. Corpus ingestion, collision graphs, a CLI, and a
> user interface are not implemented yet.

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

The first implementation layer now provides:

- the legacy Flask development server and remote Bootstrap dependency have been
  removed from the current tree;
- the threat model and disclosure process are documented in
  [SECURITY.md](SECURITY.md);
- ordered NFC, NFD, NFKC, NFKD, lower, upper, and case-fold operations;
- a canonical policy document bound to the runtime Unicode database version;
- independent byte, code-point, stage-expansion, and policy-length limits;
- fail-closed or explicit-preserve handling for controls, format characters,
  and bidirectional controls;
- redacted failures and hazard metadata that do not echo rejected identifiers;
- a typed installed package with no runtime dependencies.

The historical case-conversion prototype remains available in Git history for
provenance. It is not supported and must not be deployed: it ran Flask's debug
development server, had no pinned dependency set, and loaded a remote runtime
asset.

## Technical roadmap

Each phase will be implemented and tested before its results are presented as
working features.

1. **Bounded policy engine** — explicit normalization and case-folding order,
   Unicode-version metadata, configurable rejection or preservation of control,
   format, and bidirectional-control hazards, and strict byte, code-point, stage,
   and expansion limits (**implemented for individual identifiers**). Complete
   Unicode `Default_Ignorable_Code_Point` coverage remains future work.
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

## Quick check

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e .
.venv/bin/python -m unittest discover -s tests -v
```

The operation order is part of the policy:

```python
from casefold_observatory import TransformStep, apply_policy, create_policy

policy = create_policy((TransformStep.NFKC, TransformStep.CASEFOLD))
result = apply_policy("Straße", policy)

print(result.transformed)  # strasse
print(result.unicode_version)
print(result.policy_id)
```

`TransformResult` retains the transformed identifier in memory. Its `repr`
omits that value. The library's `IdentifierTransformError` payload does not echo
rejected values, and invalid-scalar validation does not create a chained
`UnicodeEncodeError` containing them. Callers can still attach ambient exception
context or causes, and caller objects, result objects, and Python traceback frame
locals can retain the raw string. This phase does not provide memory zeroization
or anonymous reports. Treat results derived from private namespaces as
sensitive.

Canonical serialization accepts only the active runtime's three-component
Unicode database version. A policy from another runtime is rejected instead of
being relabeled with semantics this process cannot execute.

## Security

Unicode input is untrusted, including input used only for reports. Do not commit
private identifier corpora or production namespace exports. See
[SECURITY.md](SECURITY.md) for the planned trust boundaries and for responsible
reporting instructions.

## License

[MIT](LICENSE)

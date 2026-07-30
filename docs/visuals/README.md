# Collision visual evidence

These deterministic artifacts visualize the current public
`casefold_observatory.analyze_collisions` API. They are generated from reviewed,
bounded synthetic Unicode inputs—not screenshots, UI mockups, or hand-entered
results.

| Artifact | Executed fixture | What the visual proves |
| --- | --- | --- |
| [`collision-witness-graph.svg`](collision-witness-graph.svg) | `SS`, `ss`, `ß` under `lower → casefold` | The API reports the `ss`/`SS` first merge at stage 0 and the `ß` join at stage 1; two witnesses are the minimum tree for three records. |
| [`policy-collision-landscape.svg`](policy-collision-landscape.svg) | 12 synthetic inputs including `1`/`①`/`１`, `K`/`K`, `SS`/`ss`/`ß`, and composed/decomposed `é` | The matrix is rendered from the API's exact final-equality policy groups across four ordered policies. |
| [`architecture.svg`](architecture.svg) | Public bounds and the implemented graph workflow | The trust boundary, canonical ordering, stage partitions, minimum policy forests, and separate global union tree are shown without claiming unimplemented surfaces. |
| [`evidence/collision-visuals.v1.json`](evidence/collision-visuals.v1.json) | Canonical evidence for both fixtures plus architecture constants | Every record, stage output, policy ID, group, witness, component, digest, and bound used by the SVGs is reviewable as UTF-8 JSON. |

## Reproduce

Run from the repository root with the project environment active:

```console
python scripts/render_collision_visuals.py
python scripts/render_collision_visuals.py --check
```

`--check` rebuilds all five artifacts in memory, checks the exact file set,
compares every byte and mode, and rejects symlink or special-file outputs. The
renderer uses only Python's standard library and the local package; it performs
no network requests and loads no remote fonts, scripts, images, or styles.

## Evidence relationship

Each SVG embeds a canonical `data_sha256` in its `<metadata>` element. It is the
SHA-256 of the matching compact, sorted JSON subsection:

- `first_merge` → `collision-witness-graph.svg`
- `landscape` → `policy-collision-landscape.svg`
- `architecture` → `architecture.svg`

The committed evidence records:

- implementation revision: `8c55335d6db549fbc55319addba33f3a2bda0e96`
- implementation tree SHA-256: `c6560d331aac6ba7ca9182207bf4d6e65c8e530ff6c384352fc7aff8a435a599`
- generator SHA-256: `bf974c9a132deb666ca17caab012936ccb9cdf6f094b0797ccfca0f3609c322a`
- algorithm: `stage-partition-witness-v1`
- Unicode database: `15.0.0`
- first-merge corpus label: `3ccca0815c2deeee3e4d2a61283ab17ca9debb9f4f3f7dd7f501b0c03664aa46`
- landscape corpus label: `4c3f94071f8acc5b69aa949a36db22697d84024fa5b01f53a099525c0c47684b`

The revision is the newest commit touching the analyzed implementation paths,
not repository `HEAD`; therefore a later visuals-only commit does not make the
evidence stale. The tree and generator hashes still detect uncommitted or
post-revision byte changes.

## Review notes and nonclaims

- Inputs are public synthetic Unicode examples. No credentials, secrets,
  personal data, local absolute paths, timestamps, or machine identifiers are
  captured.
- Equality is determined by exact strings. Digests are integrity labels; they
  do not provide anonymity, authentication, freshness, or proof of original
  source bytes.
- A global component is a cross-policy risk neighborhood, not a claim that all
  members are equal under one policy.
- Combining marks use dotted-circle display notation in labels so decomposed
  forms remain visibly distinct. The canonical JSON retains the exact strings.
- The SVGs are explanatory renderings of current API results, not an interactive
  CLI, application screenshot, or security boundary.

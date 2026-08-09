# CLI Evidence

This directory contains the reviewed six-file evidence bundle for the installed
`casefold-observatory` 0.4.0 workflow. The media is generated from real command
channels and a real canonical receipt produced from the public seven-record
fixture. It is not a UI mockup, benchmark, OS terminal screenshot, or claim about
identifiers outside that fixture.

## Gallery

### Installed-wheel setup and verification path

![Installed-wheel setup, capture, and verification workflow](cli-workflow.svg)

This explanatory SVG identifies the isolated wheel under test, the fixed
renderer, temporary runtime files, safe file checks, byte comparison, and human
visual-review boundary.

### Captured terminal channels

![Verified rasterized CLI transcript with success and failure channels](cli-transcript.png)

This is a verified rasterization—not an operating-system screenshot. The panels
preserve captured argv, stdout, stderr, and exit status for successful analysis,
successful replay, no-clobber rejection, and changed-source rejection.

![Four-step installed CLI demonstration](cli-demo.gif)

The GIF presents the same four observed phases as deterministic full-canvas
frames. It loops for documentation convenience; the command data is taken from
the manifest rather than simulated by an animation.

### Receipt-derived result

![Receipt-derived collision groups, witnesses, and components](cli-result.svg)

This SVG projects the stored receipt: 7 records, 3 explicit policies, 7
per-policy collision groups, 9 minimal witnesses, and 3 cross-policy components.
It does not rerun the analyzer or infer facts absent from the receipt.

## Provenance

The capture and adoption chain is immutable and machine-readable:

| Field | Reviewed identity |
| --- | --- |
| Capture source commit | `03c6f16c03e3d3e1a5230afe58f478da12228d4a` |
| Capture source tree | `78f789909de47ab5b8121f5acc510d758c241492` |
| Workflow run / attempt | [`31293264288` / `1`](https://github.com/omar07ibrahim/case/actions/runs/31293264288) |
| Workflow job | [`93194112959`](https://github.com/omar07ibrahim/case/actions/runs/31293264288/job/93194112959) |
| Hosted artifact | `case-cli-evidence-candidate-31293264288-1`, ID `9032120081` |
| Artifact archive | `188273` bytes, SHA-256 `2d9f3f8aee1f95868bfb656d17468b14854a75be606aa8a45df246ec3e04d4d4` |
| Adoption commit | `fca957b24f45031f651d918636294874b18e3251` |
| Canonical adoption record | [`evidence/cli-evidence-adoption.v1.json`](evidence/cli-evidence-adoption.v1.json) |
| Capture manifest | [`evidence/cli-evidence.v1.json`](evidence/cli-evidence.v1.json) |
| Synthetic fixture | [`fixtures/cli-demo.v1.jsonl`](fixtures/cli-demo.v1.jsonl), SHA-256 `a77c90ed5e767a4e0a8029cad14ed347354a3b939b62ad75c0da091b522a259f` |

The hosted archive was independently checked for exact inventory, regular
`100644` entry modes, manifest and receipt consistency, source bindings, media
structure, privacy markers, and visual completeness before its bytes were
adopted. The durable adoption record carries that review outcome and archive
identity; availability of the temporary hosted artifact is not required to
verify the committed bundle.

The six adopted file identities are:

| File | Bytes | SHA-256 | Role |
| --- | ---: | --- | --- |
| [`cli-demo.gif`](cli-demo.gif) | 45,778 | `0034dccbefc08dfde3a3884162d44566664fbe80e0fc56bfef7dca9677543aea` | Four captured phases |
| [`cli-result.svg`](cli-result.svg) | 6,582 | `dba4fcad5da2303e3ccbfa6ea53709ad4d4e28201cdf5dde110bb64712c71ed2` | Receipt-derived result |
| [`cli-transcript.png`](cli-transcript.png) | 109,515 | `e76316607fe1813661e799178645818bddfe73419ceaa179b0684be49ea9ed89` | Rasterized command channels |
| [`cli-workflow.svg`](cli-workflow.svg) | 9,610 | `19dba92c23617b56ac4bfc46dc9995cf909be52cd7e7ef62d61021531fc84f47` | Explanatory workflow |
| [`evidence/cli-demo.receipt.v1.json`](evidence/cli-demo.receipt.v1.json) | 6,905 | `f27a1e8abecfea76d9ef054ceea0bf3d38d07d246d21653ade01e65846a58ccb` | Real canonical receipt |
| [`evidence/cli-evidence.v1.json`](evidence/cli-evidence.v1.json) | 8,849 | `2ca3e07785a591b059f25d9b97207fe481eef5f9f77322e27f4faa678d822389` | Capture manifest |

This README is an index and is deliberately not a seventh artifact member.

## Reproduce and verify

Exact reproduction requires Linux x86-64, CPython 3.12.3 with Unicode database
15.0.0, and the repository revision being checked. Pillow is a hash-locked
documentation tool, not a package runtime dependency.

From the repository root:

```bash
test "$(python3.12 -c 'import platform; print(platform.python_version())')" = "3.12.3"
test "$(python3.12 -c 'import unicodedata; print(unicodedata.unidata_version)')" = "15.0.0"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
python3.12 -m venv "$work/renderer-venv"
"$work/renderer-venv/bin/python" -m pip install \
  --require-hashes \
  -r requirements/cli-visuals.txt
"$work/renderer-venv/bin/python" -m pip install \
  build==1.5.0 \
  packaging==26.3 \
  pyproject-hooks==1.2.0 \
  setuptools==83.0.0

mkdir -p "$work/source" "$work/wheel"
git archive HEAD | tar -x -C "$work/source"
(
  cd "$work/source"
  SOURCE_DATE_EPOCH=315532800 \
    "$work/renderer-venv/bin/python" -m build \
      --wheel \
      --no-isolation \
      --outdir "$work/wheel"
)

wheels=("$work"/wheel/*.whl)
test "${#wheels[@]}" -eq 1
python3.12 -m venv "$work/cli-venv"
"$work/cli-venv/bin/python" -m pip install \
  --no-index \
  --no-deps \
  "${wheels[0]}"

"$work/renderer-venv/bin/python" scripts/render_cli_evidence.py check \
  --venv-bin "$work/cli-venv/bin" \
  --wheel "${wheels[0]}"
git diff --exit-code
test -z "$(git status --porcelain --untracked-files=all)"
```

`check` creates two fresh temporary captures, audits both, requires them to be
byte-identical, then audits and compares the six committed files. It does not
overwrite the adopted evidence. The pinned CI implementation is in
[`.github/workflows/ci.yml`](../../.github/workflows/ci.yml).

## Update discipline

Do not hand-edit, optimize, re-encode, or substitute any of the six outputs. If a
bound runtime source, fixture, renderer, dependency, or capture environment
changes, create a new candidate; compare two fresh captures; review command
channels, receipt semantics, media structure, accessibility, privacy, and
clipping; then adopt the reviewed bytes with a new canonical provenance record.
Captions and hashes must change in the same documentation phase.

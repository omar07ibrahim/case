# Verified offline-report evidence

This directory is the review surface for Casefold Observatory 0.5.0. Every
screenshot below comes from the real static HTML emitted by the installed wheel
for the checked-in synthetic fixture. These are not mockups.

## What the captures prove

![Evidence architecture](report-architecture.svg)

*The source-controlled architecture diagram separates exact input capture,
installed-wheel verification and rendering, mode-0600 no-clobber publication,
offline Chromium capture, independent byte verification, and human adoption.*

![Desktop Chromium capture](report-desktop.png)

*Real 1440 x 1000 Chromium viewport at device-pixel ratio 1. The visible
overview, policy cards, and code-point cards come from the generated report.*

![Chromium mobile emulation](report-mobile.png)

*Real 390 x 844 Chromium mobile emulation at device-pixel ratio 1. This is
responsive-layout evidence, not a physical-device screenshot.*

![Full-page Chromium capture](report-full-page.png)

*Real Chromium full-page capture. Its pixel height must equal the browser's
measured document scroll height and remain inside the reviewed bound.*

![Real scrolling demonstration](report-scroll.gif)

*Four real 1440 x 1000 viewport screenshots taken after browser scrollTo calls.
The manifest records every requested and observed scroll position plus the
source PNG digest of every frame; this GIF is not a crop or pan of the full-page
PNG.*

## Exact workflow

The public fixture is
[report-demo.v1.jsonl](fixtures/report-demo.v1.jsonl). It contains twelve
synthetic identifiers covering case-fold and normalization collisions, composed
and decomposed text, markup-like ASCII, a bidirectional control, and a
zero-width joiner. No production or personal data is used.

The installed workflow is:

```console
casefold-observatory analyze \
  --source report-demo.v1.jsonl \
  --policy preserve@case:lower,case:casefold \
  --policy preserve@normalize:nfc,case:casefold \
  --policy preserve@normalize:nfkc,case:casefold \
  --receipt report-demo.receipt.json

casefold-observatory report \
  --source report-demo.v1.jsonl \
  --receipt report-demo.receipt.json \
  --output report-demo.html

python -m casefold_observatory verify \
  --source report-demo.v1.jsonl \
  --receipt report-demo.receipt.json
```

The generated receipt and HTML are regular single-link mode-0600 files at
runtime. Git stores the reviewed synthetic copies as ordinary 100644 blobs, so a
checkout does not preserve the runtime confidentiality mode.

## Reproduction and isolation

The dedicated workflow builds the wheel from a clean git archive and downloads
only hash-locked Python wheels. It selects Linux amd64 explicitly and pulls the
Playwright image by immutable platform-manifest digest. Each of two captures
runs in a fresh non-root, read-only container with no network, no added Linux
capabilities, no-new-privileges, a private temporary filesystem, and no GitHub
token or Docker socket.

JavaScript remains enabled. GitHub-hosted Docker does not expose a usable
Chromium user namespace under these restrictions, so the Chromium process
sandbox is explicitly disabled and recorded as such. The outer non-root,
no-network, read-only, capability-free container is the capture boundary; the
workflow does not add `SYS_ADMIN` or broaden privileges to make an inner
sandbox appear enabled. Only the trusted, locally generated static report is
opened.

The browser must observe one local document request and zero subresource
requests. The capture fails on a popup, page error, clean
load console error, URL-bearing attribute, active element, non-ASCII decoded DOM
text, horizontal document overflow, missing stylesheet, or unexpected layout
height. Negative probes then append an inline script and a modified style and
must observe both blocked by the report's Content Security Policy.

Run the same renderer and the independent verifier inside the pinned image:

```console
python scripts/render_report_evidence.py render --help
python scripts/verify_report_evidence.py verify --help
```

The two candidates must match byte-for-byte. A drift run uploads exactly the
eight bounded bundle files and fails; it never edits the checkout. Artifact
upload is not adoption. The candidate is committed only after its inventory,
hashes, HTML/CSP, receipt, images, GIF frames, SVG, provenance, and privacy
boundary have been independently checked and the pixels have been viewed.

## Machine-readable evidence

The eight-file bundle is:

1. [canonical manifest](evidence/report-evidence.v1.json);
2. [real generated receipt](evidence/report-demo.receipt.v1.json);
3. [exact offline HTML](evidence/report-demo.v1.html);
4. [desktop viewport](report-desktop.png);
5. [Chromium mobile emulation](report-mobile.png);
6. [full-page capture](report-full-page.png);
7. [real-scroll GIF](report-scroll.gif); and
8. [evidence architecture](report-architecture.svg).

The separate adoption record at
[evidence/report-evidence-adoption.v1.json](evidence/report-evidence-adoption.v1.json)
binds the reviewed hosted archive to the exact committed bytes. It is not
generator-owned and is intentionally outside the eight-file bundle.

## Provenance

The capture and adoption chain is immutable and machine-readable:

| Field | Reviewed identity |
| --- | --- |
| Capture source commit | `cc4e5fc4403f4d7dcbe20df83dc9545fc22808d1` |
| Capture source tree | `0b371628fa35fee844834aad329ffefcca77fc04` |
| Workflow run / attempt | [`31332062366` / `1`](https://github.com/omar07ibrahim/case/actions/runs/31332062366) |
| Workflow job | [`93291774425`](https://github.com/omar07ibrahim/case/actions/runs/31332062366/job/93291774425) |
| Hosted artifact | `generated-report-evidence-31332062366-1`, ID `9043217069` |
| Artifact archive | `1503825` bytes, SHA-256 `28f90cf9ea5f093ae58db70c8468de83806ad3386a5282c19ee243a0823982a5` |
| Adoption commit | `3ce13bc5c91ed89f0e466f434a17a56229b62293` |
| Canonical adoption record | [`evidence/report-evidence-adoption.v1.json`](evidence/report-evidence-adoption.v1.json) |
| Capture manifest | [`evidence/report-evidence.v1.json`](evidence/report-evidence.v1.json) |
| Synthetic fixture | [`fixtures/report-demo.v1.jsonl`](fixtures/report-demo.v1.jsonl), SHA-256 `58c4b868820471fcb67a42351d7bddbfbcc66bfd4b2165d4e9868390787991cf` |

The hosted archive was independently downloaded and checked for exact
inventory, regular `100644` entry modes, source bindings, receipt replay,
HTML and CSP integrity, browser assertions, media structure, privacy markers,
and visual completeness. The eight reviewed files were committed without
rerendering. The durable adoption record preserves that review even after the
temporary hosted artifact expires.

The eight adopted file identities are:

| File | Bytes | SHA-256 | Role |
| --- | ---: | --- | --- |
| [`evidence/report-demo.receipt.v1.json`](evidence/report-demo.receipt.v1.json) | 8,537 | `6ac6363a609cfa64c8bca7bdace514f09beab5f60927a880b220ad258f70d06e` | Replayed canonical receipt |
| [`evidence/report-demo.v1.html`](evidence/report-demo.v1.html) | 33,092 | `52e41982b2defd6f8eae643cabfc0bfd96f44fb47c0172e36aba5d864cc93d4c` | Exact offline report |
| [`evidence/report-evidence.v1.json`](evidence/report-evidence.v1.json) | 17,812 | `2059557f5400e260e09fab8ac204204b69791f4e4c878cecd913d889ba270379` | Capture manifest |
| [`report-architecture.svg`](report-architecture.svg) | 3,486 | `56ec83288a91d68a423f465ed089cc17a85a2d87b8ad045865803d1f146fac54` | Evidence architecture |
| [`report-desktop.png`](report-desktop.png) | 136,923 | `144220805f9137f9ecef4a809ed3e2165f4829efc6c65667f699e021d4765045` | Desktop viewport |
| [`report-full-page.png`](report-full-page.png) | 1,020,472 | `893a85813c07b89b81acaef2a633f49985374bea0f14384645c9a20d359b02b5` | Full document |
| [`report-mobile.png`](report-mobile.png) | 71,185 | `12a5d1a03d302d7429e8d94ba0a5e87f33f0ea61569e77506ca5bee1f7e2788c` | Mobile emulation |
| [`report-scroll.gif`](report-scroll.gif) | 210,842 | `daf9abff4452a4c3f5b9278c360d2c2b4766d19121fe8a5e1ac2d72625005204` | Four real scroll positions |

The README and adoption record are outside the generator-owned eight-file
bundle.

The manifest records the source revision and tree, per-source bindings, wheel
identity, installed runtime file identities, exact command channels, runtime
output modes, OCI image digest, Chromium version and executable hash,
Playwright/Pillow/Python/Unicode versions, font file identities, viewport and
scroll measurements, request counts, CSP probes, and every artifact digest.
It contains no timestamps, absolute host paths, file URLs, usernames, machine
IDs, credentials, or source-derived production data.

A meta CSP protects a report opened as a local file by allowing only the
hash-bound inline stylesheet and denying scripts, images, fonts, media,
connections, workers, frames, objects, forms, and manifests. If the HTML is
served over HTTP, clickjacking protection still requires an appropriate
Content-Security-Policy response header; a meta policy cannot provide
frame-ancestors.

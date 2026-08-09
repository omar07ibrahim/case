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

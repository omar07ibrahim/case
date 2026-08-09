# Third-party notices

This repository's Python package has no runtime dependencies. The tooling below
is used only by reproducible visual-evidence jobs; it is not declared by
`casefold-observatory`, included in its wheel, or loaded by its CLI. Browser
capture runs only in the dedicated offline CI lane.

## Pillow 12.3.0

- Purpose: deterministic PNG/GIF encoding for reviewed CLI and real-scroll report evidence.
- Project: https://python-pillow.github.io/
- Source: https://github.com/python-pillow/Pillow/tree/bb1d8e8ab8d29048624d96e3ee53cecf7c13d13d
  (the source commit attested for the 12.3.0 PyPI release).
- Canonical wheel:
  `pillow-12.3.0-cp312-cp312-manylinux_2_27_x86_64.manylinux_2_28_x86_64.whl`
- Wheel SHA-256:
  `78cb2c6865a35ab8ff8b75fd122f6033b92a62c82801110e48ddd6c936a45d91`
- Wheel source: https://files.pythonhosted.org/packages/84/21/a35af28dcc61f37ed850a2d64c65c701321dfbf25085e469d5559360cbbf/pillow-12.3.0-cp312-cp312-manylinux_2_27_x86_64.manylinux_2_28_x86_64.whl
- License: Pillow's MIT-CMU license, preserved upstream at
  https://github.com/python-pillow/Pillow/blob/12.3.0/LICENSE

The hash-locked installation input is
[`requirements/cli-visuals.txt`](requirements/cli-visuals.txt). It requires a
binary distribution and rejects a source fallback. The evidence manifest records
the exact canonical wheel filename and SHA-256. Published repository artifacts
contain only the encoded images, not the Pillow wheel or Pillow source.

## Embedded Aileron Regular subset used by Pillow

`PIL.ImageFont.load_default(size=...)` in Pillow 12.3.0 loads Pillow's embedded,
limited-character-set copy of Aileron Regular when FreeType support is
available. The CLI evidence renderer uses that API only for ASCII transcript
text and fails unless `getname()` resolves exactly to `("Aileron",
"Regular")`.

- Pillow API provenance:
  https://pillow.readthedocs.io/en/stable/reference/ImageFont.html
- Typeface upstream: https://dotcolon.net/fonts/aileron/
- Designer: Sora Sagano / dot colon.
- Upstream rights statement: “No Rights Reserved.”

The repository does not silently bundle an Aileron font file. The committed PNG
and GIF contain rasterized glyph pixels produced by the hash-locked Pillow
wheel. The SVGs use a generic local monospace fallback list and embed no font.


## Playwright for Python 1.62.0

- Purpose: drive the real Chromium report capture and CSP/layout probes.
- Project: https://playwright.dev/python/
- Source: https://github.com/microsoft/playwright-python/tree/v1.62.0
- License: Apache License 2.0.
- Canonical Linux x86-64 wheel:
  `playwright-1.62.0-py3-none-manylinux1_x86_64.whl`
- Wheel SHA-256:
  `ba33bae6a13b3d9d354c751cb618af357d20fe1d57767cbcce52079bbef17ad3`.

The hash-locked evidence environment also installs Playwright's exact
dependencies: pyee 13.0.0 (MIT), greenlet 3.2.4 (MIT), and
typing-extensions 4.15.0 (Python Software Foundation license). Every accepted
wheel digest is listed in
[`requirements/report-browser.txt`](requirements/report-browser.txt).

## Chromium 151.0.7922.34 and Playwright image

- Purpose: render the generated local HTML into real desktop,
  mobile-emulation, full-page, and scroll evidence.
- Browser project and license information: https://www.chromium.org/Home/
- Playwright image documentation:
  https://playwright.dev/python/docs/docker
- Image tag used for provenance: `v1.62.0-noble`.
- Multi-architecture index digest:
  `sha256:aa81288e738725378becba5b3e06cb0f3a7f012a610e87e8d767a090ea3f740d`.
- Selected Linux amd64 platform-manifest digest:
  `sha256:51d31fdfacb0cff99a1a724152e34ae408d2bd4e7da310ff157450f49261cc59`.

The mutable tag is never the execution identity: CI pulls the selected platform
manifest by digest and forces Linux amd64. The browser executable SHA-256,
executable size, operating-system identity, and resolved sans-serif/monospace
font filenames, families, styles, sizes, and SHA-256 values are captured from
that immutable image in the reviewed report-evidence manifest.

Chromium is primarily BSD-licensed and incorporates third-party components
under their respective licenses, which the upstream Chromium distribution and
Playwright image preserve. The image also contains Ubuntu Noble system
libraries and fonts under their package licenses. Neither the image, browser
binary, automation wheels, system libraries, nor font files are copied into
this repository or package. Committed PNG/GIF pixels are generated output; the
architecture SVG embeds no font file.

The exact image metadata is duplicated in the canonical
[`requirements/report-browser-image.lock.json`](requirements/report-browser-image.lock.json)
so reviewers can distinguish the multi-architecture index from the selected
platform manifest. Capture runs with no network, as a non-root user, from
read-only mounts; the image is evidence tooling rather than a sandbox claim for
hostile web content.

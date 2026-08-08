# Third-party notices

This repository's Python package has no runtime dependencies. The dependency
below is used only by the reproducible CLI visual-evidence job; it is not
installed with `casefold-observatory`, included in its wheel, or loaded by the
CLI.

## Pillow 12.3.0

- Purpose: deterministic PNG and GIF encoding for reviewed CLI evidence.
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
[`requirements/cli-visuals.txt`](requirements/cli-visuals.txt). Published
repository artifacts contain only the encoded images, not the Pillow wheel or
Pillow source.

## Embedded Aileron Regular subset used by Pillow

`PIL.ImageFont.load_default(size=...)` in Pillow 12.3.0 loads Pillow's embedded,
limited-character-set copy of Aileron Regular when FreeType support is
available. The CLI evidence renderer uses that API only for ASCII transcript
text.

- Pillow API provenance:
  https://pillow.readthedocs.io/en/stable/reference/ImageFont.html
- Typeface upstream: https://dotcolon.net/fonts/aileron/
- Designer: Sora Sagano / dot colon.
- Upstream rights statement: “No Rights Reserved.”

The repository does not silently bundle an Aileron font file. The committed PNG
and GIF contain rasterized glyph pixels produced by the hash-locked Pillow
wheel. The SVGs use a generic local monospace fallback list and embed no font.

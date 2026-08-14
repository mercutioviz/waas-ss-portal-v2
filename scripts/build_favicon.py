#!/usr/bin/env python3
"""Render `app/static/favicon.svg` into a multi-resolution `favicon.ico`.

The SVG is the source of truth — edit it, then rerun this script. The
generated ICO contains PNGs at 16 / 32 / 48 pixels for the sizes browsers
typically request.

Requires `cairosvg` and `Pillow`. Both are dev-only build tools; not
listed in requirements.txt because the produced ICO is checked in and
does not need to be regenerated at runtime.
"""

import io
from pathlib import Path

import cairosvg
from PIL import Image

REPO = Path(__file__).resolve().parent.parent
SVG_PATH = REPO / 'app' / 'static' / 'favicon.svg'
ICO_PATH = REPO / 'app' / 'static' / 'favicon.ico'
SIZES = (16, 32, 48)


def render_png(svg_bytes: bytes, size: int) -> Image.Image:
    png_bytes = cairosvg.svg2png(
        bytestring=svg_bytes,
        output_width=size,
        output_height=size,
    )
    return Image.open(io.BytesIO(png_bytes)).convert('RGBA')


def main() -> None:
    svg_bytes = SVG_PATH.read_bytes()
    frames = [render_png(svg_bytes, s) for s in SIZES]
    frames[0].save(
        ICO_PATH,
        format='ICO',
        sizes=[(s, s) for s in SIZES],
        append_images=frames[1:],
    )
    print(f'Wrote {ICO_PATH} ({ICO_PATH.stat().st_size} bytes, sizes={SIZES})')


if __name__ == '__main__':
    main()

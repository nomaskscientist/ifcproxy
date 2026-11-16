"""Render the trifecta demo's terminal output into the README animation.

    go run ./examples/trifecta-demo > demo.ans
    python scripts/render_demo_gif.py demo.ans docs/demo.gif

Needs Pillow and a monospace TTF (Consolas, DejaVu Sans Mono or Menlo).
The input is the real output of the demo (with ANSI colours); this script
only adds typing and pacing.
"""

import re
import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

COMMAND = "go run ./examples/trifecta-demo"
SIZE = 17
PAD_X, PAD_Y, TITLE_H = 22, 18, 30
COLS = 92

BG = (13, 17, 23)
TITLE_BG = (22, 27, 34)
FG = (201, 209, 217)
DIM = (125, 133, 144)
COLORS = {"31": (255, 85, 85), "32": (63, 185, 80), "33": (227, 179, 65), "36": (88, 166, 255)}

FONT_CANDIDATES = [
    ("C:/Windows/Fonts/consola.ttf", "C:/Windows/Fonts/consolab.ttf"),
    ("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"),
    ("/System/Library/Fonts/Menlo.ttc", "/System/Library/Fonts/Menlo.ttc"),
]


def load_fonts():
    for regular, bold in FONT_CANDIDATES:
        if Path(regular).exists():
            return ImageFont.truetype(regular, SIZE), ImageFont.truetype(bold, SIZE)
    sys.exit("no monospace font found; edit FONT_CANDIDATES")


SGR = re.compile(r"\x1b\[([0-9;]*)m")


def parse(line):
    """Split one line into (text, colour, bold) spans."""
    spans, colour, bold, pos = [], FG, False, 0
    for m in SGR.finditer(line):
        if m.start() > pos:
            spans.append((line[pos:m.start()], colour, bold))
        for code in (m.group(1) or "0").split(";"):
            if code in ("0", ""):
                colour, bold = FG, False
            elif code == "1":
                bold = True
            elif code == "2":
                colour = DIM
            elif code in COLORS:
                colour = COLORS[code]
        pos = m.end()
    if pos < len(line):
        spans.append((line[pos:], colour, bold))
    return spans


def main(src, dst):
    lines = Path(src).read_text(encoding="utf-8").rstrip("\n").split("\n")
    regular, boldf = load_fonts()
    cw = regular.getlength("M")
    lh = int(SIZE * 1.45)
    rows = len(lines) + 1
    width = int(PAD_X * 2 + cw * COLS)
    height = TITLE_H + PAD_Y * 2 + lh * rows

    def frame(prompt_text, shown, cursor):
        im = Image.new("RGB", (width, height), BG)
        d = ImageDraw.Draw(im)
        d.rectangle([0, 0, width, TITLE_H], fill=TITLE_BG)
        for i, c in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
            x = 16 + i * 20
            d.ellipse([x, 10, x + 11, 21], fill=c)
        d.text((width / 2, TITLE_H / 2), "ifcproxy: lethal trifecta demo", font=regular, fill=DIM, anchor="mm")
        y = TITLE_H + PAD_Y
        d.text((PAD_X, y), "$ ", font=boldf, fill=COLORS["32"])
        d.text((PAD_X + cw * 2, y), prompt_text, font=regular, fill=FG)
        if cursor:
            cx = PAD_X + cw * (2 + len(prompt_text))
            d.rectangle([cx, y + 2, cx + cw - 1, y + SIZE + 2], fill=FG)
        for i, line in enumerate(lines[:shown]):
            x, ly = PAD_X, y + lh * (i + 1)
            for text, colour, bold in parse(line):
                d.text((x, ly), text, font=boldf if bold else regular, fill=colour)
                x += cw * len(text)
        return im

    frames, durations = [], []

    def add(im, ms):
        frames.append(im)
        durations.append(ms)

    add(frame("", 0, True), 700)
    for i in range(1, len(COMMAND) + 1):
        add(frame(COMMAND[:i], 0, True), 45)
    add(frame(COMMAND, 0, True), 500)
    for n in range(1, len(lines) + 1):
        plain = SGR.sub("", lines[n - 1])
        if plain.startswith("["):
            ms = 900  # the call goes out; wait for the decision
        elif "DENY" in plain:
            ms = 1200
        elif "lethal trifecta" in plain:
            ms = 1800
        elif plain.strip() == "":
            ms = 150
        else:
            ms = 350
        add(frame(COMMAND, n, False), ms)
    durations[-1] = 6000

    palette = frames[-1].quantize(colors=256, method=Image.Quantize.MAXCOVERAGE)
    out = [f.quantize(palette=palette, dither=Image.Dither.NONE) for f in frames]
    out[0].save(dst, save_all=True, append_images=out[1:], duration=durations, loop=0, optimize=True, disposal=1)
    print(f"{dst}: {len(out)} frames, {width}x{height}, {Path(dst).stat().st_size // 1024} KiB")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2])

#!/usr/bin/env python3
"""Render the animated terminal casts under ``docs/`` - ``demo.gif`` (a real ``redgap
run``) and ``audit-demo.gif`` (``redgap audit`` catching a SILENT rule).

These are *rasterized* GIFs, not animated SVGs (which GitHub strips when a README embeds
them), so the casts play inline on the project page. The frames are deterministic - the
same content the committed samples and the site show - so re-running is reproducible.

    python scripts/gen_demo_gif.py     # writes docs/demo.gif and docs/audit-demo.gif

Requires Pillow and a monospace TTF. The font is only used to rasterize here; nothing
about it ships in the GIFs.
"""

from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

DOCS = Path(__file__).resolve().parents[1] / "docs"

# --- palette (mirrors the site's terminal tokens) --------------------------------------
BG = (10, 14, 21)
BG_BAR = (14, 20, 32)
LINE = (30, 39, 54)
INK = (232, 237, 245)
DIM = (102, 113, 138)
SUBTLE = (154, 166, 184)
RED = (255, 77, 85)
GREEN = (110, 240, 166)
AMBER = (244, 185, 66)
DOT_R, DOT_Y, DOT_G = (255, 95, 87), (254, 188, 46), (40, 200, 64)

FS = 21
LH = 31
PAD_X = 26
TOP = 60  # title bar height + gap

# Any monospace TTF works; try the common platform ones so the script runs anywhere.
_REGULAR = (
    "C:\\Windows\\Fonts\\consola.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
    "/Library/Fonts/Menlo.ttc",
)
_BOLD = (
    "C:\\Windows\\Fonts\\consolab.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf",
    "/Library/Fonts/Menlo.ttc",
)


def _font(candidates: tuple[str, ...]) -> ImageFont.FreeTypeFont:
    for path in candidates:
        try:
            return ImageFont.truetype(path, FS)
        except OSError:
            continue
    raise SystemExit(
        "gen_demo_gif: no monospace TTF found - install DejaVu Sans Mono or edit _REGULAR."
    )


font = _font(_REGULAR)
fontb = _font(_BOLD)

# A line is a list of (text, color, bold) spans. None = a blank line.
Span = tuple[str, tuple[int, int, int], bool]
Line = list[Span] | None


def _f(bold: bool) -> ImageFont.FreeTypeFont:
    return fontb if bold else font


def _row(tid: str, name: str, dot: str, status: str, color: tuple[int, int, int]) -> list[Span]:
    left = f"  {tid.ljust(11)}{name.ljust(25)}"
    return [(left, SUBTLE, False), (f"{dot} ", color, True), (status, color, False)]


# ---- content: the flagship `redgap run` -----------------------------------------------
RUN_LINES: list[Line] = [
    [("$ ", RED, True), ("pip install redgap", INK, False)],
    [("$ ", RED, True), ("redgap run", INK, False)],
    [("REPLAY - re-evaluating real captured telemetry", DIM, False)],
    None,
    _row("T1548.001", "Setuid/Setgid", "\u25cf", "detected", GREEN),
    _row("T1140", "Base64 decode -> shell", "\u25cf", "detected", GREEN),
    _row("T1053.003", "Cron", "\u25cf", "detected", GREEN),
    _row("T1070.006", "Timestomp", "\u25cf", "gap (rule)", RED),
    _row("T1003.008", "/etc/shadow read", "\u25cf", "gap (rule)", RED),
    _row("T1057", "Process discovery", "\u25cf", "gap (base-rate)", AMBER),
    [("  ... 45 more ...", DIM, False)],
    None,
    [
        ("  ", INK, False),
        ("34", GREEN, True),
        ("/51 detected", INK, False),
        ("  \u00b7  ", DIM, False),
        ("17 gaps", RED, True),
        ("   (rule:12, base-rate:5)", DIM, False),
    ],
    [("  -> find the red. close it. prove it.", GREEN, False)],
]

# ---- content: `redgap audit` catching a SILENT rule -----------------------------------
AUDIT_LINES: list[Line] = [
    [("$ ", RED, True), ("redgap audit --rules ./my-sigma/", INK, False)],
    [("REPLAY - scoring YOUR rules against real captured telemetry", DIM, False)],
    None,
    [
        ("coverage: ", SUBTLE, False),
        ("1", INK, True),
        ("/51 techniques your rules catch", SUBTLE, False),
    ],
    None,
    [("rule health:", SUBTLE, False)],
    [("  \u25cf firing        ", GREEN, True), ("Local Account Enumeration", INK, False)],
    [
        ("  \u25cf SILENT        ", RED, True),
        ("OS Credential Dumping   ", INK, False),
        ("\u2190 tagged, never fires", RED, False),
    ],
    [("  \u25cb out-of-corpus ", DIM, True), ("Rundll32 Execution (Windows)", SUBTLE, False)],
    None,
    [
        ("1", GREEN, True),
        (" firing  \u00b7  ", DIM, False),
        ("1", RED, True),
        (" SILENT  \u00b7  ", DIM, False),
        ("1", SUBTLE, True),
        (" out-of-corpus", DIM, False),
    ],
    [("the SILENT rule passes its own unit test, yet never fires on real data.", AMBER, False)],
]


def _line_width(line: Line) -> int:
    if line is None:
        return 0
    return int(sum(_f(b).getlength(t) for t, _c, b in line))


def _canvas(lines: list[Line]) -> tuple[int, int]:
    w = PAD_X * 2 + max(_line_width(ln) for ln in lines)
    h = TOP + LH * len(lines) + 22
    return int(w), h


def _draw(
    lines: list[Line],
    size: tuple[int, int],
    revealed: int,
    cursor: bool,
    typed_idx: int,
    typed: str | None,
) -> Image.Image:
    """Render one frame: the first ``revealed`` lines, an optional typing overlay on the
    command line ``typed_idx``, and an optional block cursor after the last drawn line."""
    img = Image.new("RGB", size, BG)
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, size[0], 40], fill=BG_BAR)
    d.line([0, 40, size[0], 40], fill=LINE)
    for i, col in enumerate((DOT_R, DOT_Y, DOT_G)):
        d.ellipse([22 + i * 20, 14, 34 + i * 20, 26], fill=col)
    d.text((92, 12), "redgap - replay", font=font, fill=DIM)

    y = TOP
    last_x = PAD_X
    for idx in range(revealed):
        line = lines[idx]
        if line is None:
            y += LH
            continue
        if idx == typed_idx and typed is not None:
            d.text((PAD_X, y), "$ ", font=fontb, fill=RED)
            tx = PAD_X + int(font.getlength("$ "))
            d.text((tx, y), typed, font=font, fill=INK)
            last_x = tx + int(font.getlength(typed))
            y += LH
            continue
        x = PAD_X
        for text, color, bold in line:
            d.text((x, y), text, font=_f(bold), fill=color)
            x += int(_f(bold).getlength(text))
        last_x = x
        y += LH

    if cursor:
        cy = TOP + LH * (revealed - 1)
        d.rectangle([last_x + 2, cy + 3, last_x + 12, cy + FS], fill=GREEN)
    return img


def build(lines: list[Line], cmd: str, typed_idx: int, out: Path) -> None:
    size = _canvas(lines)
    frames: list[Image.Image] = []
    durations: list[int] = []

    def add(revealed: int, cursor: bool, typed: str | None, ms: int) -> None:
        frames.append(_draw(lines, size, revealed, cursor, typed_idx, typed))
        durations.append(ms)

    base = typed_idx + 1  # lines shown while the command is typed (incl. the command line)
    add(base, True, "", 500)
    for i in range(1, len(cmd) + 1):
        add(base, True, cmd[:i], 55)
    add(base, False, cmd, 320)
    for r in range(base + 1, len(lines) + 1):
        add(r, False, None, 260 if r >= len(lines) - 1 else 150)
    full = len(lines)
    for _ in range(2):
        add(full, True, None, 560)
        add(full, False, None, 420)
    add(full, True, None, 1700)

    # Quantize every frame to the last frame's palette (it holds all colors) so the
    # animation never flickers between per-frame palettes; flat UI colors keep dither off.
    pal = frames[-1].convert("P", palette=Image.ADAPTIVE, colors=64)
    pframes = [f.quantize(palette=pal, dither=Image.Dither.NONE) for f in frames]
    pframes[0].save(
        out,
        save_all=True,
        append_images=pframes[1:],
        duration=durations,
        loop=0,
        optimize=True,
        disposal=2,
    )
    kib = out.stat().st_size // 1024
    print(f"wrote {out}  ({size[0]}x{size[1]}, {len(frames)} frames, {kib} KiB)")


def main() -> None:
    build(RUN_LINES, "redgap run", 1, DOCS / "demo.gif")
    build(AUDIT_LINES, "redgap audit --rules ./my-sigma/", 0, DOCS / "audit-demo.gif")


if __name__ == "__main__":
    main()

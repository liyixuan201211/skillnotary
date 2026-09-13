#!/usr/bin/env python3
"""
Render demo/demo.txt (real captured terminal output, ANSI colours and all)
into demo/demo.svg, so the image in the README is the tool's actual output
rather than a mock-up.

Usage:
    bash demo/run.sh > demo/demo.txt
    python3 demo/render_svg.py
"""

from __future__ import annotations

import html
import re
import sys
from pathlib import Path

ANSI_RE = re.compile(r"\x1b\[([0-9;]*)m")

# The SGR codes skillnotary's reporter actually emits.
FG = {
    "31": "#ff7b72",  # red
    "32": "#3fb950",  # green
    "33": "#d29922",  # yellow
    "34": "#58a6ff",  # blue
    "35": "#bc8cff",  # magenta
    "36": "#39c5cf",  # cyan
    "90": "#8b949e",  # gray
}
DEFAULT_FG = "#c9d1d9"
BG = "#0d1117"
BAR = "#161b22"
BORDER = "#30363d"

FONT_SIZE = 13.0
CHAR_W = 8.0  # measured for the font stack below at FONT_SIZE
LINE_H = 20.0
PAD_X = 22.0
PAD_TOP = 54.0
PAD_BOTTOM = 20.0
DOTS_H = 34.0
# Terminals wrap; so do we, otherwise a long explanation runs off the frame.
MAX_COLS = 116

FONT_STACK = (
    "ui-monospace, SFMono-Regular, 'SF Mono', Menlo, Consolas, "
    "'Liberation Mono', monospace"
)


class Run:
    __slots__ = ("text", "fg", "bold", "dim", "_style")

    def __init__(self) -> None:
        self.text = ""
        self.fg: str | None = None
        self.bold = False
        self.dim = False
        self._style: Run | None = None

    def style_attrs(self) -> str:
        attrs = []
        fg = self.fg or DEFAULT_FG
        attrs.append(f'fill="{fg}"')
        if self.bold:
            attrs.append('font-weight="600"')
        if self.dim:
            attrs.append('opacity="0.62"')
        return " ".join(attrs)


def parse_line(line: str) -> list[Run]:
    """Split a line into styled runs, tracking SGR state."""
    runs: list[Run] = []
    current = Run()
    pos = 0

    for match in ANSI_RE.finditer(line):
        if match.start() > pos:
            current.text += line[pos : match.start()]
        for code in filter(None, match.group(1).split(";")):
            if code == "0":
                if current.text:
                    runs.append(current)
                current = Run()
            elif code == "1":
                current.bold = True
            elif code == "2":
                current.dim = True
            elif code in FG:
                current.fg = FG[code]
        pos = match.end()

    if pos < len(line):
        current.text += line[pos:]
    if current.text:
        runs.append(current)
    return runs


def visible_width(line: str) -> int:
    return len(ANSI_RE.sub("", line))


def chars_to_runs(chars: list[tuple[str, "Run"]]) -> list[Run]:
    """Merge a list of (char, style) pairs back into styled runs."""
    runs: list[Run] = []
    for ch, style in chars:
        if runs and runs[-1]._style is style:
            runs[-1].text += ch
        else:
            run = Run()
            run.text = ch
            run.fg = style.fg
            run.bold = style.bold
            run.dim = style.dim
            run._style = style
            runs.append(run)
    return runs


def wrap_runs(runs: list[Run], max_cols: int) -> list[list[Run]]:
    """
    Wrap styled runs to `max_cols` visible characters, breaking at the last
    space in the window when there is one and hard-breaking otherwise.
    """
    chars: list[tuple[str, Run]] = []
    for run in runs:
        for ch in run.text:
            chars.append((ch, run))

    rows: list[list[Run]] = []
    while len(chars) > max_cols:
        window = chars[:max_cols]
        cut = None
        for i in range(len(window) - 1, -1, -1):
            if window[i][0] == " ":
                cut = i
                break
        if cut is None or cut == 0:
            rows.append(chars_to_runs(window))
            chars = chars[max_cols:]
        else:
            rows.append(chars_to_runs(chars[:cut]))
            chars = chars[cut + 1 :]
    rows.append(chars_to_runs(chars))
    return [r for r in rows if r]


def render(text: str, title: str) -> str:
    source_lines = text.rstrip("\n").split("\n")
    while source_lines and source_lines[0].strip() == "":
        source_lines.pop(0)

    # Parse each source line, then wrap it the way a terminal would.
    rows: list[list[Run]] = []
    for line in source_lines:
        runs = parse_line(line)
        if not runs:
            rows.append([])
            continue
        rows.extend(wrap_runs(runs, MAX_COLS))

    cols = min(max((sum(len(r.text) for r in row) for row in rows), default=40), MAX_COLS)
    width = round(PAD_X * 2 + cols * CHAR_W)
    height = round(PAD_TOP + len(rows) * LINE_H + PAD_BOTTOM)

    out: list[str] = []
    out.append(
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" role="img" '
        f'aria-label="{html.escape(title)}">'
    )
    out.append(
        f'<rect x="0.5" y="0.5" width="{width - 1}" height="{height - 1}" rx="10" '
        f'fill="{BG}" stroke="{BORDER}"/>'
    )
    out.append(
        f'<path d="M0.5 10a10 10 0 0 1 10-10h{width - 21}a10 10 0 0 1 10 10v{DOTS_H - 10}'
        f'H0.5z" fill="{BAR}"/>'
    )
    for i, colour in enumerate(("#ff5f57", "#febc2e", "#28c840")):
        out.append(
            f'<circle cx="{20 + i * 20}" cy="{DOTS_H / 2 + 2}" r="6" fill="{colour}"/>'
        )
    out.append(
        f'<text x="{width / 2}" y="{DOTS_H / 2 + 6}" fill="#8b949e" '
        f'font-family="{FONT_STACK}" font-size="12" text-anchor="middle">'
        f"{html.escape(title)}</text>"
    )

    out.append(
        f'<g font-family="{FONT_STACK}" font-size="{FONT_SIZE}" '
        f'xml:space="preserve">'
    )
    for index, row in enumerate(rows):
        if not row:
            continue
        y = PAD_TOP + index * LINE_H
        spans = "".join(
            f'<tspan {run.style_attrs()}>{html.escape(run.text)}</tspan>' for run in row
        )
        # xml:space on each <text> (not a parent) is what keeps the column
        # padding in tables from collapsing.
        out.append(
            f'<text x="{PAD_X}" y="{y:.1f}" xml:space="preserve" '
            f'style="white-space:pre">{spans}</text>'
        )
    out.append("</g>")
    out.append("</svg>")
    return "\n".join(out) + "\n"


def main() -> int:
    root = Path(__file__).resolve().parent
    source = root / "demo.txt"
    target = root / "demo.svg"

    if not source.exists():
        print(f"error: {source} not found; run: bash demo/run.sh > demo/demo.txt", file=sys.stderr)
        return 1

    svg = render(source.read_text(encoding="utf-8"), "skillnotary — capability drift")
    target.write_text(svg, encoding="utf-8")
    print(f"wrote {target} ({len(svg)} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

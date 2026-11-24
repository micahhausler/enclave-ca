#!/usr/bin/env python3
"""Hand-drawn diagrams for the enclave-ca docs, in light and dark variants.

    python3 hack/diagrams.py                 # rewrites every diagram in docs/img/
    python3 hack/diagrams.py overview        # just one
    python3 hack/diagrams.py --svg-dir /tmp  # also keep the intermediate SVGs

Each diagram is drawn as an SVG for GitHub's light and dark themes, then
rendered with rsvg-convert (librsvg) to docs/img/<name>@2x.png and
docs/img/<name>-dark@2x.png. The docs embed the PNGs at half their pixel
width, so the text looks the same for every reader. The SVGs are an
intermediate format and aren't committed.

Text markup inside labels: `mono` for commands and API names, *accent* for
emphasis. File names stay in the regular font.
"""
import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile

SANS = "-apple-system, BlinkMacSystemFont, 'Segoe UI', Inter, Helvetica, Arial, sans-serif"
MONO = "ui-monospace, SFMono-Regular, Menlo, Consolas, 'DejaVu Sans Mono', monospace"

THEMES = {
    "light": {
        "bg": "#ffffff", "dot": "#dbe7e4",
        "ink": "#0c2d2b", "muted": "#557370", "faint": "#8aa6a2",
        "region": "#dae8e4", "region_label": "#4f716d",
        "actor": "#0f3f3c", "actor_hdr": "#5fe0c8", "actor_title": "#ffffff", "actor_body": "#c3e3dd",
        "actor_pill": "#e3f6f1", "actor_pill_text": "#0f3f3c", "pill_dot": "#0f9488",
        "shadow": "#cfe0dc",
        "data": "#eef9f6", "data_stroke": "#0f3f3c", "data_hdr": "#0f766e", "data_title": "#0c2d2b", "data_body": "#4a6966",
        "accent": "#c2410c", "accent_soft": "#fff1e6",
        "arrow": "#0c2d2b",
    },
    "dark": {
        "bg": "#0e1615", "dot": "#1e2b29",
        "ink": "#e4f2ef", "muted": "#93b0ab", "faint": "#5f7a76",
        "region": "#1c2d2a", "region_label": "#8fb0aa",
        "actor": "#9fe7d9", "actor_hdr": "#0f5f58", "actor_title": "#062624", "actor_body": "#164c47",
        "actor_pill": "#0f3f3c", "actor_pill_text": "#e4f6f2", "pill_dot": "#5fe0c8",
        "shadow": "#070c0b",
        "data": "#111c1b", "data_stroke": "#5fe0c8", "data_hdr": "#5fe0c8", "data_title": "#e4f2ef", "data_body": "#a3bfbb",
        "accent": "#fb923c", "accent_soft": "#2a1a10",
        "arrow": "#d6ebe7",
    },
}

# Type scale, shared by every diagram.
TITLE = 32
SUB = 16
HDR = 12
CTITLE = 20
BODY = 15
MONO_BODY = 14
LABEL = 16
SMALL = 14.5
LH = 21


def esc(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


class D:
    """One diagram being drawn in one theme."""

    def __init__(self, w, h, theme):
        self.w, self.h, self.t = w, h, THEMES[theme]
        self.out = []

    def add(self, s):
        self.out.append(s)

    # ---- text -----------------------------------------------------------
    def rich(self, s, size, color, weight=400, mono_size=None):
        """Turn `mono` and *accent* markup into tspans."""
        mono_size = mono_size or round(size * 0.93, 1)
        parts = re.split(r"(`[^`]*`|\*[^*]*\*)", s)
        out = []
        for p in parts:
            if not p:
                continue
            if p.startswith("`"):
                out.append(f'<tspan font-family="{MONO}" font-size="{mono_size}" font-weight="{max(weight, 500)}">{esc(p[1:-1])}</tspan>')
            elif p.startswith("*"):
                out.append(f'<tspan fill="{self.t["accent"]}" font-weight="650">{esc(p[1:-1])}</tspan>')
            else:
                out.append(esc(p))
        return "".join(out)

    def text(self, x, y, s, size=LABEL, color=None, weight=400, anchor="start", mono=False, spacing=None, mono_size=None):
        color = color or self.t["muted"]
        fam = MONO if mono else SANS
        ls = f' letter-spacing="{spacing}"' if spacing else ""
        self.add(f'<text x="{x}" y="{y}" font-family="{fam}" font-size="{size}" font-weight="{weight}" '
                 f'fill="{color}" text-anchor="{anchor}"{ls}>{self.rich(s, size, color, weight, mono_size)}</text>')

    def lines(self, x, y, items, size=LABEL, color=None, anchor="start", lh=LH, weight=400):
        for i, s in enumerate(items):
            self.text(x, y + i * lh, s, size=size, color=color, anchor=anchor, weight=weight)

    # ---- frame ------------------------------------------------------------
    def frame(self, title, subtitle):
        t = self.t
        self.add(f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {self.w} {self.h}" role="img">')
        self.add('<defs>')
        self.add(f'<pattern id="dots" width="22" height="22" patternUnits="userSpaceOnUse">'
                 f'<circle cx="2" cy="2" r="1.1" fill="{t["dot"]}"/></pattern>')
        for name, color in (("ink", t["arrow"]), ("accent", t["accent"]), ("muted", t["muted"])):
            self.add(f'<marker id="ah-{name}" viewBox="0 0 12 12" refX="10" refY="6" markerWidth="12" markerHeight="12" '
                     f'markerUnits="userSpaceOnUse" orient="auto-start-reverse">'
                     f'<path d="M1,1.5 L11,6 L1,10.5 L3.6,6 z" fill="{color}"/></marker>')
        self.add('</defs>')
        self.add(f'<rect width="{self.w}" height="{self.h}" fill="{t["bg"]}"/>')
        self.add(f'<rect width="{self.w}" height="{self.h}" fill="url(#dots)"/>')
        self.text(60, 82, title, size=TITLE, color=t["ink"], weight=700, mono_size=TITLE)
        self.lines(60, 118, subtitle, size=SUB, color=t["muted"], lh=24)

    def legend(self, x, y, items, row_layout=False):
        """items: list of (kind, label); kinds actor, data, solid, dashed, accent."""
        t = self.t
        cx = x
        for i, (kind, label) in enumerate(items):
            if row_layout:
                lx, ly = cx, y
                cx += 46 + len(label) * 8.4 + 34
            else:
                col, row = i // 2, i % 2
                lx, ly = x + col * 230, y + row * 34
            if kind == "actor":
                self.add(f'<rect x="{lx}" y="{ly - 12}" width="34" height="18" rx="5" fill="{t["actor"]}"/>')
            elif kind == "data":
                self.add(f'<rect x="{lx}" y="{ly - 12}" width="34" height="18" rx="5" fill="{t["data"]}" '
                         f'stroke="{t["data_stroke"]}" stroke-width="1.8"/>')
            elif kind in ("solid", "dashed", "accent"):
                color = "accent" if kind == "accent" else "ink"
                dash = ' stroke-dasharray="6 5"' if kind == "dashed" else ""
                self.add(f'<path d="M{lx},{ly - 3} H{lx + 32}" stroke="{t["arrow"] if color == "ink" else t["accent"]}" '
                         f'stroke-width="2"{dash} marker-end="url(#ah-{color})"/>')
            self.text(lx + 46, ly + 2, label, size=LABEL, color=t["ink"])

    def set_height(self, h):
        """Resize the canvas after drawing, for diagrams whose height comes from their content."""
        old, self.h = self.h, h
        self.out = [x.replace(f'viewBox="0 0 {self.w} {old}"', f'viewBox="0 0 {self.w} {h}"')
                     .replace(f'width="{self.w}" height="{old}"', f'width="{self.w}" height="{h}"') for x in self.out]

    def end(self):
        self.add("</svg>")
        return "\n".join(self.out) + "\n"

    # ---- shapes ---------------------------------------------------------
    def region(self, x, y, w, h, label, icon=None):
        t = self.t
        self.add(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="22" fill="{t["region"]}"/>')
        if icon == "laptop":
            ix, iy, c = x + 22, y + 17, t["region_label"]
            self.add(f'<g fill="none" stroke="{c}" stroke-width="1.7" stroke-linejoin="round" stroke-linecap="round">'
                     f'<rect x="{ix + 2.5}" y="{iy}" width="17" height="12" rx="2"/><path d="M{ix},{iy + 15.5} H{ix + 22}"/></g>')
            self.text(x + 54, y + 32, label.upper(), size=HDR, color=c, weight=650, spacing=1.4)
        elif icon == "server":
            ix, iy, c = x + 22, y + 15, t["region_label"]
            self.add(f'<g fill="none" stroke="{c}" stroke-width="1.7"><rect x="{ix}" y="{iy}" width="20" height="17" rx="3"/>'
                     f'<path d="M{ix},{iy + 5.67} H{ix + 20} M{ix},{iy + 11.33} H{ix + 20}"/></g>')
            self.text(x + 54, y + 32, label.upper(), size=HDR, color=c, weight=650, spacing=1.4)
        else:
            self.text(x + 22, y + 32, label.upper(), size=HDR, color=t["region_label"], weight=650, spacing=1.4)

    def card(self, x, y, w, kind, header, title, body=(), pills=(), h=None, icon=True, title_size=CTITLE, pad=24):
        """kind: actor (runs) or data (at rest). Returns (x, y, w, h)."""
        t = self.t
        actor = kind == "actor"
        n = len(body)
        cy = y + 36
        title_y = cy + 30 if header else y + 34  # no header: a compact step card
        body_y = title_y + (27 if header else 25)
        auto_h = (body_y + (n - 1) * LH if n else title_y) + 22
        auto_h += sum(42 for _ in pills)
        h = h or (auto_h - y)
        if actor:
            self.add(f'<rect x="{x}" y="{y + 5}" width="{w}" height="{h}" rx="16" fill="{t["shadow"]}"/>')
            self.add(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="16" fill="{t["actor"]}"/>')
        else:
            self.add(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="16" fill="{t["data"]}" '
                     f'stroke="{t["data_stroke"]}" stroke-width="2"/>')
        hdr_c = t["actor_hdr"] if actor else t["data_hdr"]
        if header:
            self.text(x + pad, cy, header.upper(), size=HDR, color=hdr_c, weight=650, spacing=1.4, mono_size=HDR)
        if icon:
            ix, iy = x + w - pad - 14, y + 22
            if icon == "server":  # a rack unit with three bays
                ix, iy = x + w - pad - 22, y + 20
                self.add(f'<g fill="none" stroke="{hdr_c}" stroke-width="1.8">'
                         f'<rect x="{ix}" y="{iy}" width="22" height="19" rx="3.5"/>'
                         f'<path d="M{ix},{iy + 6.33} H{ix + 22} M{ix},{iy + 12.67} H{ix + 22}"/></g>'
                         + "".join(f'<circle cx="{ix + 4.5}" cy="{iy + 3.17 + k * 6.33:.2f}" r="1.2" fill="{hdr_c}"/>'
                                   for k in range(3)))
            elif icon == "laptop":  # screen over a base
                ix, iy = x + w - pad - 30, y + 19
                self.add(f'<g fill="none" stroke="{hdr_c}" stroke-width="1.8" stroke-linejoin="round" stroke-linecap="round">'
                         f'<rect x="{ix + 3.5}" y="{iy}" width="23" height="16" rx="2.5"/>'
                         f'<path d="M{ix},{iy + 20.5} H{ix + 30}"/></g>')
            elif icon == "chip":  # a TPM: square package with pins on each side
                ix, iy = x + w - pad - 22, y + 17
                pins = "".join(f"M{ix + 7 + k * 4},{iy} V{iy + 3} M{ix + 7 + k * 4},{iy + 19} V{iy + 22} "
                               f"M{ix},{iy + 7 + k * 4} H{ix + 3} M{ix + 19},{iy + 7 + k * 4} H{ix + 22} " for k in range(3))
                self.add(f'<g fill="none" stroke="{hdr_c}" stroke-width="1.8" stroke-linecap="round">'
                         f'<rect x="{ix + 3}" y="{iy + 3}" width="16" height="16" rx="2.5"/>'
                         f'<rect x="{ix + 8}" y="{iy + 8}" width="6" height="6" rx="1"/><path d="{pins}"/></g>')
            elif icon == "role":  # IAM-style person: round head, sloped shoulders
                ix, iy = x + w - pad - 24, y + 17
                self.add(f'<g fill="none" stroke="{hdr_c}" stroke-width="1.8" stroke-linejoin="round" stroke-linecap="round">'
                         f'<circle cx="{ix + 12}" cy="{iy + 5.5}" r="5"/>'
                         f'<path d="M{ix + 1},{iy + 24} V{iy + 21} C{ix + 1},{iy + 16} {ix + 5},{iy + 13.5} {ix + 12},{iy + 13.5} '
                         f'C{ix + 19},{iy + 13.5} {ix + 23},{iy + 16} {ix + 23},{iy + 21} V{iy + 24} Z"/></g>')
            elif actor:
                self.add(f'<path d="M{ix + 2},{iy} L{ix + 15},{iy + 8} L{ix + 2},{iy + 16} z" fill="{hdr_c}"/>')
            else:
                self.add(f'<g fill="none" stroke="{hdr_c}" stroke-width="1.8">'
                         f'<ellipse cx="{ix + 8}" cy="{iy + 3}" rx="8" ry="3"/>'
                         f'<path d="M{ix},{iy + 3} V{iy + 15} A8,3 0 0 0 {ix + 16},{iy + 15} V{iy + 3}"/></g>')
        self.text(x + pad, title_y, title, size=title_size, color=t["actor_title"] if actor else t["data_title"],
                  weight=650, mono_size=title_size - 1)
        for i, s in enumerate(body):
            ind = 0
            m = re.match(r"^(\d+\.) (.*)$", s)
            if m:  # numbered item: number in the gutter, text indented
                self.text(x + pad, body_y + i * LH, m.group(1), size=BODY,
                          color=t["actor_hdr"] if actor else t["data_hdr"], weight=650)
                s, ind = m.group(2), 22
            elif s.startswith("  "):
                s, ind = s.strip(), 22
            self.text(x + pad + ind, body_y + i * LH, s, size=BODY, color=t["actor_body"] if actor else t["data_body"],
                      mono_size=MONO_BODY)
        py = (body_y + (n - 1) * LH if n else title_y) + 18
        for p in pills:  # a tuple (text,) marks an accent pill, e.g. a Touch ID prompt
            accent = isinstance(p, tuple)
            self.pill(x + pad - 8, py, w - 2 * pad + 16, p[0] if accent else p, on_actor=actor, accent=accent)
            py += 42
        return (x, y, w, h)


    def phase(self, x, y, title, note, bg=None):
        """A phase heading (bold title, muted note) on a small patch so lifelines don't run through it."""
        t = self.t
        tw = len(title) * 9.4 + 12 + len(note) * 7.4 + 16
        self.add(f'<rect x="{x - 8}" y="{y - 22}" width="{tw}" height="32" rx="8" fill="{bg or t["bg"]}"/>')
        self.text(x, y, title, size=18, color=t["ink"], weight=650)
        self.text(x + len(title) * 9.4 + 12, y, note, size=SMALL)

    def diamond(self, cx, cy, hw, hh, lines):
        t = self.t
        self.add(f'<path d="M{cx},{cy - hh} L{cx + hw},{cy} L{cx},{cy + hh} L{cx - hw},{cy} Z" fill="{t["data"]}" '
                 f'stroke="{t["data_stroke"]}" stroke-width="2" stroke-linejoin="round"/>')
        y0 = cy + 6 - (len(lines) - 1) * 10
        for i, s in enumerate(lines):
            self.text(cx, y0 + i * 20, s, size=LABEL, color=t["ink"], weight=600 if i == 0 else 400, anchor="middle")

    def braces(self, x, y, h=24, color=None):
        """A {} mark, for credentials JSON. (x, y) is the top-left; about 26 wide."""
        c = color or self.t["data_hdr"]
        m = h / 2
        left = (f"M{x + 7},{y} C{x + 3},{y} {x + 3},{y + 2.5} {x + 3},{y + 5.5} V{y + m - 3} "
                f"C{x + 3},{y + m - 1} {x + 1.5},{y + m} {x},{y + m} C{x + 1.5},{y + m} {x + 3},{y + m + 1} {x + 3},{y + m + 3} "
                f"V{y + h - 5.5} C{x + 3},{y + h - 2.5} {x + 3},{y + h} {x + 7},{y + h}")
        rx = x + 26
        right = (f"M{rx - 7},{y} C{rx - 3},{y} {rx - 3},{y + 2.5} {rx - 3},{y + 5.5} V{y + m - 3} "
                 f"C{rx - 3},{y + m - 1} {rx - 1.5},{y + m} {rx},{y + m} C{rx - 1.5},{y + m} {rx - 3},{y + m + 1} {rx - 3},{y + m + 3} "
                 f"V{y + h - 5.5} C{rx - 3},{y + h - 2.5} {rx - 3},{y + h} {rx - 7},{y + h}")
        self.add(f'<path d="{left} {right}" fill="none" stroke="{c}" stroke-width="2.2" stroke-linecap="round" '
                 f'stroke-linejoin="round"/>')

    def terminal(self, x, y, w, title, sub=None, accent_sub=False, icon=None):
        """An end state: a fully rounded outlined pill, optionally with a {} mark on the left."""
        t = self.t
        h = 64 if sub else 48
        self.add(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{h / 2}" fill="{t["bg"]}" '
                 f'stroke="{t["data_stroke"]}" stroke-width="2"/>')
        cx = x + w / 2
        if icon == "braces":
            self.braces(x + 22, y + h / 2 - 12)
            cx = x + 56 + (w - 56 - 20) / 2
        self.text(cx, y + (28 if sub else 30), title, size=LABEL, color=t["ink"], weight=600, anchor="middle")
        if sub:
            self.text(cx, y + 49, sub, size=SMALL, anchor="middle",
                      color=t["accent"] if accent_sub else t["muted"], weight=600 if accent_sub else 400)
        return (x, y, w, h)

    def pill(self, x, y, w, s, on_actor=True, accent=False):
        t = self.t
        fill = t["actor_pill"] if on_actor else t["region"]
        tc = t["actor_pill_text"] if on_actor else t["ink"]
        self.add(f'<rect x="{x}" y="{y}" width="{w}" height="32" rx="9" fill="{fill}"/>')
        self.add(f'<circle cx="{x + 15}" cy="{y + 16}" r="4" fill="{t["accent"] if accent else t["pill_dot"]}"/>')
        self.text(x + 28, y + 21, s, size=BODY - 1, color=tc, weight=500, mono_size=MONO_BODY - 0.5)

    def arrow(self, pts, style="solid", color="ink", r=14, width=2, start_dot=False):
        t = self.t
        c = t["accent"] if color == "accent" else t["muted"] if color == "muted" else t["arrow"]
        d = rounded(pts, r)
        dash = ' stroke-dasharray="7 6"' if style == "dashed" else ' stroke-dasharray="2 5" stroke-linecap="round"' if style == "dotted" else ""
        self.add(f'<path d="{d}" fill="none" stroke="{c}" stroke-width="{width}"{dash} '
                 f'marker-end="url(#ah-{color})"/>')
        if start_dot:
            self.add(f'<circle cx="{pts[0][0]}" cy="{pts[0][1]}" r="4" fill="{c}"/>')

    def badge(self, cx, cy, s):
        """An accent-outlined tag with a padlock, for transfers that need a secure channel."""
        t = self.t
        w = 30 + len(re.sub(r"[`*]", "", s)) * 7.6
        x = cx - w / 2
        self.add(f'<rect x="{x}" y="{cy - 13}" width="{w}" height="26" rx="13" fill="{t["accent_soft"]}" '
                 f'stroke="{t["accent"]}" stroke-width="1.4"/>')
        lx, ly = x + 12, cy - 5
        self.add(f'<g fill="none" stroke="{t["accent"]}" stroke-width="1.6">'
                 f'<path d="M{lx + 2},{ly + 4} V{ly + 1} A3.5,3.5 0 0 1 {lx + 9},{ly + 1} V{ly + 4}"/></g>')
        self.add(f'<rect x="{lx}" y="{ly + 4}" width="11" height="8" rx="1.5" fill="{t["accent"]}"/>')
        self.text(x + 29, cy + 4.5, s, size=13, color=t["accent"], weight=600)


def rounded(pts, r):
    """Orthogonal polyline with rounded corners."""
    if len(pts) == 2:
        (x0, y0), (x1, y1) = pts
        return f"M{x0},{y0} L{x1},{y1}"
    d = f"M{pts[0][0]},{pts[0][1]}"
    for i in range(1, len(pts) - 1):
        (xa, ya), (xb, yb), (xc, yc) = pts[i - 1], pts[i], pts[i + 1]
        def toward(x0, y0, x1, y1, dist):
            L = ((x1 - x0) ** 2 + (y1 - y0) ** 2) ** 0.5 or 1
            k = min(dist, L / 2) / L
            return x0 + (x1 - x0) * k, y0 + (y1 - y0) * k
        p1 = toward(xb, yb, xa, ya, r)
        p2 = toward(xb, yb, xc, yc, r)
        d += f" L{p1[0]:.1f},{p1[1]:.1f} Q{xb},{yb} {p2[0]:.1f},{p2[1]:.1f}"
    d += f" L{pts[-1][0]},{pts[-1][1]}"
    return d


# ---------------------------------------------------------------------------
# 1. README overview
# ---------------------------------------------------------------------------
def overview(theme):
    """The AWS account as a band across the top; the CA Mac above the two clients below it."""
    W, H = 920, 1204
    d = D(W, H, theme)
    t = d.t
    d.frame("enclave-ca",
            ["One Mac signs every leaf with a root key held in its Secure Enclave.",
             "Each client trades its leaf for short-lived AWS credentials."])
    d.legend(60, 186, [("actor", "machine or service"), ("data", "data at rest"),
                       ("solid", "sends"), ("dashed", "reads")], row_layout=True)

    # AWS band: Roles Anywhere reads the trust anchor
    BY = 268
    d.region(30, 224, W - 60, 252, "AWS account")
    ta = d.card(50, BY, 300, "data", "trust anchor", "ca.crt", ["the root, registered once"])
    ra = d.card(530, BY, 340, "actor", "AWS", "IAM Roles Anywhere",
                ["1. checks that the leaf chains",
                 "  to the trust anchor",
                 "2. checks the role's trust policy",
                 "3. returns temporary credentials"], icon="role")
    y = BY + 66
    d.arrow([(ra[0], y), (ta[0] + ta[2] + 3, y)], style="dashed")
    d.text((ra[0] + ta[0] + ta[2]) / 2, y - 10, "checks the chain", anchor="middle", size=SMALL)

    # Tree: CA Mac above the two clients
    ca = d.card(170, 580, 390, "actor", "Secure Enclave · Touch ID", "CA Mac",
                ["the root key never leaves the enclave;",
                 "signs leaves with `enclave-ca sign`,",
                 "one Touch ID prompt per signature"],
                pills=["ca.key · works only on this Mac", "ca.crt · the public root"], icon="laptop")
    CL_Y, CL_W = ca[1] + ca[3] + 110, 360
    lin = d.card(50, CL_Y, CL_W, "actor", "Linux host", "server01",
                 ["key in its TPM: server01.tss",
                  "optional TPM attestation",
                  "signs with `aws_signing_helper`"], icon="server")
    d.card(510, CL_Y, CL_W, "actor", "Mac client", "mac",
                 ["key in its Secure Enclave: mac.key",
                  "signs with",
                  "`enclave-ca credential-process`"], icon="laptop")
    # more clients like these
    for i in range(3):
        d.add(f'<circle cx="{448 + i * 12}" cy="{CL_Y + lin[3] / 2}" r="3.2" fill="{t["muted"]}"/>')

    ca_bot = ca[1] + ca[3]
    mid = (ca_bot + CL_Y) / 2
    for (down_x, up_x, side, host) in ((196, 222, "left", "server01"), (548, 522, "right", "mac")):
        d.arrow([(up_x, CL_Y), (up_x, ca_bot + 3)])
        d.arrow([(down_x, ca_bot), (down_x, CL_Y - 3)])
        out, inn = ("end", "start") if side == "left" else ("start", "end")
        sgn = -1 if side == "left" else 1
        d.text(down_x + sgn * 12, mid + 5, f"{host}.crt leaf", anchor=out, color=t["ink"])
        d.text(up_x - sgn * 12, mid + 5, f"{host}.csr", anchor=inn, color=t["ink"])

    # ca.crt straight up into the trust anchor
    d.arrow([(270, ca[1]), (270, ta[1] + ta[3] + 3)])
    d.text(284, (224 + 252 + ca[1]) / 2 + 6, "ca.crt, registered once", color=t["ink"])  # between the AWS band and the CA Mac

    # Mac client <-> Roles Anywhere, straight up past the CA Mac
    ra_bot = ra[1] + ra[3]
    x_up, x_down = 742, 770
    d.arrow([(x_up, CL_Y), (x_up, ra_bot + 3)])
    d.arrow([(x_down, ra_bot), (x_down, CL_Y - 3)])
    my = (ra_bot + CL_Y) / 2 + 60
    d.lines(x_up - 12, my - 14, ["`rolesanywhere:`", "`CreateSession`"], anchor="end", color=t["ink"], lh=20)
    d.text(x_up - 12, my + 30, "signed by its key", anchor="end", size=SMALL)
    d.lines(x_down + 12, my - 14, ["temporary", "AWS creds"], color=t["ink"], lh=20)
    d.lines(x_down + 12, my + 30, ["key ID, secret,", "session token"], size=SMALL, lh=19)

    d.lines(50, CL_Y + lin[3] + 56,
            ["The Linux host makes the same CreateSession call.",
             "The Mac client can be the same Mac that holds the CA key."], size=LABEL, lh=24)
    return d.end()


def credential_cache(theme):
    """docs/design.md, "Credential cache": the --cache flowchart. Everything on the Mac sits in one box;
    Roles Anywhere is the one call that leaves it."""
    W = 1110
    d = D(W, 2000, theme)
    t = d.t
    d.frame("Credential cache",
            ["`credential-process --cache` trades a prompt per command",
             "for a prompt per session."])
    d.legend(60, 186, [("actor", "something that runs"), ("data", "data at rest"),
                       ("solid", "then / writes"), ("dashed", "reads")], row_layout=True)
    region_at = len(d.out)  # the Mac box goes here, behind everything, once its height is known

    A, B, C, R = (42, 224), (300, 580), (606, 804), (874, 1080)
    RX0, RX1, RY0 = 20, 826, 232
    bx, bw = B[0], B[1] - B[0]
    bc = (B[0] + B[1]) / 2

    def down(y0, y1, label=None):
        d.arrow([(bc, y0), (bc, y1 - 3)])
        if label:
            d.text(bc + 14, (y0 + y1) / 2 + 5, label, size=SMALL)

    def bottom(c):
        return c[1] + c[3]

    cli = d.card(bx, RY0 + 56, bw, "actor", None, "AWS CLI", ["runs `credential_process`", "on every command"],
                 icon=False)
    y = bottom(cli) + 46
    down(bottom(cli), y)
    ec = d.card(bx, y, bw, "actor", None, "`enclave-ca`", ["`credential-process --cache`"], icon=False, pad=20)
    kc_h = 168
    kc = d.card(A[0], ec[1] + ec[3] / 2 - kc_h / 2, A[1] - A[0], "data", "never synced", "login keychain",
                ["one entry per", "hash of every", "input"], pad=20, h=kc_h)
    ly = ec[1] + ec[3] / 2
    d.arrow([(bx, ly), (A[1] + 3, ly)], style="dashed")
    d.text((bx + A[1]) / 2, ly - 10, "looks up", anchor="middle", size=SMALL)

    # fresh?
    dy = bottom(ec) + 46 + 56
    down(bottom(ec), dy - 56)
    d.diamond(bc, dy, 104, 56, ["fresh entry?", "10+ min left"])
    hit = d.terminal(C[0], dy - 32, C[1] - C[0], "cached creds", "to the AWS CLI", icon="braces")
    d.text((C[0] + C[1]) / 2, bottom(hit) + 26, "no prompt", anchor="middle", size=SMALL, color=t["accent"], weight=600)
    d.arrow([(bc + 104, dy), (C[0] - 3, dy)])
    d.text((bc + 104 + C[0]) / 2, dy - 10, "hit", anchor="middle", color=t["ink"])

    # miss or stale: sign on the Mac, then the one call out to AWS
    y = dy + 56 + 50
    down(dy + 56, y, "miss or stale")
    se = d.card(bx, y, bw, "actor", "Secure Enclave", "sign CreateSession", ["with mac.key"],
                pills=[("prompts unless access is `none`",)], icon=False)
    y3 = bottom(se) + 46
    down(bottom(se), y3)
    wr = d.card(bx, y3, bw, "actor", None, "write the entry", ["reused until 10 min", "before `Expiration`"],
                icon=False)
    d.card(R[0], se[1], R[1] - R[0], "actor", "AWS", "Roles Anywhere",
                ["checks the chain", "and trust policy"], h=bottom(wr) - se[1], icon="role", pad=20)
    y1 = se[1] + se[3] / 2
    d.arrow([(B[1], y1), (R[0] - 3, y1)])
    d.text((B[1] + R[0]) / 2, y1 - 12, "`rolesanywhere:CreateSession`", anchor="middle", color=t["ink"])
    y2 = wr[1] + wr[3] / 2
    d.arrow([(R[0], y2), (B[1] + 3, y2)])
    d.text((B[1] + R[0]) / 2, y2 - 12, "temporary AWS creds", anchor="middle", color=t["ink"])

    # write back to the keychain: left, then up
    wy = wr[1] + wr[3] / 2
    kx = (A[0] + A[1]) / 2
    d.arrow([(bx, wy), (kx, wy), (kx, bottom(kc) + 3)])
    d.text(kx + 14, (wy + bottom(kc)) / 2, "writes", size=SMALL)
    y4 = bottom(wr) + 46
    down(bottom(wr), y4)
    end = d.terminal(bx, y4, bw, "fresh creds", "to the AWS CLI", icon="braces")

    RY1 = bottom(end) + 34
    d.out[region_at:region_at] = []
    region = D(W, 10, theme)
    region.region(RX0, RY0, RX1 - RX0, RY1 - RY0, "mac", icon="laptop")
    d.out[region_at:region_at] = region.out

    yf = RY1 + 48
    d.lines(RX0 + 4, yf, ["A cache read or write failure is reported on stderr",
                          "and falls back to a fresh CreateSession."], size=LABEL, lh=24)
    d.set_height(yf + 50)
    return d.end()


def attestation(theme):
    """docs/tpm-attestation.md: enrollment and issuance as a sequence diagram."""
    W = 1000
    d = D(W, 2000, theme)
    t = d.t
    d.frame("TPM attestation",
            ["Enrollment pins server01's TPM to the CA Mac once. Issuance proves",
             "each client key lives in that TPM before the CA Mac asks for Touch ID."])
    d.legend(60, 186, [("actor", "something that runs"), ("solid", "sends"),
                       ("accent", "needs a secure channel")], row_layout=True)
    back_at = len(d.out)  # regions and lifelines go here, behind everything, once the height is known

    TPM, HOST, CA = 150, 430, 805
    SRV, CAR = (20, 590), (630, 980)  # server01 box, CA Mac box
    PW = 220
    top = 236
    head_y = top + 52
    heads = [d.card(TPM - PW / 2, head_y, PW, "actor", None, "TPM", icon="chip"),
             d.card(HOST - PW / 2, head_y, PW, "actor", None, "`tpm-attest.sh`", icon=False),
             d.card(CA - PW / 2, head_y, PW, "actor", None, "`enclave-ca`", icon=False)]
    y = head_y + heads[0][3]

    def msg(y, frm, to, label, accent=False, sub=None):
        d.arrow([(frm, y), (to + (6 if to < frm else -6), y)], color="accent" if accent else "ink")
        mx = (frm + to) / 2
        d.text(mx, y - 11, label, anchor="middle", color=t["accent"] if accent else t["ink"])
        if sub:
            d.text(mx, y + 23, sub, anchor="middle", size=SMALL)

    def cmd(x, y, s):
        """A command pill sitting on a lifeline."""
        w = len(s) * 8.6 + 34
        d.add(f'<rect x="{x - w / 2}" y="{y}" width="{w}" height="34" rx="10" fill="{t["actor"]}"/>')
        d.text(x, y + 22.5, f"`{s}`", anchor="middle", size=15, color=t["actor_title"], weight=600, mono_size=14.5)
        return y + 34

    def note(x, y, title, body, w=320, pills=()):
        c = d.card(x - w / 2, y, w, "actor", None, title, body, icon=False, title_size=16, pad=20, pills=pills)
        return c[1] + c[3]

    # Enrollment
    y += 64
    d.phase(SRV[0] + 22, y, "Enrollment", "once per TPM, over a secure channel such as SSH", bg=t["region"])
    y += 34
    y = cmd(HOST, y, "tpm-attest.sh keys") + 40
    msg(y, HOST, TPM, "create the AK under the EK")
    y += 50
    msg(y, TPM, HOST, "ak.pub, ak.priv, ek.crt")
    y += 58
    msg(y, HOST, CA, "ek.crt, ak.pub", accent=True)
    d.badge((HOST + CA) / 2, y + 26, "secure channel")
    y += 56
    y = note(CA, y, "`enclave-ca tpm-challenge`",
             ["checks the AK's attributes, then",
              "MakeCredential: a secret wrapped",
              "to the EK, bound to the AK's name;",
              "writes server01.tpm.json (pending)"]) + 48
    msg(y, CA, HOST, "server01.challenge")
    y += 30
    y = cmd(HOST, y, "tpm-attest.sh activate") + 40
    msg(y, HOST, TPM, "ActivateCredential")
    y += 50
    msg(y, TPM, HOST, "the secret, only if this TPM")
    d.text((TPM + HOST) / 2, y + 23, "holds that EK and AK", anchor="middle", size=SMALL)
    y += 72
    msg(y, HOST, CA, "server01.activated", sub="the secret, sent back")
    y += 52
    y = note(CA, y, "`enclave-ca tpm-enroll`", ["the secret's hash matches:", "enrollment complete"])

    # Issuance
    y += 70
    d.phase(SRV[0] + 22, y, "Issuance", "once per client key", bg=t["region"])
    y += 34
    y = cmd(HOST, y, "tpm-attest.sh certify") + 40
    msg(y, HOST, TPM, "Certify the client key with the AK")
    y += 50
    msg(y, TPM, HOST, "`TPMS_ATTEST` + AK signature")
    y += 58
    msg(y, HOST, CA, "server01.attest.pem + .csr", sub="public area, statement, signature")
    y += 56
    y = note(CA, y, "`enclave-ca sign`",
             ["checks, before any prompt:",
              "1. enrollment complete for this CN",
              "2. AK signature verifies",
              "3. starts with `TPM_GENERATED_VALUE`",
              "  and is a certify statement",
              "4. name = hash of the public area",
              "5. `fixedTPM`, `fixedParent`,",
              "  `sensitiveDataOrigin`, `sign`",
              "6. key = the CSR's public key"],
             pills=[("then Touch ID",)]) + 48
    msg(y, CA, HOST, "server01.crt")
    d.text((HOST + CA) / 2, y + 24, "`OU=tpm-ek-pinned, CN=server01`", anchor="middle", size=SMALL, color=t["ink"])

    RB = y + 50
    H = RB + 30
    d.set_height(H)
    back = D(W, H, theme)
    back.region(SRV[0], top, SRV[1] - SRV[0], RB - top, "server01", icon="server")
    back.region(CAR[0], top, CAR[1] - CAR[0], RB - top, "CA Mac", icon="laptop")
    back.out += [f'<path d="M{x},{head_y + 30} V{RB - 20}" stroke="{t["faint"]}" stroke-width="1.6" stroke-dasharray="5 6"/>'
                 for x in (TPM, HOST, CA)]
    d.out[back_at:back_at] = back.out
    return d.end()


DIAGRAMS = {"overview": overview, "credential-cache": credential_cache, "attestation": attestation}


def main():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    ap = argparse.ArgumentParser(description="Draw the docs diagrams and render them to PNG.")
    ap.add_argument("names", nargs="*", metavar="NAME",
                    help=f"diagrams to draw (default: all of {', '.join(DIAGRAMS)})")
    ap.add_argument("--out-dir", default=os.path.join(root, "docs", "img"), help="where the PNGs go")
    ap.add_argument("--svg-dir", help="keep the intermediate SVGs here (default: a temporary directory)")
    ap.add_argument("--no-png", action="store_true", help="only draw the SVGs; needs --svg-dir")
    args = ap.parse_args()
    unknown = [n for n in args.names if n not in DIAGRAMS]
    if unknown:
        ap.error(f"unknown diagram {', '.join(unknown)}; choose from {', '.join(DIAGRAMS)}")
    if args.no_png and not args.svg_dir:
        ap.error("--no-png needs --svg-dir")
    rsvg = None if args.no_png else shutil.which("rsvg-convert")
    if not args.no_png and not rsvg:
        sys.exit("rsvg-convert not found; install librsvg (brew install librsvg, apt install librsvg2-bin)")

    with tempfile.TemporaryDirectory() as tmp:
        svg_dir = args.svg_dir or tmp
        os.makedirs(svg_dir, exist_ok=True)
        os.makedirs(args.out_dir, exist_ok=True)
        for name in args.names or DIAGRAMS:
            for theme in ("light", "dark"):
                suffix = "" if theme == "light" else "-dark"
                svg = os.path.join(svg_dir, f"{name}{suffix}.svg")
                with open(svg, "w") as f:
                    f.write(DIAGRAMS[name](theme))
                if args.svg_dir:
                    print(svg)
                if rsvg:
                    png = os.path.join(args.out_dir, f"{name}{suffix}@2x.png")
                    subprocess.run([rsvg, "-z", "2", svg, "-o", png], check=True)
                    print(png)


if __name__ == "__main__":
    main()

"""Generate isometric low-poly SVG icons matching frontend_svg/ (polygon faces,
gradient shading, glow filter, blurred drop shadow, 512x512).

Also copies the three original icons with their <defs> ids namespaced so all
icons can be inlined on one page without id collisions.

    python frontend/tools/make_icons.py
"""
from __future__ import annotations

import math
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "frontend_svg"
OUT = ROOT / "frontend" / "public" / "icons"

C30, S30 = math.cos(math.radians(30)), 0.5


def P(x, y, z):
    """World (x right-back, y left-back, z up) -> screen."""
    return ((x - y) * C30, (x + y) * S30 - z)


def pts(seq):
    return " ".join(f"{a:.2f},{b:.2f}" for a, b in seq)


def shade(hex_, k):
    h = hex_.lstrip("#")
    r, g, b = (int(h[i:i + 2], 16) for i in (0, 2, 4))
    if k >= 0:
        r, g, b = (int(c + (255 - c) * k) for c in (r, g, b))
    else:
        r, g, b = (int(c * (1 + k)) for c in (r, g, b))
    return f"#{r:02x}{g:02x}{b:02x}"


class Icon:
    def __init__(self, ns: str):
        self.ns = ns
        self.defs: list[str] = []
        self.body: list[str] = []
        self.grad_n = 0
        self.xs: list[float] = []
        self.ys: list[float] = []

    # ---- defs
    def grad(self, a, b, diag=False):
        self.grad_n += 1
        gid = f"{self.ns}-g{self.grad_n}"
        x2, y2 = ("1", "1") if diag else ("0", "1")
        self.defs.append(
            f'<linearGradient id="{gid}" x1="0" y1="0" x2="{x2}" y2="{y2}">'
            f'<stop offset="0" stop-color="{a}"/><stop offset="1" stop-color="{b}"/></linearGradient>')
        return f"url(#{gid})"

    def _track(self, seq):
        for a, b in seq:
            self.xs.append(a)
            self.ys.append(b)

    # ---- primitives
    def poly(self, seq, fill, extra=""):
        self._track(seq)
        self.body.append(f'<polygon points="{pts(seq)}" fill="{fill}" {extra}/>')

    def line(self, seq, color, w=2.0, glow=True, dash=None, cap="round"):
        xs, ys = [a for a, _ in seq], [b for _, b in seq]
        if glow and (max(xs) - min(xs) < 1 or max(ys) - min(ys) < 1):
            # a zero-width/height bbox collapses the filter region; nudge it
            seq = list(seq) + [(seq[-1][0] + 0.6, seq[-1][1] + 0.6)]
        self._track(seq)
        f = f' filter="url(#{self.ns}-glow)"' if glow else ""
        d = f' stroke-dasharray="{dash}"' if dash else ""
        self.body.append(
            f'<polyline points="{pts(seq)}" fill="none" stroke="{color}" stroke-width="{w}" '
            f'stroke-linecap="{cap}" stroke-linejoin="round"{d}{f}/>')

    def dot(self, x, y, z, r, color, glow=True):
        sx, sy = P(x, y, z)
        self._track([(sx - r, sy - r), (sx + r, sy + r)])
        f = f' filter="url(#{self.ns}-glow)"' if glow else ""
        self.body.append(f'<circle cx="{sx:.2f}" cy="{sy:.2f}" r="{r}" fill="{color}"{f}/>')

    def shadow(self, x, y, w, d, pad=10):
        seq = [P(x - pad, y - pad, 0), P(x + w + pad, y - pad, 0), P(x + w + pad, y + d + pad, 0),
               P(x - pad, y + d + pad, 0)]
        seq = [(a + 6, b + 10) for a, b in seq]
        self._track(seq)
        self.body.append(f'<polygon points="{pts(seq)}" fill="#000" opacity="0.25" filter="url(#{self.ns}-soft)"/>')

    def box(self, x, y, z, w, d, h, color, top=None, grad=True):
        """Visible faces: top, front-left (y+d), front-right (x+w)."""
        top = top or shade(color, 0.25)
        t = [P(x, y, z + h), P(x + w, y, z + h), P(x + w, y + d, z + h), P(x, y + d, z + h)]
        fl = [P(x, y + d, z), P(x + w, y + d, z), P(x + w, y + d, z + h), P(x, y + d, z + h)]
        fr = [P(x + w, y, z), P(x + w, y + d, z), P(x + w, y + d, z + h), P(x + w, y, z + h)]
        if grad:
            self.poly(fl, self.grad(shade(color, 0.0), shade(color, -0.3)))
            self.poly(fr, self.grad(shade(color, -0.25), shade(color, -0.5)))
            self.poly(t, self.grad(shade(top, 0.15), top, diag=True))
        else:
            self.poly(fl, color)
            self.poly(fr, shade(color, -0.3))
            self.poly(t, top)
        return t, fl, fr

    def cyl(self, cx, cy, z, r, h, color, top=None, n=36):
        top = top or shade(color, 0.3)
        ring = lambda zz, angs: [P(cx + r * math.cos(a), cy + r * math.sin(a), zz) for a in angs]
        # side faces the viewer where cos a + sin a > 0, i.e. a in [-45deg, 135deg]
        half = [math.radians(-45 + 180 * i / (n // 2)) for i in range(n // 2 + 1)]
        tp = ring(z + h, [2 * math.pi * i / n for i in range(n)])
        side = ring(z, half) + ring(z + h, list(reversed(half)))
        self.poly(side, self.grad(shade(color, 0.05), shade(color, -0.45), diag=True))
        self.poly(tp, self.grad(shade(top, 0.2), top, diag=True))
        return tp

    def face_pts(self, plane, origin, uv):
        """Map 2-D points onto a face. plane 'fl' (x,z at y=const), 'fr' (y,z at x=const), 'top' (x,y at z=const)."""
        ox, oy, oz = origin
        out = []
        for u, v in uv:
            if plane == "fl":
                out.append(P(ox + u, oy, oz + v))
            elif plane == "fr":
                out.append(P(ox, oy + u, oz + v))
            else:
                out.append(P(ox + u, oy + v, oz))
        return out

    def circle_on(self, plane, origin, cx, cy, r, n=32):
        return self.face_pts(plane, origin, [(cx + r * math.cos(2 * math.pi * i / n),
                                              cy + r * math.sin(2 * math.pi * i / n)) for i in range(n + 1)])

    def platform(self, x, y, w, d, h, color, edge):
        self.shadow(x, y, w, d)
        t, _, _ = self.box(x, y, 0, w, d, h, color)
        self.line(t + [t[0]], edge, 1.2, glow=True)
        return h

    # ---- render
    def svg(self) -> str:
        pad = 14
        x0, x1 = min(self.xs) - pad, max(self.xs) + pad
        y0, y1 = min(self.ys) - pad, max(self.ys) + pad
        s = max(x1 - x0, y1 - y0)
        cx, cy = (x0 + x1) / 2, (y0 + y1) / 2
        vb = f"{cx - s / 2:.2f} {cy - s / 2:.2f} {s:.2f} {s:.2f}"
        filt = (f'<filter id="{self.ns}-glow" x="-60%" y="-60%" width="220%" height="220%"><feGaussianBlur stdDeviation="2.2" result="b"/>'
                f'<feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter>'
                f'<filter id="{self.ns}-soft" x="-30%" y="-30%" width="160%" height="160%"><feGaussianBlur stdDeviation="5"/></filter>')
        return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="{vb}" width="512" height="512">\n'
                f'<defs>{filt}{"".join(self.defs)}</defs>\n' + "\n".join(self.body) + "\n</svg>\n")


# ------------------------------------------------------------------ icons
def adversary():
    I = Icon("adv")
    h = I.platform(0, 0, 120, 120, 10, "#1b1f2a", "#ff6a2b")
    # laptop base + screen
    I.box(22, 30, h, 76, 58, 5, "#2a2f3c", top="#3b4252")
    I.box(22, 30, h + 5, 76, 6, 52, "#20242f", top="#3b4252")
    scr = I.face_pts("fl", (22, 36.01, h + 5), [(5, 5), (71, 5), (71, 48), (5, 48)])
    I.poly(scr, I.grad("#ff8a4c", "#a8240f"))
    # reticle glyph on screen
    I.line(I.circle_on("fl", (22, 36.02, h + 5), 38, 26.5, 13), "#fff4ea", 2.4)
    I.line(I.face_pts("fl", (22, 36.02, h + 5), [(38, 9), (38, 44)]), "#fff4ea", 1.8)
    I.line(I.face_pts("fl", (22, 36.02, h + 5), [(20, 26.5), (56, 26.5)]), "#fff4ea", 1.8)
    I.dot(22 + 38, 36.02, h + 5 + 26.5, 2.6, "#ffffff")
    # keyboard keys
    for i in range(6):
        for j in range(3):
            k = I.face_pts("top", (30 + i * 11, 48 + j * 11, h + 5.01), [(0, 0), (8, 0), (8, 8), (0, 8)])
            I.poly(k, "#4a5163")
    # malicious packets flying out
    I.line([P(96, 30, h + 50), P(110, 14, h + 62), P(126, 2, h + 78), P(142, -10, h + 96)], "#ff6a2b", 1.6, dash="4 4")
    for (x, y, z) in [(106, 10, h + 56), (122, -2, h + 72), (138, -14, h + 90)]:
        I.box(x, y, z, 9, 9, 9, "#ff5a1f", top="#ffb08a")
    return I


def iot():
    I = Icon("iot")
    h = I.platform(0, 0, 130, 130, 10, "#18303a", "#22d3ee")
    hub = (65, 65)
    # camera
    I.box(14, 14, h, 26, 22, 18, "#cfd8e3", top="#f1f5f9")
    I.cyl(27, 36.5, h + 6, 6, 1, "#0f172a")
    I.dot(27, 37, h + 9, 2.4, "#22d3ee")
    # bulb
    I.cyl(100, 22, h, 7, 8, "#94a3b8")
    sx, sy = P(100, 22, h + 22)
    I.body.append(f'<circle cx="{sx:.2f}" cy="{sy:.2f}" r="13" fill="url(#iot-bulb)" filter="url(#iot-glow)"/>')
    I.defs.append('<radialGradient id="iot-bulb"><stop offset="0" stop-color="#fffbe6"/><stop offset="1" stop-color="#facc15"/></radialGradient>')
    I._track([(sx - 13, sy - 13), (sx + 13, sy + 13)])
    # speaker
    I.cyl(26, 102, h, 11, 26, "#334155", top="#475569")
    for k in range(3):
        I.line(I.circle_on("top", (26, 102, h + 26.01), 0, 0, 3 + 3 * k, 24), "#22d3ee", 1.0, glow=False)
    # plug
    I.box(92, 92, h, 22, 22, 14, "#e2e8f0", top="#ffffff")
    I.dot(100, 103, h + 14.1, 1.6, "#0f172a", glow=False)
    I.dot(106, 103, h + 14.1, 1.6, "#0f172a", glow=False)
    # hub + links
    I.cyl(hub[0], hub[1], h, 9, 6, "#0e7490", top="#22d3ee")
    for (x, y, z) in [(27, 25, h + 18), (100, 22, h + 10), (26, 102, h + 26), (103, 103, h + 14)]:
        I.line([P(hub[0], hub[1], h + 6), P(x, y, z)], "#67e8f9", 1.4)
        I.dot(x, y, z, 2.2, "#a5f3fc")
    return I


def gateway():
    I = Icon("gw")
    h = I.platform(0, 0, 120, 120, 10, "#151c2e", "#22d3ee")
    I.box(20, 34, h, 80, 52, 20, "#1e3a8a", top="#2b4fb5")
    for i in range(6):
        I.dot(28 + i * 11, 86.01, h + 10, 2.0, "#34d399" if i < 4 else "#22d3ee")
    for ax in (30, 60, 90):
        I.box(ax, 40, h + 20, 4, 4, 38, "#cbd5e1", top="#ffffff", grad=False)
        I.dot(ax + 2, 42, h + 60, 2.6, "#67e8f9")
    for k, r in enumerate((18, 30, 42)):
        arc = [P(60 + r * math.cos(a), 42, h + 66 + r * math.sin(a))
               for a in [math.radians(t) for t in range(30, 151, 10)]]
        I.line(arc, "#22d3ee", 2.0 - k * 0.4)
    return I


def lan():
    I = Icon("lan")
    h = I.platform(0, 0, 130, 120, 10, "#14231c", "#34d399")
    for i, x in enumerate((18, 52, 86)):
        I.box(x, 34, h, 28, 34, 70 - i * 6, "#1f2937", top="#374151")
        for s in range(5 - i):
            y0 = h + 8 + s * 12
            slot = I.face_pts("fl", (x, 68.01, 0), [(3, y0), (25, y0), (25, y0 + 8), (3, y0 + 8)])
            I.poly(slot, "#111827")
            I.dot(x + 22, 68.02, y0 + 4, 1.4, "#34d399")
            I.dot(x + 18, 68.02, y0 + 4, 1.4, "#22d3ee" if s % 2 else "#34d399")
    I.line([P(32, 90, h), P(66, 100, h), P(100, 90, h)], "#34d399", 1.6)
    return I


def sink_blocked():
    I = Icon("blk")
    h = I.platform(0, 0, 110, 110, 10, "#2a1114", "#ef4444")
    I.box(25, 25, h, 60, 60, 30, "#7f1d1d", top="#b91c1c")
    o = (25, 25, h + 30.01)
    I.line(I.circle_on("top", o, 30, 30, 20), "#fecaca", 5)
    I.line(I.face_pts("top", o, [(16, 16), (44, 44)]), "#fecaca", 5)
    I.line(I.face_pts("fl", (25, 85.01, h), [(4, 26), (56, 26)]), "#ef4444", 2)
    return I


def sink_quarantine():
    I = Icon("qua")
    h = I.platform(0, 0, 110, 110, 10, "#2a2110", "#facc15")
    I.box(22, 28, h, 66, 54, 40, "#a16207", top="#ca8a04")
    o = (22, 82.01, h)
    for k in range(5):
        x = 4 + k * 13
        I.poly(I.face_pts("fl", o, [(x, 2), (x + 6, 2), (x + 14, 10), (x + 8, 10)]), "#111827")
    # lock
    I.poly(I.face_pts("fl", o, [(24, 14), (42, 14), (42, 30), (24, 30)]), "#fde68a")
    I.line(I.face_pts("fl", o, [(27, 30), (27, 35), (30, 38), (36, 38), (39, 35), (39, 30)]), "#fde68a", 2.6)
    I.dot(22 + 33, 82.02, h + 22, 1.8, "#111827", glow=False)
    return I


def sink_alert():
    I = Icon("alr")
    h = I.platform(0, 0, 110, 110, 10, "#26112a", "#e879f9")
    I.cyl(55, 55, h, 26, 10, "#581c87", top="#7e22ce")
    I.cyl(55, 55, h + 10, 16, 22, "#c026d3", top="#f0abfc")
    for k in range(8):
        a = 2 * math.pi * k / 8
        I.line([P(55 + 22 * math.cos(a), 55 + 22 * math.sin(a), h + 26),
                P(55 + 38 * math.cos(a), 55 + 38 * math.sin(a), h + 34)], "#f5d0fe", 1.6)
    I.dot(55, 55, h + 36, 4, "#ffffff")
    return I


def pipeline():
    I = Icon("pipe")
    h = I.platform(0, 0, 130, 110, 10, "#151a2e", "#8b5cf6")
    for k in range(3):
        I.cyl(40, 55, h + k * 16, 24, 13, "#4c1d95" if k % 2 else "#5b21b6", top="#8b5cf6")
    I.line([P(64, 55, h + 30), P(80, 55, h + 30), P(92, 55, h + 20)], "#c4b5fd", 2)
    # funnel to slab
    I.box(88, 38, h, 28, 34, 10, "#312e81", top="#6366f1")
    for k in range(3):
        I.dot(96 + k * 7, 72.01, h + 5, 1.6, "#a5b4fc")
    return I


def rules():
    I = Icon("rul")
    h = I.platform(0, 0, 110, 110, 10, "#10202a", "#22d3ee")
    I.box(26, 22, h, 58, 70, 8, "#0f3a4a", top="#155e75")
    o = (26, 22, h + 8.01)
    for k in range(5):
        y = 10 + k * 12
        I.poly(I.face_pts("top", o, [(8, y), (14, y), (14, y + 6), (8, y + 6)]), "#22d3ee")
        I.line(I.face_pts("top", o, [(9, y + 3), (11, y + 5), (14, y)]), "#ecfeff", 1.2, glow=False)
        I.line(I.face_pts("top", o, [(20, y + 3), (50 - (k % 3) * 8, y + 3)]), "#a5f3fc", 1.6, glow=False)
    return I


def training():
    I = Icon("trn")
    h = I.platform(0, 0, 110, 110, 10, "#1a1430", "#8b5cf6")
    for k in range(3):
        z = h + 4 + k * 18
        I.box(24, 24, z, 62, 62, 5, "#3b2a7a", top="#6d4fd8")
        for i in range(3):
            for j in range(3):
                I.dot(34 + i * 20, 34 + j * 20, z + 5.1, 2.0, "#e9d5ff" if k == 2 else "#a78bfa", glow=k == 2)
    I.line([P(55, 55, h + 9), P(55, 55, h + 46)], "#c4b5fd", 1.4, dash="3 3")
    return I


def paper():
    I = Icon("ppr")
    h = I.platform(0, 0, 110, 110, 10, "#1c1a14", "#fbbf24")
    for k in range(3):
        I.box(26 - k * 3, 20 + k * 3, h + k * 4, 56, 72, 4, "#e5e7eb", top="#ffffff", grad=False)
    o = (20, 26, h + 12.01)
    for k in range(6):
        y = 12 + k * 8
        I.line(I.face_pts("top", o, [(8, y), (46 - (k % 2) * 12, y)]), "#9ca3af", 1.6, glow=False)
    I.poly(I.face_pts("top", o, [(38, 52), (50, 52), (50, 70), (44, 64), (38, 70)]), "#f59e0b")
    return I


def namespace_original(name: str, ns: str):
    text = (SRC / name).read_text(encoding="utf-8")
    ids = set(re.findall(r'id="([^"]+)"', text))
    for i in sorted(ids, key=len, reverse=True):
        text = re.sub(rf'id="{re.escape(i)}"', f'id="{ns}-{i}"', text)
        text = re.sub(rf'url\(#{re.escape(i)}\)', f'url(#{ns}-{i})', text)
    return text


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    for src, dst, ns in [("validator.svg", "validator.svg", "val"), ("IDS.svg", "ids.svg", "ids"),
                         ("discriminator.svg", "discriminator.svg", "dis")]:
        (OUT / dst).write_text(namespace_original(src, ns), encoding="utf-8")
    makers = {"adversary": adversary, "iot": iot, "gateway": gateway, "lan": lan,
              "sink-blocked": sink_blocked, "sink-quarantine": sink_quarantine, "sink-alert": sink_alert,
              "pipeline": pipeline, "rules": rules, "training": training, "paper": paper}
    for name, fn in makers.items():
        svg = fn().svg()
        (OUT / f"{name}.svg").write_text(svg, encoding="utf-8")
        (SRC / f"{name}.svg").write_text(svg, encoding="utf-8")
    print("icons:", sorted(p.name for p in OUT.glob("*.svg")))


if __name__ == "__main__":
    main()

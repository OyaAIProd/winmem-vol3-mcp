"""Generate architecture diagram for winmem-vol3-mcp (DFRWS paper figure)."""

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch
import os

# ── Colour palette (muted, print-friendly) ────────────────────
PAL = {
    "client":  ("#EDE9FE", "#7C3AED"),
    "server":  ("#DBEAFE", "#2563EB"),
    "session": ("#D1FAE5", "#059669"),
    "plugins": ("#FEF3C7", "#D97706"),
    "vol3":    ("#FEE2E2", "#DC2626"),
    "image":   ("#F3F4F6", "#6B7280"),
}
TXT = "#1F2937"
SUB = "#6B7280"

fig, ax = plt.subplots(figsize=(11, 14.5))
ax.set_xlim(0, 11)
ax.set_ylim(0.5, 18.5)
ax.axis("off")
fig.patch.set_facecolor("white")

CX = 5.5          # centre x
BW = 9.0           # main box width
BX = CX - BW / 2   # main box left x


def rbox(x, y, w, h, key, lw=2):
    fc, ec = PAL[key]
    ax.add_patch(FancyBboxPatch(
        (x, y), w, h, boxstyle="round,pad=0.12",
        fc=fc, ec=ec, lw=lw, zorder=1))


def wbox(x, y, w, h, ec, lw=1):
    ax.add_patch(FancyBboxPatch(
        (x, y), w, h, boxstyle="round,pad=0.08",
        fc="#FFFFFF", ec=ec, lw=lw, zorder=2))


def T(x, y, s, fs=11, bold=False, color=TXT, **kw):
    defaults = dict(ha="center", va="center", fontsize=fs,
                    fontweight="bold" if bold else "normal",
                    color=color, zorder=5)
    defaults.update(kw)
    ax.text(x, y, s, **defaults)


def arrow(x, y1, y2, text=None, bidir=False):
    style = "<->" if bidir else "->"
    ax.annotate("", xy=(x, y2), xytext=(x, y1),
                arrowprops=dict(arrowstyle=style, color="#374151", lw=2),
                zorder=3)
    if text:
        T(x + 0.15, (y1 + y2) / 2, text, fs=8.5, color=SUB,
          fontstyle="italic", ha="left")


# ─── 1  Claude Desktop ────────────────────────────────────────
rbox(BX, 16.2, BW, 1.3, "client")
T(CX, 17.05, "Claude Desktop", fs=14, bold=True)
T(CX, 16.55, "MCP Client  \u00b7  Natural-language forensic queries",
  fs=9, color=SUB)

arrow(CX, 16.2, 15.5, "MCP Protocol (stdio, JSON-RPC)", bidir=True)

# ─── 2  MCP Server ────────────────────────────────────────────
rbox(BX, 13.3, BW, 2.2, "server")
T(CX, 15.15, "mcp_server.py", fs=13, bold=True)
T(CX, 14.65, 'FastMCP  "winmem-vol3-mcp"', fs=9.5, color=SUB)

wbox(BX + 0.4, 13.5, BW - 0.8, 0.9, PAL["server"][1])
T(CX, 14.1, "79 MCP Tool Endpoints", fs=10, bold=True)
T(CX, 13.7,
  "Three-layer docstrings:  trigger patterns  \u00b7  return schema"
  "  \u00b7  forensic context", fs=7.5, color=SUB)

arrow(CX, 13.3, 12.6)

# ─── 3  Session ───────────────────────────────────────────────
rbox(BX, 9.3, BW, 3.3, "session")
T(CX, 12.25, "session.py", fs=13, bold=True)
T(CX, 11.75,
  "Single-image analysis session  (one Context per image, reused)",
  fs=8.5, color=SUB)

ec_s = PAL["session"][1]
cw, cg = 2.5, 0.3
cx0 = BX + 0.5
cy = 10.5

wbox(cx0, cy, cw, 0.9, ec_s)
T(cx0 + cw / 2, cy + 0.55, "Context", fs=9, bold=True)
T(cx0 + cw / 2, cy + 0.2, "(built once, reused)", fs=7, color=SUB)

wbox(cx0 + cw + cg, cy, cw, 0.9, ec_s)
T(cx0 + cw + cg + cw / 2, cy + 0.55, "Result Cache", fs=9, bold=True)
T(cx0 + cw + cg + cw / 2, cy + 0.2, "(per-plugin, per-arg)", fs=7, color=SUB)

cw3 = 2.8
wbox(cx0 + 2 * (cw + cg), cy, cw3, 0.9, ec_s)
T(cx0 + 2 * (cw + cg) + cw3 / 2, cy + 0.55, "Config Cache",
  fs=9, bold=True)
T(cx0 + 2 * (cw + cg) + cw3 / 2, cy + 0.2, "{image}.vol3cfg.json",
  fs=7, color=SUB)

wbox(BX + 0.5, 9.5, BW - 1.0, 0.7, ec_s)
T(CX, 9.85,
  "FileHandler (VOL_DUMP_DIR)  \u2014  dump plugins write extracted binaries",
  fs=8, color=SUB)

arrow(CX, 9.3, 8.6)

# ─── 4  Plugin Wrappers ──────────────────────────────────────
rbox(BX, 5.2, BW, 3.4, "plugins")
T(CX, 8.25, "plugins/  \u2014  13 category modules \u2192 PLUGIN_MAP",
  fs=12, bold=True)

modules = [
    ["process", "memory", "network", "kernel", "malware"],
    ["module", "file", "registry", "service", "desktop"],
    ["console", "security", "sysinfo"],
]
mw, mh, mg = 1.5, 0.5, 0.12
mx0 = BX + 0.5
my0 = 7.4
ec_p = PAL["plugins"][1]

for ri, row in enumerate(modules):
    for ci, mod in enumerate(row):
        mx = mx0 + ci * (mw + mg)
        my = my0 - ri * (mh + mg)
        wbox(mx, my, mw, mh, ec_p)
        T(mx + mw / 2, my + mh / 2, mod, fs=8)

T(CX, 5.5,
  "_common.py: TreeGrid \u2192 typed dicts   \u00b7   "
  "_file_handler.py: DumpFileHandler",
  fs=8, color=SUB)

arrow(CX, 5.2, 4.5, "direct Python import (same process, no subprocess)")

# ─── 5  Volatility3 ──────────────────────────────────────────
rbox(BX, 3.1, BW, 1.4, "vol3")
T(CX, 3.95, "volatility3  v2.27.0", fs=13, bold=True)
T(CX, 3.4,
  "automagic  \u00b7  contexts  \u00b7  renderers  \u00b7  TreeGrid  \u00b7  ISF symbols",
  fs=9, color=SUB)

arrow(CX, 3.1, 2.4)

# ─── 6  Memory Image ─────────────────────────────────────────
iw = 5
rbox(CX - iw / 2, 1.3, iw, 1.1, "image")
T(CX, 1.95, "Windows Memory Image", fs=11, bold=True)
T(CX, 1.55, ".vmem  /  .raw  /  .dmp", fs=9, color=SUB)

# ── Save ──────────────────────────────────────────────────────
os.makedirs("png", exist_ok=True)
fig.savefig("png/architecture.png", dpi=200, bbox_inches="tight",
            facecolor="white", edgecolor="none")
plt.close()
print("Saved png/architecture.png")

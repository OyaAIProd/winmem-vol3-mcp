"""Desktop / GUI plugin wrappers (windowstations, desktops, deskscan)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from volatility3.plugins.windows import deskscan, desktops, windowstations

from plugins._common import parse_treegrid, run_plugin

if TYPE_CHECKING:
    from session import Session


def run_windowstations(session: Session) -> dict:
    """Run windows.windowstations and return WindowStation objects."""
    treegrid = run_plugin(session, windowstations.WindowStations)
    return {"plugin": "windowstations", "results": parse_treegrid(treegrid)}


PLUGIN_MAP = {
    "windowstations": run_windowstations,
}

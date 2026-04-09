"""Registry analysis plugin wrappers (hivelist, hivescan, printkey, ...)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from volatility3.plugins.windows.registry import hivelist

from plugins._common import parse_treegrid, run_plugin

if TYPE_CHECKING:
    from session import Session


def run_hivelist(session: Session) -> dict:
    """Run windows.registry.hivelist and return loaded registry hives."""
    treegrid = run_plugin(session, hivelist.HiveList)
    return {"plugin": "registry.hivelist", "results": parse_treegrid(treegrid)}


PLUGIN_MAP = {
    "registry.hivelist": run_hivelist,
}

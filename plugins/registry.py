"""Registry analysis plugin wrappers (hivelist, hivescan, printkey, ...)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from volatility3.plugins.windows.registry import hivelist, hivescan, printkey

from plugins._common import parse_treegrid, run_plugin

if TYPE_CHECKING:
    from session import Session


def run_hivelist(session: Session) -> dict:
    """Run windows.registry.hivelist and return loaded registry hives."""
    treegrid = run_plugin(session, hivelist.HiveList)
    return {"plugin": "registry.hivelist", "results": parse_treegrid(treegrid)}


def run_hivescan(session: Session) -> dict:
    """Run windows.registry.hivescan and return hives found by pool scanning."""
    treegrid = run_plugin(session, hivescan.HiveScan)
    return {"plugin": "registry.hivescan", "results": parse_treegrid(treegrid)}


def run_printkey(session: Session) -> dict:
    """Run windows.registry.printkey and return registry keys and values."""
    treegrid = run_plugin(session, printkey.PrintKey)
    return {"plugin": "registry.printkey", "results": parse_treegrid(treegrid)}


PLUGIN_MAP = {
    "registry.hivelist": run_hivelist,
    "registry.hivescan": run_hivescan,
    "registry.printkey": run_printkey,
}

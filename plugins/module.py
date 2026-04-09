"""Module / DLL analysis plugin wrappers (dlllist, ldrmodules, modules, ...)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from volatility3.plugins.windows import dlllist, ldrmodules

from plugins._common import parse_treegrid, run_plugin

if TYPE_CHECKING:
    from session import Session


def run_dlllist(session: Session) -> dict:
    """Run windows.dlllist and return loaded modules per process."""
    treegrid = run_plugin(session, dlllist.DllList)
    return {"plugin": "dlllist", "results": parse_treegrid(treegrid)}


def run_ldrmodules(session: Session) -> dict:
    """Run windows.ldrmodules and return loader module list comparison."""
    treegrid = run_plugin(session, ldrmodules.LdrModules)
    return {"plugin": "ldrmodules", "results": parse_treegrid(treegrid)}


PLUGIN_MAP = {
    "dlllist": run_dlllist,
    "ldrmodules": run_ldrmodules,
}

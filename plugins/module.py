"""Module / DLL analysis plugin wrappers (dlllist, ldrmodules, modules, ...)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from volatility3.plugins.windows import dlllist, iat, modscan, modules, verinfo

from plugins._common import parse_treegrid, run_plugin

if TYPE_CHECKING:
    from session import Session


def run_dlllist(session: Session) -> dict:
    """Run windows.dlllist and return loaded modules per process."""
    treegrid = run_plugin(session, dlllist.DllList)
    return {"plugin": "dlllist", "results": parse_treegrid(treegrid)}


def run_modules(session: Session) -> dict:
    """Run windows.modules and return loaded kernel modules."""
    treegrid = run_plugin(session, modules.Modules)
    return {"plugin": "modules", "results": parse_treegrid(treegrid)}


def run_modscan(session: Session) -> dict:
    """Run windows.modscan and return kernel modules found by pool scanning."""
    treegrid = run_plugin(session, modscan.ModScan)
    return {"plugin": "modscan", "results": parse_treegrid(treegrid)}


def run_verinfo(session: Session) -> dict:
    """Run windows.verinfo and return PE version information."""
    treegrid = run_plugin(session, verinfo.VerInfo)
    return {"plugin": "verinfo", "results": parse_treegrid(treegrid)}


def run_iat(session: Session) -> dict:
    """Run windows.iat and return Import Address Table entries."""
    treegrid = run_plugin(session, iat.IAT)
    return {"plugin": "iat", "results": parse_treegrid(treegrid)}


PLUGIN_MAP = {
    "dlllist": run_dlllist,
    "iat": run_iat,
    "modscan": run_modscan,
    "modules": run_modules,
    "verinfo": run_verinfo,
}

"""File analysis plugin wrappers (filescan, dumpfiles, symlinkscan, mutantscan)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from volatility3.plugins.windows import dumpfiles, filescan, mutantscan

from plugins._common import parse_treegrid, run_plugin

if TYPE_CHECKING:
    from session import Session


def run_filescan(session: Session) -> dict:
    """Run windows.filescan and return file objects found by pool scanning."""
    treegrid = run_plugin(session, filescan.FileScan)
    return {"plugin": "filescan", "results": parse_treegrid(treegrid)}


def run_dumpfiles(session: Session) -> dict:
    """Run windows.dumpfiles and return cached file dump metadata."""
    treegrid = run_plugin(session, dumpfiles.DumpFiles)
    return {"plugin": "dumpfiles", "results": parse_treegrid(treegrid)}


def run_mutantscan(session: Session) -> dict:
    """Run windows.mutantscan and return mutex objects found by pool scanning."""
    treegrid = run_plugin(session, mutantscan.MutantScan)
    return {"plugin": "mutantscan", "results": parse_treegrid(treegrid)}


PLUGIN_MAP = {
    "dumpfiles": run_dumpfiles,
    "filescan": run_filescan,
    "mutantscan": run_mutantscan,
}

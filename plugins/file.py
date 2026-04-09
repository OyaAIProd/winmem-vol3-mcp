"""File analysis plugin wrappers (filescan, dumpfiles, symlinkscan, mutantscan)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from volatility3.plugins.windows import filescan

from plugins._common import parse_treegrid, run_plugin

if TYPE_CHECKING:
    from session import Session


def run_filescan(session: Session) -> dict:
    """Run windows.filescan and return file objects found by pool scanning."""
    treegrid = run_plugin(session, filescan.FileScan)
    return {"plugin": "filescan", "results": parse_treegrid(treegrid)}


PLUGIN_MAP = {
    "filescan": run_filescan,
}

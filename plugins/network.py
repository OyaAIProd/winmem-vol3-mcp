"""Network analysis plugin wrappers (netscan, netstat)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from volatility3.plugins.windows import netscan

from plugins._common import parse_treegrid, run_plugin

if TYPE_CHECKING:
    from session import Session


def run_netscan(session: Session) -> dict:
    """Run windows.netscan and return network connections by pool scanning."""
    treegrid = run_plugin(session, netscan.NetScan)
    return {"plugin": "netscan", "results": parse_treegrid(treegrid)}


PLUGIN_MAP = {
    "netscan": run_netscan,
}

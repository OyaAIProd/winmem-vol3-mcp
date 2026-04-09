"""System information plugin wrappers (info, statistics, ...)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from volatility3.plugins.windows import info

from plugins._common import parse_treegrid, run_plugin

if TYPE_CHECKING:
    from session import Session


def run_info(session: Session) -> dict:
    """Run windows.info and return system information."""
    treegrid = run_plugin(session, info.Info)
    results = {}
    for row in parse_treegrid(treegrid):
        results[row["Variable"]] = row["Value"]
    return {"plugin": "info", "results": results}


PLUGIN_MAP = {
    "info": run_info,
}

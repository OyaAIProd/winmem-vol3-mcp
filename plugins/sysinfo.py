"""System information plugin wrappers (info, statistics, ...)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from volatility3.plugins.windows import crashinfo, info, statistics

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


def run_statistics(session: Session) -> dict:
    """Run windows.statistics and return memory space statistics."""
    treegrid = run_plugin(session, statistics.Statistics)
    return {"plugin": "statistics", "results": parse_treegrid(treegrid)}


def run_crashinfo(session: Session) -> dict:
    """Run windows.crashinfo and return crash dump header information."""
    treegrid = run_plugin(session, crashinfo.Crashinfo)
    return {"plugin": "crashinfo", "results": parse_treegrid(treegrid)}


PLUGIN_MAP = {
    "crashinfo": run_crashinfo,
    "info": run_info,
    "statistics": run_statistics,
}

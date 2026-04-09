"""Volatility3 Windows plugin wrappers.

Each wrapper runs a single plugin via the Python API and returns
structured results (not raw text).
"""

from __future__ import annotations

from typing import Any, TYPE_CHECKING

from volatility3.framework import automagic, interfaces
from volatility3.framework.interfaces.renderers import BaseAbsentValue
from volatility3.framework.renderers import format_hints
from volatility3.framework.interfaces.configuration import path_join
from volatility3.plugins.windows import bigpools, info, pslist, psscan, pstree

if TYPE_CHECKING:
    from session import Session

BASE_CONFIG_PATH = "plugins"


def _serialize_value(val: Any) -> Any:
    """Convert a volatility3 rendered value to a JSON-serializable type."""
    if isinstance(val, BaseAbsentValue):
        return None
    if isinstance(val, format_hints.Hex):
        return hex(val)
    if isinstance(val, (int, float, bool, str)):
        return val
    return str(val)


def parse_treegrid(treegrid) -> list[dict[str, Any]]:
    """Parse a Volatility3 TreeGrid into a list of dicts."""
    col_names = [col.name for col in treegrid.columns]
    rows: list[dict[str, Any]] = []

    def visitor(node, accumulator):
        row = {
            name: _serialize_value(node.values[i])
            for i, name in enumerate(col_names)
        }
        accumulator.append(row)
        return accumulator

    treegrid.populate(visitor, rows)
    return rows


def _noop_progress(percent: float, msg: str = "") -> None:
    """No-op progress callback required by some automagics."""


def _run_plugin(session: Session, plugin_class):
    """Run automagic and construct a plugin, returning (TreeGrid, constructed)."""
    ctx = session.ctx
    plugin_name = plugin_class.__name__
    session.apply_config(plugin_name)

    available = automagic.available(ctx)
    automagics = automagic.choose_automagic(available, plugin_class)
    automagic.run(automagics, ctx, plugin_class, BASE_CONFIG_PATH, progress_callback=_noop_progress)
    plugin_config_path = path_join(BASE_CONFIG_PATH, plugin_name)
    constructed = plugin_class(ctx, plugin_config_path, progress_callback=_noop_progress)
    treegrid = constructed.run()

    if not session.has_config:
        session.save_config(dict(constructed.build_configuration()))

    return treegrid


def run_info(session: Session) -> dict:
    """Run windows.info and return system information."""
    treegrid = _run_plugin(session, info.Info)
    results = {}
    for row in parse_treegrid(treegrid):
        results[row["Variable"]] = row["Value"]
    return {"plugin": "info", "results": results}


def run_pslist(session: Session) -> dict:
    """Run windows.pslist and return structured process list."""
    treegrid = _run_plugin(session, pslist.PsList)
    return {"plugin": "pslist", "results": parse_treegrid(treegrid)}


def run_psscan(session: Session) -> dict:
    """Run windows.psscan and return process list found by pool scanning."""
    treegrid = _run_plugin(session, psscan.PsScan)
    return {"plugin": "psscan", "results": parse_treegrid(treegrid)}


def run_pstree(session: Session) -> dict:
    """Run windows.pstree and return process tree with depth info."""
    treegrid = _run_plugin(session, pstree.PsTree)
    col_names = [col.name for col in treegrid.columns]
    rows: list[dict[str, Any]] = []

    def visitor(node, accumulator):
        row = {
            name: _serialize_value(node.values[i])
            for i, name in enumerate(col_names)
        }
        row["depth"] = node.path_depth
        accumulator.append(row)
        return accumulator

    treegrid.populate(visitor, rows)
    return {"plugin": "pstree", "results": rows}


def run_bigpools(session: Session) -> dict:
    """Run windows.bigpools and return big page pool allocations."""
    treegrid = _run_plugin(session, bigpools.BigPools)
    return {"plugin": "bigpools", "results": parse_treegrid(treegrid)}


PLUGIN_REGISTRY: dict[str, callable] = {
    "bigpools": run_bigpools,
    "info": run_info,
    "pslist": run_pslist,
    "psscan": run_psscan,
    "pstree": run_pstree,
}

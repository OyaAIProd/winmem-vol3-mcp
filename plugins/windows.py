"""Volatility3 Windows plugin wrappers.

Each wrapper runs a single plugin via the Python API and returns
structured results (not raw text).
"""

from __future__ import annotations

from typing import Any

from volatility3.framework import automagic, interfaces
from volatility3.framework.interfaces.renderers import BaseAbsentValue
from volatility3.framework.renderers import format_hints
from volatility3.framework.interfaces.configuration import path_join
from volatility3.plugins.windows import pslist, psscan

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


def _run_plugin(ctx: interfaces.context.ContextInterface, plugin_class):
    """Run automagic and construct a plugin, returning the TreeGrid."""
    available = automagic.available(ctx)
    automagics = automagic.choose_automagic(available, plugin_class)
    automagic.run(automagics, ctx, plugin_class, BASE_CONFIG_PATH, progress_callback=_noop_progress)
    plugin_config_path = path_join(BASE_CONFIG_PATH, plugin_class.__name__)
    constructed = plugin_class(ctx, plugin_config_path, progress_callback=_noop_progress)
    return constructed.run()


def run_pslist(ctx: interfaces.context.ContextInterface) -> dict:
    """Run windows.pslist and return structured process list."""
    treegrid = _run_plugin(ctx, pslist.PsList)
    return {"plugin": "pslist", "results": parse_treegrid(treegrid)}


def run_psscan(ctx: interfaces.context.ContextInterface) -> dict:
    """Run windows.psscan and return process list found by pool scanning."""
    treegrid = _run_plugin(ctx, psscan.PsScan)
    return {"plugin": "psscan", "results": parse_treegrid(treegrid)}


PLUGIN_REGISTRY: dict[str, callable] = {
    "pslist": run_pslist,
    "psscan": run_psscan,
}

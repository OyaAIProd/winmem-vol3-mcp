"""Shared utilities for Volatility3 plugin wrappers."""

from __future__ import annotations

from typing import Any, TYPE_CHECKING

from volatility3.framework import automagic
from volatility3.framework.interfaces.renderers import BaseAbsentValue
from volatility3.framework.renderers import format_hints
from volatility3.framework.interfaces.configuration import path_join

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


def run_plugin(session: Session, plugin_class):
    """Run automagic and construct a plugin, returning a TreeGrid."""
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

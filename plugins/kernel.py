"""Kernel / driver analysis plugin wrappers (bigpools, callbacks, ...)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from volatility3.plugins.windows import bigpools, callbacks

from plugins._common import parse_treegrid, run_plugin

if TYPE_CHECKING:
    from session import Session


def run_bigpools(session: Session) -> dict:
    """Run windows.bigpools and return big page pool allocations."""
    treegrid = run_plugin(session, bigpools.BigPools)
    return {"plugin": "bigpools", "results": parse_treegrid(treegrid)}


def run_callbacks(session: Session) -> dict:
    """Run windows.callbacks and return kernel callbacks and notification routines."""
    treegrid = run_plugin(session, callbacks.Callbacks)
    return {"plugin": "callbacks", "results": parse_treegrid(treegrid)}


PLUGIN_MAP = {
    "bigpools": run_bigpools,
    "callbacks": run_callbacks,
}

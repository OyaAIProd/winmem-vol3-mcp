"""Memory analysis plugin wrappers (malfind, vadinfo, vadwalk, ...)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from volatility3.plugins.windows import malfind

from plugins._common import parse_treegrid, run_plugin

if TYPE_CHECKING:
    from session import Session


def run_malfind(session: Session) -> dict:
    """Run windows.malfind and return potentially injected memory regions."""
    treegrid = run_plugin(session, malfind.Malfind)
    return {"plugin": "malfind", "results": parse_treegrid(treegrid)}


REGISTRY = {
    "malfind": run_malfind,
}

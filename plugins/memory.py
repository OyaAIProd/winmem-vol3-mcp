"""Memory analysis plugin wrappers (malfind, vadinfo, vadwalk, ...)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from volatility3.plugins.windows import malfind, vadinfo, vadwalk

from plugins._common import parse_treegrid, run_plugin

if TYPE_CHECKING:
    from session import Session


def run_malfind(session: Session) -> dict:
    """Run windows.malfind and return potentially injected memory regions."""
    treegrid = run_plugin(session, malfind.Malfind)
    return {"plugin": "malfind", "results": parse_treegrid(treegrid)}


def run_vadinfo(session: Session) -> dict:
    """Run windows.vadinfo and return VAD (Virtual Address Descriptor) details."""
    treegrid = run_plugin(session, vadinfo.VadInfo)
    return {"plugin": "vadinfo", "results": parse_treegrid(treegrid)}


def run_vadwalk(session: Session) -> dict:
    """Run windows.vadwalk and return VAD tree structure."""
    treegrid = run_plugin(session, vadwalk.VadWalk)
    return {"plugin": "vadwalk", "results": parse_treegrid(treegrid)}


REGISTRY = {
    "malfind": run_malfind,
    "vadinfo": run_vadinfo,
    "vadwalk": run_vadwalk,
}

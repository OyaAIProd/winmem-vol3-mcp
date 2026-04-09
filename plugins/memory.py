"""Memory analysis plugin wrappers (malfind, vadinfo, vadwalk, ...)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from volatility3.plugins.windows import malfind, memmap, strings, vadinfo, vadwalk, virtmap

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


def run_memmap(session: Session) -> dict:
    """Run windows.memmap and return virtual-to-physical memory mappings."""
    treegrid = run_plugin(session, memmap.Memmap)
    return {"plugin": "memmap", "results": parse_treegrid(treegrid)}


def run_virtmap(session: Session) -> dict:
    """Run windows.virtmap and return virtual mapped sections."""
    treegrid = run_plugin(session, virtmap.VirtMap)
    return {"plugin": "virtmap", "results": parse_treegrid(treegrid)}


def run_strings(session: Session) -> dict:
    """Run windows.strings and return strings mapped to processes."""
    treegrid = run_plugin(session, strings.Strings)
    return {"plugin": "strings", "results": parse_treegrid(treegrid)}


PLUGIN_MAP = {
    "malfind": run_malfind,
    "memmap": run_memmap,
    "strings": run_strings,
    "vadinfo": run_vadinfo,
    "vadwalk": run_vadwalk,
    "virtmap": run_virtmap,
}

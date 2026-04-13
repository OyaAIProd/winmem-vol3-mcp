"""Memory analysis plugin wrappers (vadinfo, vadwalk, ...)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from volatility3.plugins.windows import memmap, shimcachemem, strings, vadinfo, vadregexscan, vadwalk, virtmap

from plugins._common import parse_treegrid, run_plugin

if TYPE_CHECKING:
    from session import Session


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


def run_shimcachemem(session: Session) -> dict:
    """Run windows.shimcachemem and return Application Compatibility Cache entries."""
    treegrid = run_plugin(session, shimcachemem.ShimcacheMem)
    return {"plugin": "shimcachemem", "results": parse_treegrid(treegrid)}


def run_vadregexscan(session: Session, pattern: str, maxsize: int = 128) -> dict:
    """Run windows.vadregexscan against every process VAD with the given regex.

    pattern: regex pattern to search (required by the plugin).
    maxsize: maximum byte context around each match (default 128).
    """
    treegrid = run_plugin(
        session,
        vadregexscan.VadRegExScan,
        extra_config={"pattern": pattern, "maxsize": maxsize},
    )
    return {"plugin": "vadregexscan", "results": parse_treegrid(treegrid)}


PLUGIN_MAP = {
    "memmap": run_memmap,
    "shimcachemem": run_shimcachemem,
    "strings": run_strings,
    "vadinfo": run_vadinfo,
    "vadregexscan": run_vadregexscan,
    "vadwalk": run_vadwalk,
    "virtmap": run_virtmap,
}

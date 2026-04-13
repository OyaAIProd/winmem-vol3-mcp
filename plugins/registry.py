"""Registry analysis plugin wrappers (hivelist, hivescan, printkey, ...)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from volatility3.plugins.windows.registry import certificates, getcellroutine, hivelist, hivescan, printkey, scheduled_tasks, userassist

from plugins._common import parse_treegrid, run_plugin

if TYPE_CHECKING:
    from session import Session


def run_hivelist(session: Session) -> dict:
    """Run windows.registry.hivelist and return loaded registry hives."""
    treegrid = run_plugin(session, hivelist.HiveList)
    return {"plugin": "registry.hivelist", "results": parse_treegrid(treegrid)}


def run_hivescan(session: Session) -> dict:
    """Run windows.registry.hivescan and return hives found by pool scanning."""
    treegrid = run_plugin(session, hivescan.HiveScan)
    return {"plugin": "registry.hivescan", "results": parse_treegrid(treegrid)}


def run_userassist(session: Session) -> dict:
    """Run windows.registry.userassist and return UserAssist data."""
    treegrid = run_plugin(session, userassist.UserAssist)
    return {"plugin": "registry.userassist", "results": parse_treegrid(treegrid)}


def run_printkey(session: Session) -> dict:
    """Run windows.registry.printkey and return registry keys and values."""
    treegrid = run_plugin(session, printkey.PrintKey)
    return {"plugin": "registry.printkey", "results": parse_treegrid(treegrid)}


def run_certificates(session: Session) -> dict:
    """Run windows.registry.certificates and return certificate store entries."""
    treegrid = run_plugin(session, certificates.Certificates)
    return {"plugin": "registry.certificates", "results": parse_treegrid(treegrid)}


def run_scheduled_tasks(session: Session) -> dict:
    """Run windows.registry.scheduled_tasks and return scheduled task entries."""
    treegrid = run_plugin(session, scheduled_tasks.ScheduledTasks)
    return {"plugin": "registry.scheduled_tasks", "results": parse_treegrid(treegrid)}


def run_getcellroutine(session: Session) -> dict:
    """Run windows.registry.getcellroutine and return hives with hooked GetCellRoutine handlers."""
    treegrid = run_plugin(session, getcellroutine.GetCellRoutine)
    return {"plugin": "registry.getcellroutine", "results": parse_treegrid(treegrid)}


PLUGIN_MAP = {
    "registry.certificates": run_certificates,
    "registry.getcellroutine": run_getcellroutine,
    "registry.hivelist": run_hivelist,
    "registry.hivescan": run_hivescan,
    "registry.printkey": run_printkey,
    "registry.scheduled_tasks": run_scheduled_tasks,
    "registry.userassist": run_userassist,
}

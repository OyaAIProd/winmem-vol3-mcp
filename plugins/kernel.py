"""Kernel / driver analysis plugin wrappers (bigpools, callbacks, ...)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from volatility3.plugins.windows import bigpools, callbacks, devicetree, driverirp, drivermodule, driverscan, poolscanner

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


def run_devicetree(session: Session) -> dict:
    """Run windows.devicetree and return device tree by drivers."""
    treegrid = run_plugin(session, devicetree.DeviceTree)
    return {"plugin": "devicetree", "results": parse_treegrid(treegrid)}


def run_driverirp(session: Session) -> dict:
    """Run windows.driverirp and return IRP handler table for drivers."""
    treegrid = run_plugin(session, driverirp.DriverIrp)
    return {"plugin": "driverirp", "results": parse_treegrid(treegrid)}


def run_poolscanner(session: Session) -> dict:
    """Run windows.poolscanner and return generic pool scan results."""
    treegrid = run_plugin(session, poolscanner.PoolScanner)
    return {"plugin": "poolscanner", "results": parse_treegrid(treegrid)}


def run_driverscan(session: Session) -> dict:
    """Run windows.driverscan and return driver objects found by pool scanning."""
    treegrid = run_plugin(session, driverscan.DriverScan)
    return {"plugin": "driverscan", "results": parse_treegrid(treegrid)}


def run_drivermodule(session: Session) -> dict:
    """Run windows.drivermodule and return hidden driver module detection."""
    treegrid = run_plugin(session, drivermodule.DriverModule)
    return {"plugin": "drivermodule", "results": parse_treegrid(treegrid)}


PLUGIN_MAP = {
    "bigpools": run_bigpools,
    "callbacks": run_callbacks,
    "devicetree": run_devicetree,
    "driverirp": run_driverirp,
    "drivermodule": run_drivermodule,
    "driverscan": run_driverscan,
    "poolscanner": run_poolscanner,
}

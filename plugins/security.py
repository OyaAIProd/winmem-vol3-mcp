"""Security / malware analysis plugin wrappers (skeleton_key_check, mbrscan, ...)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from volatility3.plugins.windows import getservicesids, mbrscan, skeleton_key_check, truecrypt

from plugins._common import parse_treegrid, run_plugin

if TYPE_CHECKING:
    from session import Session


def run_skeleton_key_check(session: Session) -> dict:
    """Run windows.skeleton_key_check and return Skeleton Key detection results."""
    treegrid = run_plugin(session, skeleton_key_check.Skeleton_Key_Check)
    return {"plugin": "skeleton_key_check", "results": parse_treegrid(treegrid)}


def run_truecrypt(session: Session) -> dict:
    """Run windows.truecrypt and return cached TrueCrypt passphrases."""
    treegrid = run_plugin(session, truecrypt.Passphrase)
    return {"plugin": "truecrypt", "results": parse_treegrid(treegrid)}


def run_mbrscan(session: Session) -> dict:
    """Run windows.mbrscan and return potential Master Boot Record entries."""
    treegrid = run_plugin(session, mbrscan.MBRScan)
    return {"plugin": "mbrscan", "results": parse_treegrid(treegrid)}


def run_getservicesids(session: Session) -> dict:
    """Run windows.getservicesids and return service SID mappings."""
    treegrid = run_plugin(session, getservicesids.GetServiceSIDs)
    return {"plugin": "getservicesids", "results": parse_treegrid(treegrid)}


PLUGIN_MAP = {
    "getservicesids": run_getservicesids,
    "mbrscan": run_mbrscan,
    "skeleton_key_check": run_skeleton_key_check,
    "truecrypt": run_truecrypt,
}

"""Volatility3 Windows plugin wrappers.

Each category module exposes a PLUGIN_MAP dict mapping plugin names to runner
functions. This package aggregates them into a single PLUGIN_MAP.
"""

from plugins._common import BASE_CONFIG_PATH
from plugins.kernel import PLUGIN_MAP as _kernel
from plugins.memory import PLUGIN_MAP as _memory
from plugins.process import PLUGIN_MAP as _process
from plugins.sysinfo import PLUGIN_MAP as _sysinfo

PLUGIN_MAP: dict[str, callable] = {
    **_kernel,
    **_memory,
    **_process,
    **_sysinfo,
}

__all__ = ["BASE_CONFIG_PATH", "PLUGIN_MAP"]

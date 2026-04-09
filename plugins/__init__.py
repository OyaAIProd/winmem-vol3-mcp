"""Volatility3 Windows plugin wrappers.

Each category module exposes a REGISTRY dict mapping plugin names to runner
functions. This package aggregates them into a single PLUGIN_REGISTRY.
"""

from plugins._common import BASE_CONFIG_PATH
from plugins.kernel import REGISTRY as _kernel
from plugins.memory import REGISTRY as _memory
from plugins.process import REGISTRY as _process
from plugins.sysinfo import REGISTRY as _sysinfo

PLUGIN_REGISTRY: dict[str, callable] = {
    **_kernel,
    **_memory,
    **_process,
    **_sysinfo,
}

__all__ = ["BASE_CONFIG_PATH", "PLUGIN_REGISTRY"]

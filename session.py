"""Session management for Volatility3 MCP server."""

import json
from pathlib import Path

from volatility3.framework import contexts, interfaces
from volatility3.framework.interfaces.configuration import HierarchicalDict, path_join
from plugins import PLUGIN_MAP, BASE_CONFIG_PATH
from plugins._file_handler import make_file_handler


class Session:
    """Single-image analysis session with config caching.

    dump_dir: optional on-disk directory for dump plugins (dumpfiles,
        pedump, ...). When set, a FileHandler bound to this path is
        exposed via ``self.file_handler`` and can be passed to
        ``run_plugin(open_method=...)``. When unset, accessing
        ``file_handler`` raises so the caller surfaces a clear error.
    """

    def __init__(self, image_path: str, dump_dir: str = ""):
        self.image_path = image_path
        self.ctx = contexts.Context()
        # Cache key is either the plugin name (zero-arg tools) or a
        # (plugin_name, frozenset-of-kwargs) tuple for parameterized tools
        # such as windows_vadregexscan where results differ by argument.
        self._cache: dict = {}
        self._config_path = Path(image_path + ".vol3cfg.json")
        self._saved_config: dict | None = None
        self.dump_dir = dump_dir
        self._file_handler = make_file_handler(dump_dir) if dump_dir else None
        self._init_context()

    @property
    def file_handler(self):
        """FileHandler class bound to ``dump_dir`` for use with dump plugins.

        Raises RuntimeError if ``VOL_DUMP_DIR`` was not set when the server
        started, so the Claude-visible MCP tool can return a clear message.
        """
        if self._file_handler is None:
            raise RuntimeError(
                "VOL_DUMP_DIR is not configured. Set the VOL_DUMP_DIR "
                "environment variable in claude_desktop_config.json to "
                "an existing directory before calling any dump tool."
            )
        return self._file_handler

    def _init_context(self):
        uri = Path(self.image_path).resolve().as_uri()
        self.ctx.config["automagic.LayerStacker.single_location"] = uri
        if self._config_path.exists():
            with open(self._config_path) as f:
                self._saved_config = json.load(f)

    def apply_config(self, plugin_name: str):
        """Splice saved config into a plugin's config path if available."""
        if self._saved_config is not None:
            plugin_config_path = path_join(BASE_CONFIG_PATH, plugin_name)
            self.ctx.config.splice(
                plugin_config_path,
                HierarchicalDict(self._saved_config),
            )

    def save_config(self, config_dict: dict):
        """Save plugin configuration to JSON file for fast subsequent loads."""
        self._saved_config = config_dict
        with open(self._config_path, "w") as f:
            json.dump(config_dict, f, sort_keys=True, indent=2)
            f.write("\n")

    @property
    def has_config(self) -> bool:
        return self._saved_config is not None

    def run_plugin(self, plugin_name: str, **kwargs) -> dict:
        """Run a plugin by name, returning cached results if available.

        Extra kwargs are forwarded to the plugin's runner function and used
        to key the cache, so calling the same parameterized plugin twice
        with identical arguments returns the cached result, while different
        arguments trigger a fresh run.
        """
        cache_key = (plugin_name, frozenset(kwargs.items())) if kwargs else plugin_name
        if cache_key in self._cache:
            return self._cache[cache_key]
        if plugin_name not in PLUGIN_MAP:
            raise ValueError(f"Unknown plugin: {plugin_name}")
        result = PLUGIN_MAP[plugin_name](self, **kwargs)
        self._cache[cache_key] = result
        return result

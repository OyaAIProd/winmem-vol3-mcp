"""Session management for Volatility3 MCP server."""

import json
from pathlib import Path

from volatility3.framework import contexts, interfaces
from volatility3.framework.interfaces.configuration import HierarchicalDict, path_join
from plugins.windows import PLUGIN_REGISTRY, BASE_CONFIG_PATH


class Session:
    """Single-image analysis session with config caching."""

    def __init__(self, image_path: str):
        self.image_path = image_path
        self.ctx = contexts.Context()
        self._cache: dict[str, dict] = {}
        self._config_path = Path(image_path + ".vol3cfg.json")
        self._saved_config: dict | None = None
        self._init_context()

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

    def run_plugin(self, plugin_name: str) -> dict:
        """Run a plugin by name, returning cached results if available."""
        if plugin_name in self._cache:
            return self._cache[plugin_name]
        if plugin_name not in PLUGIN_REGISTRY:
            raise ValueError(f"Unknown plugin: {plugin_name}")
        result = PLUGIN_REGISTRY[plugin_name](self)
        self._cache[plugin_name] = result
        return result

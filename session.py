"""Session management for Volatility3 MCP server."""

from pathlib import Path

from volatility3.framework import contexts
from plugins.windows import PLUGIN_REGISTRY


class Session:
    """Single-image analysis session with result caching."""

    def __init__(self, image_path: str):
        self.image_path = image_path
        self.ctx = contexts.Context()
        self._cache: dict[str, dict] = {}
        self._init_context()

    def _init_context(self):
        uri = Path(self.image_path).resolve().as_uri()
        self.ctx.config["automagic.LayerStacker.single_location"] = uri

    def run_plugin(self, plugin_name: str) -> dict:
        """Run a plugin by name, returning cached results if available."""
        if plugin_name in self._cache:
            return self._cache[plugin_name]
        if plugin_name not in PLUGIN_REGISTRY:
            raise ValueError(f"Unknown plugin: {plugin_name}")
        result = PLUGIN_REGISTRY[plugin_name](self.ctx)
        self._cache[plugin_name] = result
        return result

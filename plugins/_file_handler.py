"""File handler factory for volatility3 dump plugins.

Dump plugins (``windows.dumpfiles``, ``windows.pedump``, ...) extract
binary content from memory by calling ``PluginInterface.open(filename)``
which returns a ``FileHandlerInterface`` instance. The interface's
``close()`` method decides *where* the bytes actually land.

This module provides ``make_file_handler(output_dir)``: a factory that
binds a ``DumpFileHandler`` class to a specific on-disk directory.
Every file opened by a plugin constructed with this handler is buffered
in memory and flushed to ``output_dir`` when the plugin finalises the
file. Filename collisions are resolved by appending ``-1``, ``-2``, ...
before the extension (same behaviour as the vol3 CLI).
"""

from __future__ import annotations

import io
import os

from volatility3.framework.interfaces import plugins


def make_file_handler(output_dir: str):
    """Return a FileHandlerInterface subclass that writes into ``output_dir``.

    The directory is created on first use. Every handler instance buffers
    writes in an ``io.BytesIO`` and flushes to
    ``<output_dir>/<preferred_filename>`` in ``close()``. Collisions are
    resolved by inserting ``-N`` before the extension.
    """
    os.makedirs(output_dir, exist_ok=True)

    class DumpFileHandler(io.BytesIO, plugins.FileHandlerInterface):
        def __init__(self, filename: str):
            io.BytesIO.__init__(self)
            plugins.FileHandlerInterface.__init__(self, filename)

        def close(self):
            if self.closed:
                return None
            self.seek(0)

            output_path = os.path.join(output_dir, self.preferred_filename)
            base, ext = os.path.splitext(output_path)
            counter = 1
            while os.path.exists(output_path):
                output_path = f"{base}-{counter}{ext}"
                counter += 1

            with open(output_path, "wb") as fp:
                fp.write(self.read())

            super().close()

    return DumpFileHandler

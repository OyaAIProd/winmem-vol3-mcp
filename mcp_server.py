"""MCP server for Volatility3 memory forensics."""

import os
import sys

from mcp.server.fastmcp import FastMCP
from session import Session

IMAGE_PATH = os.environ.get("VOL_IMAGE_PATH", "")
if not IMAGE_PATH or not os.path.isfile(IMAGE_PATH):
    print(
        f"VOL_IMAGE_PATH is not set or file does not exist: {IMAGE_PATH!r}",
        file=sys.stderr,
    )
    sys.exit(1)

mcp = FastMCP("volatility-mcp")
session = Session(IMAGE_PATH)


@mcp.tool()
def get_image_info() -> dict:
    """Get system information from the memory image (OS version, architecture, etc.).
    Call this first to initialize the session and cache configuration for faster subsequent analysis."""
    return session.run_plugin("info")


@mcp.tool()
def get_processes() -> dict:
    """Return the list of processes from the loaded memory image."""
    return session.run_plugin("pslist")


@mcp.tool()
def scan_processes() -> dict:
    """Scan for processes using pool tag scanning. Can find hidden/unlinked processes."""
    return session.run_plugin("psscan")


@mcp.tool()
def get_process_tree() -> dict:
    """Return the process tree with parent-child hierarchy and depth info."""
    return session.run_plugin("pstree")


if __name__ == "__main__":
    mcp.run()

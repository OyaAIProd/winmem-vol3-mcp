# volatility3-mcp

An MCP (Model Context Protocol) server that wraps the [Volatility3](https://github.com/volatilityfoundation/volatility3) memory forensics framework, enabling conversational Windows memory analysis through Claude Desktop.

> **Windows memory images only.** This project exclusively targets Windows memory dumps. All plugins are sourced from `volatility3.plugins.windows.*`. Linux and macOS memory analysis will be addressed in separate projects.

## Key Features

- **Direct Python API integration** -- calls `volatility3` as a library (`import volatility3`), not via subprocess
- **Structured output** -- TreeGrid results are parsed into typed JSON-serializable dicts, not raw text
- **Session-based context** -- a single Volatility3 Context is built once at startup and reused across all plugin calls
- **Result caching** -- plugin results are cached per session to avoid redundant computation
- **Config caching** -- kernel/layer configuration is saved to `{image}.vol3cfg.json` on first run, skipping expensive PDB download and layer scanning on subsequent starts
- **Forensic-aware tool docstrings** -- each MCP tool carries a three-layer docstring (trigger patterns, return structure, forensic context) that guides the LLM to select the right tool, interpret results accurately, and autonomously chain multi-step analysis workflows

## Installation

Requires Python 3.10+ and [uv](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/cpuu/winmem-vol3-mcp.git
cd winmem-vol3-mcp
uv sync
```

## Usage

### Claude Desktop Configuration

Add the following to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "winmem-vol3-mcp": {
      "command": "uv",
      "args": ["--directory", "/absolute/path/to/winmem-vol3-mcp", "run", "python", "mcp_server.py"],
      "env": {
        "VOL_IMAGE_PATH": "/absolute/path/to/memory.vmem"
      }
    }
  }
}
```

`VOL_IMAGE_PATH` must point to an existing Windows memory image file. The server will not start without it.

### Quick Test

After configuring Claude Desktop, ask Claude to identify the memory image. Claude will call `get_image_info` and return system information:

```json
{
  "plugin": "info",
  "results": {
    "Kernel Base": "0xf80002a52000",
    "DTB": "0x187000",
    "Is64Bit": true,
    "IsPAE": false,
    "NTBuildLab": "7601.17514.amd64fre.win7sp1_rtm.",
    "NtMajorVersion": 6,
    "NtMinorVersion": 1,
    "NtProductType": "NtProductWinNt"
  }
}
```

## Available Tools

| MCP Tool | Volatility3 Plugin | Description |
|---|---|---|
| `get_image_info` | `windows.info` | OS version, architecture, kernel base (call first to cache config) |
| `get_processes` | `windows.pslist` | List running processes |
| `scan_processes` | `windows.psscan` | Pool tag scanning (finds hidden/unlinked processes) |
| `get_process_tree` | `windows.pstree` | Process tree with parent-child hierarchy |

## Architecture

```
Claude Desktop  <-->  MCP Server (stdio)  <-->  volatility3 (Python import)
                            |
                         Session
                            +-- Context (built once, reused)
                            +-- Config cache ({image}.vol3cfg.json)
                            +-- Result cache (plugin name -> result)
```

A single memory image is fixed per server session. This is intentional -- it ensures all plugin results within a session refer to exactly one memory image, maintaining analytical rigor.

## License

Apache-2.0

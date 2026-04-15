# Volatility3 MCP Server — Project Context

## Project Overview

This project implements an MCP (Model Context Protocol) server that wraps the Volatility3 memory forensics framework, enabling conversational memory analysis through Claude Desktop. The ultimate goal is a research paper targeting DFRWS, with clear technical contributions over existing implementations.

---

## Differentiation from Prior Work

### Limitations of Existing Implementations

| Project | Invocation | Tools | Output | Caching/Session |
|---|---|---|---|---|
| **Gaffx/volatility-mcp** | MCP → FastAPI → subprocess (3 layers) | 3 | raw text | none |
| **bornpresident/Volatility-MCP-Server** | subprocess wrapper | ~6 | raw text | none |
| **OMGhozlan/Volatility-MCP-Server** | `asyncio.create_subprocess_exec` (vol.py) | 5 (1 generic `run_plugin` + 4 utils) | raw text (stdout) | none |
| **capelabs/vibe-sandbox** (vol3 component) | `subprocess.run` (vol CLI with `-r json`) | 3 (1 generic `run_plugin` + 2 utils) | JSON string from CLI | none |

- All four use **subprocess** to call Volatility3 — none imports the library directly
- All expose a single generic `run_plugin(plugin_name, ...)` tool instead of per-plugin endpoints with forensic-aware docstrings
- None implement caching, session management, or context reuse
- None provide per-plugin return schemas or tool-chaining hints for the LLM
- capelabs/vibe-sandbox's primary focus is sandbox orchestration (VirtualBox + Docker), not memory analysis depth

### Our Contributions
1. **Direct Volatility3 Python API integration** — `import volatility3` directly, no subprocess
2. **Session-based Context management** — one Context per image, created once and reused
3. **Structured plugin output** — TreeGrid parsed into typed dicts, not raw text
4. **Cross-plugin correlation tools** — e.g., malfind results automatically chained to dlllist/cmdline
5. **Automated forensic report generation** — session analysis flow tracked and exported as report

---

## Architecture

### Overall Structure
```
Claude Desktop
    ↕ (MCP protocol, stdio)
MCP Server process (mcp_server.py)
    ↕ (Python import, same process)
volatility3 package (pip install)
    ↕
Memory image file (single, fixed at config)
```

### Session Design
A single memory image is fixed per server session for analytical rigor.
The image path is specified in `claude_desktop_config.json` and cannot be changed at runtime.

```
MCP Server
  └── Session (single, initialized at startup)
        ├── Context            (built once from fixed image path, reused)
        ├── PluginResultCache  (plugin name → structured result)
        └── run_plugin(plugin_class) → structured dict
```

### Image Path Resolution
The memory image path is provided exclusively via the `VOL_IMAGE_PATH` environment variable set in `claude_desktop_config.json`. There is no runtime switching of images. This constraint is intentional — it enforces analytical rigor by ensuring all plugin results within a session refer to exactly one memory image.

---

## Tech Stack

- Python 3.10+
- `volatility3==2.7.0` — installed via pip, used via direct import
- `mcp` — FastMCP, stdio transport
- Claude Desktop — MCP client
- **Windows memory images only** — Linux and macOS are out of scope and will be addressed in separate projects. All plugins are sourced from `volatility3.plugins.windows.*` only.

---

## Tool Docstring Design Principles

The docstring of each MCP tool is the primary signal Claude uses to decide which tool to invoke. Poorly written docstrings cause incorrect tool selection or tool abandonment. All tools must follow the three-layer structure below.

### Layer 1 — Purpose and Natural Language Trigger Patterns
Describe what the tool does and list the types of user questions that should trigger it.
Claude uses this to match user intent to the correct tool.

```python
"""
Run the pslist plugin to enumerate processes from the Windows memory image.

Use this tool when the user asks about:
- Running processes or active programs
- Process list, process tree, or process hierarchy
- What applications were open at the time of capture
- Parent-child process relationships
"""
```

### Layer 2 — Return Value Structure
Explicitly describe the structure of the returned dict.
Claude uses this to interpret results correctly and formulate accurate responses.

```python
"""
Returns a dict with:
- "plugin": "pslist"
- "results": list of {
    "name": process name (str),
    "pid": process ID (int),
    "ppid": parent process ID (int),
    "offset": virtual offset (int),
    "threads": thread count (int),
    "create_time": process creation time (str)
  }
"""
```

### Layer 3 — Forensic Context and Tool Chaining Hints
Describe the forensic significance of the output and suggest how results should be
connected to other tools. Claude uses this to autonomously construct multi-step
analysis workflows without explicit user instruction.

```python
"""
Forensic context:
- Compare with psscan results to detect hidden processes (pslist vs psscan discrepancy)
- Use pid values from this output as input to get_cmdline or get_dlllist
- Unusual parent-child relationships (e.g., svchost.exe not parented by services.exe)
  may indicate process injection or masquerading
"""
```

### Complete Example

```python
@mcp.tool()
def get_processes() -> dict:
    """
    Run the pslist plugin to enumerate processes from the Windows memory image.

    Use this tool when the user asks about:
    - Running processes or active programs
    - Process list, process tree, or process hierarchy
    - What applications were open at the time of capture
    - Parent-child process relationships

    Returns a dict with:
    - "plugin": "pslist"
    - "results": list of {
        "name": process name (str),
        "pid": process ID (int),
        "ppid": parent process ID (int),
        "offset": virtual offset (int),
        "threads": thread count (int),
        "create_time": process creation time (str)
      }

    Forensic context:
    - Compare with psscan results to detect hidden processes
    - Use pid values from this output as input to get_cmdline or get_dlllist
    - Unusual parent-child relationships (e.g., svchost.exe not parented by
      services.exe) may indicate process injection or masquerading
    """
    return session.run_plugin("pslist")
```

### Docstring Writing Rules
- Layer 1, 2, and 3 are all mandatory for every tool
- Layer 1 trigger patterns must include at least 3 distinct phrasings of user intent
- Layer 3 must reference at least one other tool by function name where applicable
- Do not describe implementation details (e.g., "calls Volatility3 pslist plugin internally")
- Write in plain English; avoid jargon that Claude may not associate with user queries

---

## Current Implementation Stage: Hello World

### Goal
- Claude Desktop reads the image path from environment variable at startup
- A single Session is initialized with that image
- When the user asks about processes in natural language, Claude calls the `get_processes` tool
- The tool runs `pslist` via Volatility3 Python API and returns structured results

### File Structure
```
winmem-vol3-mcp/
├── mcp_server.py       # MCP server entry point
├── session.py          # Session class
├── plugins/
│   └── windows.py      # Plugin wrappers (pslist, etc.)
├── requirements.txt
└── CLAUDE.md
```

### requirements.txt
```
volatility3==2.7.0
mcp>=1.0.0
```

### Claude Desktop Configuration (claude_desktop_config.json)
```json
{
  "mcpServers": {
    "volatility": {
      "command": "python",
      "args": ["/absolute/path/to/mcp_server.py"],
      "env": {
        "VOL_IMAGE_PATH": "/absolute/path/to/win10.vmem",
        "VOL_DUMP_DIR": "/absolute/path/to/dumps"
      }
    }
  }
}
```

`VOL_IMAGE_PATH` is the only supported way to specify the memory image. The server will fail to start if this variable is not set or the file does not exist.

`VOL_DUMP_DIR` is optional. When set, dump plugins (`windows_dumpfiles`, future `windows_pedump`, etc.) write extracted bytes into this directory using a `FileHandlerInterface` subclass bound to the path. The directory is created on first use; filename collisions are resolved by appending `-1`, `-2`, ... before the extension. When `VOL_DUMP_DIR` is unset, any dump tool call raises a `RuntimeError` with a clear message so Claude can ask the user to configure it.

---

## Hello World Implementation Guide

### mcp_server.py
```python
import os
from mcp.server.fastmcp import FastMCP
from session import Session

IMAGE_PATH = os.environ.get("VOL_IMAGE_PATH", "")
if not IMAGE_PATH or not os.path.exists(IMAGE_PATH):
    raise RuntimeError(f"VOL_IMAGE_PATH is not set or file does not exist: {IMAGE_PATH}")

mcp = FastMCP("winmem-vol3-mcp")
session = Session(IMAGE_PATH)

@mcp.tool()
def get_processes() -> dict:
    """
    Run the pslist plugin to enumerate processes from the Windows memory image.

    Use this tool when the user asks about:
    - Running processes or active programs
    - Process list, process tree, or process hierarchy
    - What applications were open at the time of capture
    - Parent-child process relationships

    Returns a dict with:
    - "plugin": "pslist"
    - "results": list of {
        "name": process name (str),
        "pid": process ID (int),
        "ppid": parent process ID (int),
        "offset": virtual offset (int),
        "threads": thread count (int),
        "create_time": process creation time (str)
      }

    Forensic context:
    - Compare with psscan results to detect hidden processes
    - Use pid values from this output as input to get_cmdline or get_dlllist
    - Unusual parent-child relationships (e.g., svchost.exe not parented by
      services.exe) may indicate process injection or masquerading
    """
    return session.run_plugin("pslist")

if __name__ == "__main__":
    mcp.run()
```

### session.py
```python
from volatility3.framework import contexts, automagic
from volatility3.plugins.windows import pslist

class Session:
    def __init__(self, image_path: str):
        self.image_path = image_path
        self.ctx = contexts.Context()
        self.cache = {}
        self._init_context()

    def _init_context(self):
        self.ctx.config["automagic.LayerStacker.single_location"] = f"file://{self.image_path}"

    def run_plugin(self, plugin_name: str) -> dict:
        if plugin_name in self.cache:
            return self.cache[plugin_name]
        result = getattr(self, f"_run_{plugin_name}")()
        self.cache[plugin_name] = result
        return result

    def _run_pslist(self) -> dict:
        available = automagic.available(self.ctx)
        automagic.run(available, self.ctx, pslist.PsList, "plugins")
        plugin = pslist.PsList(self.ctx, "plugins")
        treegrid = plugin.run()
        results = []
        for row in treegrid.generator:
            results.append({
                "name": str(row[0]),
                "pid":  int(row[1]),
                "ppid": int(row[2]),
            })
        return {"plugin": "pslist", "results": results}
```

---

## Implementation Notes

- **Symbol tables (ISF)**: Downloaded automatically on first run — internet access required
- **Windows only**: This project exclusively targets Windows memory images. Linux and macOS images are out of scope and will be addressed in separate projects. All plugins are sourced from `volatility3.plugins.windows.*` only.
- **TreeGrid column order**: Varies by plugin — verify against volatility3 source before mapping
- **Context reuse**: Context is built once at startup and reused for all plugin calls
- **Image path prefix**: Must include `file://` prefix when assigned to Context config

---

## Roadmap (After Hello World)

1. Add plugins: `netscan`, `malfind`, `cmdline`, `dlllist`, `psscan`
2. Implement cross-plugin correlation tools
3. Implement forensic report generation tool
4. Design CTF-based evaluation benchmark and run experiments

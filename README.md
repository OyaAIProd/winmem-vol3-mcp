# volatility3-mcp

An MCP (Model Context Protocol) server that wraps the [Volatility3](https://github.com/volatilityfoundation/volatility3) memory forensics framework, enabling conversational Windows memory analysis through Claude Desktop.

## Key Features

- **Direct Python API integration** -- calls `volatility3` as a library (`import volatility3`), not via subprocess
- **Structured output** -- TreeGrid results are parsed into typed JSON-serializable dicts, not raw text
- **Session-based context** -- a single Volatility3 Context is built once at startup and reused across all plugin calls
- **Result caching** -- plugin results are cached per session to avoid redundant computation

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
    "volatility": {
      "command": "uv",
      "args": ["run", "python", "/absolute/path/to/mcp_server.py"],
      "env": {
        "VOL_IMAGE_PATH": "/absolute/path/to/memory.vmem"
      }
    }
  }
}
```

`VOL_IMAGE_PATH` must point to an existing Windows memory image file. The server will not start without it.

### Direct Testing

```bash
VOL_IMAGE_PATH=./memory.vmem uv run python -c "
from session import Session
s = Session('./memory.vmem')
result = s.run_plugin('pslist')
print(result)
"
```

### Example Output

```json
{
  "plugin": "pslist",
  "results": [
    {
      "PID": 4,
      "PPID": 0,
      "ImageFileName": "System",
      "Offset(V)": "0xfa80018bc040",
      "Threads": 77,
      "Handles": 505,
      "SessionId": null,
      "Wow64": false,
      "CreateTime": "2025-07-25 15:07:57",
      "ExitTime": null,
      "File output": "Disabled"
    }
  ]
}
```

## Available Tools

| MCP Tool | Volatility3 Plugin | Description |
|---|---|---|
| `get_processes` | `windows.pslist` | List running processes |

## Architecture

```
Claude Desktop  <-->  MCP Server (stdio)  <-->  volatility3 (Python import)
                            |
                         Session
                            +-- Context (built once, reused)
                            +-- Cache (plugin name -> result)
```

A single memory image is fixed per server session. This is intentional -- it ensures all plugin results within a session refer to exactly one memory image, maintaining analytical rigor.

## License

Apache-2.0

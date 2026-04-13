# winmem-vol3-mcp

An MCP (Model Context Protocol) server that wraps the [Volatility3](https://github.com/volatilityfoundation/volatility3) memory forensics framework, enabling conversational Windows memory analysis through Claude Desktop.

> **Windows memory images only.** This project exclusively targets Windows memory dumps. All plugins are sourced from `volatility3.plugins.windows.*`. Linux and macOS memory analysis will be addressed in separate projects.

## Key Features

- **Direct Python API integration** -- calls `volatility3` as a library (`import volatility3`), not via subprocess
- **Structured output** -- TreeGrid results are parsed into typed JSON-serializable dicts, not raw text
- **Session-based context** -- a single Volatility3 Context is built once at startup and reused across all plugin calls
- **Parameterized query support** -- plugins that require a user argument (e.g., `windows_vadregexscan(pattern)`) are exposed as MCP tools with typed parameters, letting Claude drive regex hunts and other targeted queries end-to-end without leaving the conversation
- **Binary extraction to disk** -- dump plugins (`windows_dumpfiles`, `windows_pedump`, ...) write recovered files / PE images to the directory set by the `VOL_DUMP_DIR` environment variable, while the MCP response returns only the on-disk path and metadata. This keeps dumped binaries out of Claude's context window (which binary blobs would otherwise overwhelm) yet makes them immediately available to the analyst for IDA, YARA, or sandbox workflows
- **Result caching** -- plugin results are cached per session; parameterized tools are keyed by their argument set, so repeating the same query is free while changing an argument triggers a fresh run
- **Config caching** -- kernel/layer configuration is saved to `{image}.vol3cfg.json` on first run, skipping expensive PDB download and layer scanning on subsequent starts
- **Forensic-aware tool docstrings** -- each MCP tool carries a three-layer docstring (trigger patterns, return structure, forensic context) that guides the LLM to select the right tool, interpret results accurately, and autonomously chain multi-step analysis workflows
- **Multilingual natural language queries** -- while the codebase and tool outputs are in English, users can ask questions in any language Claude supports (e.g., Korean, Japanese, Chinese, German, etc.) and receive analysis results in the same language

## Installation

Requires Python 3.10+ and [uv](https://docs.astral.sh/uv/). 

Dependencies are managed via uv and pinned to [Volatility3 2.27.0](https://github.com/volatilityfoundation/volatility3/releases/tag/v2.27.0) (released 2026-01-30).

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
        "VOL_IMAGE_PATH": "/absolute/path/to/memory.vmem",
        "VOL_DUMP_DIR": "/absolute/path/to/dumps"
      }
    }
  }
}
```

`VOL_IMAGE_PATH` must point to an existing Windows memory image file. The server will not start without it.

`VOL_DUMP_DIR` is optional. When set, dump tools such as `windows_dumpfiles` write recovered bytes into this directory (it is created on first use, and filename collisions are resolved by appending `-1`, `-2`, ...). When unset, calling any dump tool raises a clear error so Claude can ask the user to configure it.

### Quick Test

After configuring Claude Desktop, try asking:

> *"Please, identify the memory image."*

Claude will automatically call `windows_info` and present the analysis results in a conversational format:

![Memory Image Identification](png/imageinfo.png)

You can then ask follow-up questions to dig deeper:

> *"Could you list all running processes and flag any that look suspicious?"*

![Process List](png/pslist.png)

## Available Tools

69 Windows plugins from Volatility3 v2.27.0 (`volatility3.plugins.windows.*`) are integrated as MCP tools. See [TOOL_CATALOG.md](TOOL_CATALOG.md) for the complete reference and `plan.md` for remaining plugin coverage.

| Category | Plugins |
|---|---|
| Process Analysis | pslist, psscan, pstree, cmdline, sessions, getsids, privileges, envars, handles, joblinks, thrdscan, threads |
| Memory Analysis | vadinfo, vadwalk, memmap, virtmap, strings, shimcachemem, vadregexscan |
| Module / DLL Analysis | dlllist, modules, modscan, verinfo, iat, pe_symbols, pedump |
| Network Analysis | netscan, netstat |
| Kernel / Driver Analysis | bigpools, callbacks, driverscan, driverirp, devicetree, ssdt, poolscanner, orphan_kernel_threads, kpcrs, unloadedmodules, timers, debugregisters, etwpatch |
| File Analysis | filescan, dumpfiles, symlinkscan, mutantscan |
| Registry Analysis | registry.hivelist, registry.hivescan, registry.printkey, registry.userassist, registry.certificates, registry.scheduled_tasks, registry.getcellroutine, registry.amcache |
| Service Analysis | svcscan, svclist |
| Desktop / GUI | windowstations, desktops, deskscan |
| System Information | info, statistics, crashinfo |
| Security / Integrity | mbrscan, truecrypt, getservicesids, suspended_threads |
| Malware Detection | malware.drivermodule, malware.ldrmodules, malware.malfind, malware.skeleton_key_check |

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

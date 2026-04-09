# Volatility3 Windows Plugin List

All plugins from `volatility3.plugins.windows.*` (v2.27.0) with MCP tool name
mapping and implementation status.

## Naming Convention

MCP tool names mirror the Volatility3 plugin name for easy identification.
Format: `windows_{plugin_name}` (e.g., `windows.pslist` -> `windows_pslist`).
Registry sub-plugins use `windows_registry_{name}`.

---

## Process Analysis

| Volatility3 Plugin | MCP Tool Name | Status | Description |
|---|---|---|---|
| `windows.pslist` | `windows_pslist` | Done | List processes via active process linked list |
| `windows.psscan` | `windows_psscan` | Done | Scan for processes by pool tag (finds hidden) |
| `windows.pstree` | `windows_pstree` | Done | Process tree with parent-child hierarchy |
| `windows.cmdline` | `windows_cmdline` | Planned | List process command line arguments |
| `windows.sessions` | `windows_sessions` | Planned | List processes with session information |
| `windows.getsids` | `windows_getsids` | Planned | Print SIDs owning each process |
| `windows.privileges` | `windows_privileges` | Planned | List process token privileges |
| `windows.envars` | `windows_envars` | Planned | Display process environment variables |
| `windows.handles` | `windows_handles` | Planned | List process open handles |
| `windows.joblinks` | `windows_joblinks` | Planned | Print process job link information |
| `windows.thrdscan` | `windows_thrdscan` | Planned | Scan for Windows threads |

## Memory Analysis

| Volatility3 Plugin | MCP Tool Name | Status | Description |
|---|---|---|---|
| `windows.malfind` | `windows_malfind` | Planned | Detect potentially injected code in process memory |
| `windows.vadinfo` | `windows_vadinfo` | Planned | List process memory ranges (VAD) |
| `windows.vadwalk` | `windows_vadwalk` | Planned | Walk the VAD tree |
| `windows.memmap` | `windows_memmap` | Planned | Print the memory map |
| `windows.virtmap` | `windows_virtmap` | Planned | List virtual mapped sections |
| `windows.strings` | `windows_strings` | Planned | Map strings output to processes |

## Module / DLL Analysis

| Volatility3 Plugin | MCP Tool Name | Status | Description |
|---|---|---|---|
| `windows.dlllist` | `windows_dlllist` | Planned | List loaded modules per process |
| `windows.ldrmodules` | `windows_ldrmodules` | Planned | List loaded modules (detects unlinked DLLs) |
| `windows.modules` | `windows_modules` | Planned | List loaded kernel modules |
| `windows.modscan` | `windows_modscan` | Planned | Scan for kernel modules by pool tag |
| `windows.verinfo` | `windows_verinfo` | Planned | List version information from PE files |
| `windows.iat` | `windows_iat` | Planned | Extract Import Address Table |

## Network Analysis

| Volatility3 Plugin | MCP Tool Name | Status | Description |
|---|---|---|---|
| `windows.netscan` | `windows_netscan` | Planned | Scan for network objects by pool tag |
| `windows.netstat` | `windows_netstat` | Planned | Traverse network tracking structures |

## Kernel / Driver Analysis

| Volatility3 Plugin | MCP Tool Name | Status | Description |
|---|---|---|---|
| `windows.bigpools` | `windows_bigpools` | Done | List big page pool allocations |
| `windows.callbacks` | `windows_callbacks` | Done | List kernel callbacks and notification routines |
| `windows.driverscan` | `windows_driverscan` | Done | Scan for driver objects |
| `windows.driverirp` | `windows_driverirp` | Done | List IRPs for drivers |
| `windows.drivermodule` | `windows_drivermodule` | Done | Detect hidden driver modules |
| `windows.devicetree` | `windows_devicetree` | Done | List device tree by drivers |
| `windows.ssdt` | `windows_ssdt` | Done | List system call table |
| `windows.poolscanner` | `windows_poolscanner` | Done | Generic pool scanner |

## File Analysis

| Volatility3 Plugin | MCP Tool Name | Status | Description |
|---|---|---|---|
| `windows.filescan` | `windows_filescan` | Done | Scan for file objects |
| `windows.dumpfiles` | `windows_dumpfiles` | Done | Dump cached file contents |
| `windows.symlinkscan` | `windows_symlinkscan` | Done | Scan for symbolic links |
| `windows.mutantscan` | `windows_mutantscan` | Done | Scan for mutexes |

## Registry Analysis

| Volatility3 Plugin | MCP Tool Name | Status | Description |
|---|---|---|---|
| `windows.registry.hivelist` | `windows_registry_hivelist` | Planned | List registry hives |
| `windows.registry.hivescan` | `windows_registry_hivescan` | Planned | Scan for registry hives |
| `windows.registry.printkey` | `windows_registry_printkey` | Planned | Print registry keys and values |
| `windows.registry.userassist` | `windows_registry_userassist` | Planned | Print UserAssist registry data |
| `windows.registry.certificates` | `windows_registry_certificates` | Planned | List certificates from registry store |

## System Information

| Volatility3 Plugin | MCP Tool Name | Status | Description |
|---|---|---|---|
| `windows.info` | `windows_info` | Done | OS version, architecture, kernel details |
| `windows.statistics` | `windows_statistics` | Planned | Memory space statistics |
| `windows.crashinfo` | `windows_crashinfo` | Planned | Windows crash dump information |

## Security / Malware

| Volatility3 Plugin | MCP Tool Name | Status | Description |
|---|---|---|---|
| `windows.skeleton_key_check` | `windows_skeleton_key_check` | Planned | Detect Skeleton Key malware |
| `windows.mbrscan` | `windows_mbrscan` | Planned | Scan for Master Boot Records |
| `windows.truecrypt` | `windows_truecrypt` | Planned | Find TrueCrypt cached passphrases |
| `windows.getservicesids` | `windows_getservicesids` | Planned | List process token service SIDs |

---

## Summary

- **Total plugins**: 49
- **Done**: 38 (Process 11, Memory 6, Module/DLL 6, Network 2, Kernel 8, File 4, System Info 1)
- **Planned**: 11

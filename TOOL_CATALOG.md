# Volatility3 Windows Plugin Catalog

All 49 plugins from `volatility3.plugins.windows.*` (v2.27.0) are fully
integrated as MCP tools.

## Naming Convention

MCP tool names mirror the Volatility3 plugin name for easy identification.
Format: `windows_{plugin_name}` (e.g., `windows.pslist` -> `windows_pslist`).
Registry sub-plugins use `windows_registry_{name}`.

---

## Process Analysis

| Volatility3 Plugin | MCP Tool Name | Description |
|---|---|---|
| `windows.pslist` | `windows_pslist` | List processes via active process linked list |
| `windows.psscan` | `windows_psscan` | Scan for processes by pool tag (finds hidden) |
| `windows.pstree` | `windows_pstree` | Process tree with parent-child hierarchy |
| `windows.cmdline` | `windows_cmdline` | List process command line arguments |
| `windows.sessions` | `windows_sessions` | List processes with session information |
| `windows.getsids` | `windows_getsids` | Print SIDs owning each process |
| `windows.privileges` | `windows_privileges` | List process token privileges |
| `windows.envars` | `windows_envars` | Display process environment variables |
| `windows.handles` | `windows_handles` | List process open handles |
| `windows.joblinks` | `windows_joblinks` | Print process job link information |
| `windows.thrdscan` | `windows_thrdscan` | Scan for Windows threads |

## Memory Analysis

| Volatility3 Plugin | MCP Tool Name | Description |
|---|---|---|
| `windows.malfind` | `windows_malfind` | Detect potentially injected code in process memory |
| `windows.vadinfo` | `windows_vadinfo` | List process memory ranges (VAD) |
| `windows.vadwalk` | `windows_vadwalk` | Walk the VAD tree |
| `windows.memmap` | `windows_memmap` | Print the memory map |
| `windows.virtmap` | `windows_virtmap` | List virtual mapped sections |
| `windows.strings` | `windows_strings` | Map strings output to processes |

## Module / DLL Analysis

| Volatility3 Plugin | MCP Tool Name | Description |
|---|---|---|
| `windows.dlllist` | `windows_dlllist` | List loaded modules per process |
| `windows.ldrmodules` | `windows_ldrmodules` | List loaded modules (detects unlinked DLLs) |
| `windows.modules` | `windows_modules` | List loaded kernel modules |
| `windows.modscan` | `windows_modscan` | Scan for kernel modules by pool tag |
| `windows.verinfo` | `windows_verinfo` | List version information from PE files |
| `windows.iat` | `windows_iat` | Extract Import Address Table |

## Network Analysis

| Volatility3 Plugin | MCP Tool Name | Description |
|---|---|---|
| `windows.netscan` | `windows_netscan` | Scan for network objects by pool tag |
| `windows.netstat` | `windows_netstat` | Traverse network tracking structures |

## Kernel / Driver Analysis

| Volatility3 Plugin | MCP Tool Name | Description |
|---|---|---|
| `windows.bigpools` | `windows_bigpools` | List big page pool allocations |
| `windows.callbacks` | `windows_callbacks` | List kernel callbacks and notification routines |
| `windows.driverscan` | `windows_driverscan` | Scan for driver objects |
| `windows.driverirp` | `windows_driverirp` | List IRPs for drivers |
| `windows.drivermodule` | `windows_drivermodule` | Detect hidden driver modules |
| `windows.devicetree` | `windows_devicetree` | List device tree by drivers |
| `windows.ssdt` | `windows_ssdt` | List system call table |
| `windows.poolscanner` | `windows_poolscanner` | Generic pool scanner |

## File Analysis

| Volatility3 Plugin | MCP Tool Name | Description |
|---|---|---|
| `windows.filescan` | `windows_filescan` | Scan for file objects |
| `windows.dumpfiles` | `windows_dumpfiles` | Dump cached file contents |
| `windows.symlinkscan` | `windows_symlinkscan` | Scan for symbolic links |
| `windows.mutantscan` | `windows_mutantscan` | Scan for mutexes |

## Registry Analysis

| Volatility3 Plugin | MCP Tool Name | Description |
|---|---|---|
| `windows.registry.hivelist` | `windows_registry_hivelist` | List registry hives |
| `windows.registry.hivescan` | `windows_registry_hivescan` | Scan for registry hives |
| `windows.registry.printkey` | `windows_registry_printkey` | Print registry keys and values |
| `windows.registry.userassist` | `windows_registry_userassist` | Print UserAssist registry data |
| `windows.registry.certificates` | `windows_registry_certificates` | List certificates from registry store |

## System Information

| Volatility3 Plugin | MCP Tool Name | Description |
|---|---|---|
| `windows.info` | `windows_info` | OS version, architecture, kernel details |
| `windows.statistics` | `windows_statistics` | Memory space statistics |
| `windows.crashinfo` | `windows_crashinfo` | Windows crash dump information |

## Security / Malware

| Volatility3 Plugin | MCP Tool Name | Description |
|---|---|---|
| `windows.skeleton_key_check` | `windows_skeleton_key_check` | Detect Skeleton Key malware |
| `windows.mbrscan` | `windows_mbrscan` | Scan for Master Boot Records |
| `windows.truecrypt` | `windows_truecrypt` | Find TrueCrypt cached passphrases |
| `windows.getservicesids` | `windows_getservicesids` | List process token service SIDs |

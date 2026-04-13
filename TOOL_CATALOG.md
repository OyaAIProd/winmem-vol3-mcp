# Volatility3 Windows Plugin Catalog

61 plugins from `volatility3.plugins.windows.*` (v2.27.0) are integrated
as MCP tools. The remaining v2.27.0 plugins are tracked in `plan.md`.

## Naming Convention

MCP tool names mirror the Volatility3 plugin name for easy identification.
Format: `windows_{plugin_name}` (e.g., `windows.pslist` -> `windows_pslist`).
Sub-namespace plugins follow `windows_{namespace}_{name}`:
- `windows.registry.*` -> `windows_registry_{name}`
- `windows.malware.*` -> `windows_malware_{name}`

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
| `windows.threads` | `windows_threads` | List per-process threads via thread list walk |

## Memory Analysis

| Volatility3 Plugin | MCP Tool Name | Description |
|---|---|---|
| `windows.vadinfo` | `windows_vadinfo` | List process memory ranges (VAD) |
| `windows.vadwalk` | `windows_vadwalk` | Walk the VAD tree |
| `windows.memmap` | `windows_memmap` | Print the memory map |
| `windows.virtmap` | `windows_virtmap` | List virtual mapped sections |
| `windows.strings` | `windows_strings` | Map strings output to processes |
| `windows.shimcachemem` | `windows_shimcachemem` | Recover Shimcache / AppCompatCache from kernel memory (evidence of execution) |
| `windows.vadregexscan` | `windows_vadregexscan(pattern, maxsize=128)` | Scan every process VAD for a regex (parameterized) |

## Module / DLL Analysis

| Volatility3 Plugin | MCP Tool Name | Description |
|---|---|---|
| `windows.dlllist` | `windows_dlllist` | List loaded modules per process |
| `windows.modules` | `windows_modules` | List loaded kernel modules |
| `windows.modscan` | `windows_modscan` | Scan for kernel modules by pool tag |
| `windows.verinfo` | `windows_verinfo` | List version information from PE files |
| `windows.iat` | `windows_iat` | Extract Import Address Table |
| `windows.pe_symbols` | `windows_pe_symbols(source, module, symbols="", addresses="")` | Resolve PE symbol names <-> addresses (parameterized) |
| `windows.pedump` | `windows_pedump(base, pid=0, kernel_module=False)` | Reconstruct a PE at base to VOL_DUMP_DIR (parameterized) |

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
| `windows.devicetree` | `windows_devicetree` | List device tree by drivers |
| `windows.ssdt` | `windows_ssdt` | List system call table |
| `windows.poolscanner` | `windows_poolscanner` | Generic pool scanner |
| `windows.orphan_kernel_threads` | `windows_orphan_kernel_threads` | Detect kernel threads not mapped to any module (rootkit indicator) |

## File Analysis

| Volatility3 Plugin | MCP Tool Name | Description |
|---|---|---|
| `windows.filescan` | `windows_filescan` | Scan for file objects |
| `windows.dumpfiles` | `windows_dumpfiles(pid, filter, filter_ignore_case, virtaddr, physaddr)` | Dump cached file contents to VOL_DUMP_DIR (parameterized) |
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
| `windows.registry.scheduled_tasks` | `windows_registry_scheduled_tasks` | Decode Task Scheduler entries (persistence indicator) |
| `windows.registry.getcellroutine` | `windows_registry_getcellroutine` | Detect hives with hooked GetCellRoutine handler (registry rootkit) |
| `windows.registry.amcache` | `windows_registry_amcache` | Decode AmCache.hve application execution records (SHA1, timestamps) |

## Service Analysis

| Volatility3 Plugin | MCP Tool Name | Description |
|---|---|---|
| `windows.svcscan` | `windows_svcscan` | Enumerate Windows services by scanning services.exe |
| `windows.svclist` | `windows_svclist` | List services via services.exe linked list (Win10 15063+ x64 only) |

## System Information

| Volatility3 Plugin | MCP Tool Name | Description |
|---|---|---|
| `windows.info` | `windows_info` | OS version, architecture, kernel details |
| `windows.statistics` | `windows_statistics` | Memory space statistics |
| `windows.crashinfo` | `windows_crashinfo` | Windows crash dump information |

## Security / Integrity

| Volatility3 Plugin | MCP Tool Name | Description |
|---|---|---|
| `windows.mbrscan` | `windows_mbrscan` | Scan for Master Boot Records |
| `windows.truecrypt` | `windows_truecrypt` | Find TrueCrypt cached passphrases |
| `windows.getservicesids` | `windows_getservicesids` | List process token service SIDs |
| `windows.suspended_threads` | `windows_suspended_threads` | Detect never-resumed suspended threads (hollowing / EDR evasion) |

## Malware Detection

Canonical `windows.malware.*` plugins for advanced rootkit / injection /
evasion detection. The legacy `windows.*` aliases (drivermodule, ldrmodules,
malfind, skeleton_key_check) are deprecated `PluginRenameClass` wrappers
for these and will be removed by the Volatility Foundation on 2026-06-07.

| Volatility3 Plugin | MCP Tool Name | Description |
|---|---|---|
| `windows.malware.drivermodule` | `windows_malware_drivermodule` | Detect hidden driver modules |
| `windows.malware.ldrmodules` | `windows_malware_ldrmodules` | List loaded modules (detects unlinked DLLs) |
| `windows.malware.malfind` | `windows_malware_malfind` | Detect potentially injected code in process memory |
| `windows.malware.skeleton_key_check` | `windows_malware_skeleton_key_check` | Detect Skeleton Key malware |

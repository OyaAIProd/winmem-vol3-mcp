# Volatility3 MCP Server — Development Plan

## 0. Remaining Plugin Implementation

49 plugins from v2.7.0 are fully integrated. After upgrading to v2.27.0,
42 new plugins were initially identified. Investigation revealed **6 of these
are deprecated `PluginRenameClass` wrappers** that redirect to canonical
implementations elsewhere. These wrappers are excluded to avoid duplicate
MCP tools and deprecation warnings. Effective total: **36 plugins**.

Deprecated wrappers dropped (kept only under their canonical path):
- `windows.suspicious_threads` → canonical `windows.malware.suspicious_threads`
- `windows.psxview` → canonical `windows.malware.psxview`
- `windows.hollowprocesses` → canonical `windows.malware.hollowprocesses`
- `windows.processghosting` → canonical `windows.malware.processghosting`
- `windows.svcdiff` → canonical `windows.malware.svcdiff`
  (already in Malware category; Service duplicate dropped)
- `windows.scheduled_tasks` → canonical `windows.registry.scheduled_tasks`
  (this deprecated alias is redundant with the registry.* version already
  in the plan; expose only the canonical path)

New plugins by category (36 total):

- **Malware** (11): malware.drivermodule, malware.hollowprocesses,
  malware.ldrmodules, malware.malfind, malware.pebmasquerade,
  malware.processghosting, malware.psxview, malware.skeleton_key_check,
  malware.suspicious_threads, malware.svcdiff, malware.unhooked_system_calls
- **Process** (3): threads, orphan_kernel_threads, suspended_threads
- **Service** (3): svclist, svcscan, registry.scheduled_tasks
- **Registry** (3): registry.amcache, registry.getcellroutine, amcache
- **Kernel** (6): debugregisters, etwpatch, kpcrs, timers,
  unhooked_system_calls, unloadedmodules
- **Desktop/GUI** (3): deskscan, desktops, windowstations
- **Memory** (2): vadregexscan, shimcachemem
- **Module** (2): pe_symbols, pedump
- **Other** (3): cmdscan, consoles, windows

Work should continue on the `plugin` branch using the same pattern:
create a category sub-branch, implement one plugin per commit, merge back.

### History

- **2026-04-13** — Process category reduced from 7 → 3 after confirming that
  `suspicious_threads`, `psxview`, `hollowprocesses`, `processghosting` under
  `volatility3.plugins.windows.*` are deprecated `PluginRenameClass` wrappers
  (`removal_date="2026-06-07"`) that redirect to `windows.malware.*` canonical
  implementations. Implementing both would create duplicate MCP tools and emit
  deprecation warnings. Canonical versions will be covered in Malware category.
  Total new plugins: 42 → 38.
- **2026-04-13** — Service category reduced from 5 → 3. `windows.svcdiff` is a
  deprecated wrapper for `windows.malware.svcdiff` (`removal_date="2026-06-07"`),
  and that canonical version is already listed in the Malware category — the
  Service entry would be a duplicate. `windows.scheduled_tasks` is a deprecated
  wrapper for `windows.registry.scheduled_tasks` (`removal_date="2026-09-25"`),
  and the registry.* canonical version is already listed in the same Service
  entry — the alias was a redundant second exposure of the same plugin.
  Total new plugins: 38 → 36.

---

Beyond wrapping individual plugins (engineering work), the project needs
research-grade contributions to target DFRWS. The four directions below are
ordered by research impact.

---

## 1. Cross-plugin Correlation Tools (Highest Research Value)

No existing MCP implementation performs cross-plugin correlation.
Compound tools execute deterministic forensic logic on the server side,
guaranteeing reproducibility and accuracy — unlike relying on LLM reasoning
alone.

Planned compound tools:

- **`detect_hidden_processes`** — Automatically compare pslist vs psscan and
  return processes present only in psscan (DKOM / rootkit indicator).
- **`triage_process(pid)`** — Collect cmdline + dlllist + handles + netscan +
  malfind for a single PID in one call, returning a consolidated view.
- **`detect_process_anomalies`** — Flag known-bad patterns: svchost.exe not
  parented by services.exe, name masquerading (svchost vs svch0st), unusual
  session IDs, etc.
- **`build_timeline`** — Merge timestamps from process creation/exit, network
  connections, and other artifacts into a single chronological sequence.

## 2. Evaluation Framework (Required for Paper Acceptance)

Quantitative evaluation is mandatory for any systems paper.

- **CTF-based benchmark** — Use publicly available CTF memory images with
  known ground-truth answers. Compare this project against Gaffx/volatility-mcp,
  bornpresident/Volatility-MCP-Server, and manual Volatility3 CLI analysis.
- **Metrics** — Accuracy (correct answers / total questions), response latency,
  tool call count, incorrect tool selection rate.
- **Docstring quality experiment** — A/B test Claude's analysis quality with
  and without Layer 3 (forensic context) in tool docstrings to measure the
  impact of forensic hints on LLM-driven analysis.

## 3. Forensic Report Generation (Practical Completeness)

Automated report generation demonstrates end-to-end forensic workflow support.

- **Session analysis log** — Track which tools were called, in what order, and
  summarize each result.
- **IOC extraction** — Aggregate suspicious IPs, processes, DLLs, and other
  indicators discovered during analysis into a structured output.
- **Report templates** — Produce structured output (JSON + Markdown) suitable
  for DFRWS or court submission formats.
- **Evidence chain** — Record which plugin result supported which analytical
  conclusion, enabling auditability.

## 4. Performance Optimization (Scale-dependent)

Becomes meaningful as plugin count grows toward 49.

- **Parallel plugin execution** — Run independent plugins concurrently
  (e.g., pslist and netscan have no dependency on each other).
- **Dependency-aware scheduling** — When a correlation tool needs multiple
  plugins, dispatch them in parallel and merge results.
- **Lazy vs eager loading** — Pre-warm only essential plugins (info, pslist)
  at session start; run everything else on demand.

---

## Priority Summary

| Priority | Direction                    | Rationale                                      |
|----------|------------------------------|-------------------------------------------------|
| 1        | Cross-plugin Correlation     | Core differentiator; absent from all prior work |
| 2        | Evaluation Framework         | Required for paper acceptance                   |
| 3        | Forensic Report Generation   | Practical completeness + system contribution    |
| 4        | Performance Optimization     | Relevant after plugin count scales up           |

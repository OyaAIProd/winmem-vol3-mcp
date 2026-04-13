# Volatility3 MCP Server — Development Plan

## Resume here (next session entry point)

Plugin-coverage work (Section 0) is **complete** as of 2026-04-13.
The next milestone is research-grade work for the DFRWS paper. Pick
up at the section that matches your current focus:

1. **Cross-plugin Correlation Tools** — start here for the highest-impact
   research contribution (Section 1).
2. **Evaluation Framework** — required for paper acceptance (Section 2).
3. **Forensic Report Generation** — analyst-facing deliverable (Section 3).
4. **Performance Optimization** — scale-dependent polish (Section 4).

Recommended first sub-task: implement `detect_hidden_processes`
(pslist vs psscan diff) in Section 1 — small, demonstrates the
correlation-tool pattern, and exercises the existing
`session.run_plugin()` cache.

---

## 0. Remaining Plugin Implementation

**Status (2026-04-13): COMPLETE.** All 79 non-deprecated Windows plugins
in volatility3 v2.27.0 are integrated as MCP tools. The v2.7.0 baseline of
49 plugins was extended by 30 new tools (34 fresh plugins minus 4 already
shipped under their canonical `windows_malware_*` names during the rename
audit). The 8 deprecated `PluginRenameClass` wrappers (`removal_date`
2026-06-07 / 2026-09-25) were intentionally excluded so the MCP surface
exposes only canonical paths.

Original investigation found 42 new plugins after the v2.27.0 upgrade;
**8 turned out to be deprecated wrappers** redirecting to canonical
implementations elsewhere — excluded to avoid duplicate MCP tools and
deprecation warnings. Effective new total implemented: **34 plugins**.

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
- `windows.amcache` → canonical `windows.registry.amcache`
  (same duplicate-alias pattern; only expose the registry.* canonical)
- `windows.unhooked_system_calls` → canonical
  `windows.malware.unhooked_system_calls` (already in the Malware category;
  Kernel duplicate dropped)

New plugins by category (34 total):

- **Malware** (7 remaining; 4 already shipped under `windows_malware_*`):
  malware.hollowprocesses, malware.pebmasquerade, malware.processghosting,
  malware.psxview, malware.suspicious_threads, malware.svcdiff,
  malware.unhooked_system_calls. Already implemented (migrated from the
  deprecated `windows.*` aliases during the 2026-04-13 rename audit):
  malware.drivermodule, malware.ldrmodules, malware.malfind,
  malware.skeleton_key_check.
- **Process** (3): threads, orphan_kernel_threads, suspended_threads
- **Service** (3): svclist, svcscan, registry.scheduled_tasks
- **Registry** (2): registry.amcache, registry.getcellroutine
- **Kernel** (5): debugregisters, etwpatch, kpcrs, timers, unloadedmodules
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
- **2026-04-13** — Registry category reduced from 3 → 2. `windows.amcache` is a
  deprecated wrapper for `windows.registry.amcache` (`removal_date="2026-09-25"`),
  and the registry.* canonical version is already listed in the same Registry
  entry — same duplicate-alias pattern as `windows.scheduled_tasks`. Drop the
  deprecated alias; expose only the canonical `windows.registry.amcache`.
  Total new plugins: 36 → 35.
- **2026-04-13** — Audited all 57 already-shipped MCP tools for deprecation.
  Found 4 that were built against the deprecated `windows.*` classes rather
  than the canonical `windows.malware.*` implementations: `drivermodule`,
  `ldrmodules`, `malfind`, `skeleton_key_check`. Renamed the MCP tools to
  `windows_malware_*` and switched the internal class references to
  `windows.malware.*`, matching the naming convention that will be used for
  the remaining 7 malware plugins. This reduces outstanding Malware work
  from 11 → 7 (since these 4 are effectively already implemented under the
  correct names). Total new plugins still 35.
- **2026-04-13** — Kernel category reduced from 6 → 5.
  `windows.unhooked_system_calls` is a deprecated `PluginRenameClass`
  wrapper (`removal_date="2026-06-07"`) for
  `windows.malware.unhooked_system_calls.UnhookedSystemCalls`, which is
  already listed in the Malware category. Dropping the Kernel alias avoids
  the duplicate MCP tool. Total new plugins: 35 → 34.
- **2026-04-13** — v2.27.0 plugin coverage **complete**: 79/79
  non-deprecated Windows plugins are now exposed as MCP tools across
  all categories (Malware, Process, Service, Registry, Kernel,
  Desktop/GUI, Memory, Module, Other). Future plugin work depends on
  upstream volatility3 releases adding new windows.* / windows.malware.*
  modules; section 0 will be reopened then.

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

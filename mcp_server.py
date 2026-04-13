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

# Optional on-disk directory for dump plugins (dumpfiles, pedump, ...). When
# unset, calling any dump tool will raise with a clear message. When set,
# binary extractions land in this directory; it is created on first use.
DUMP_DIR = os.environ.get("VOL_DUMP_DIR", "")

mcp = FastMCP("winmem-vol3-mcp")
session = Session(IMAGE_PATH, dump_dir=DUMP_DIR)


@mcp.tool()
def windows_info() -> dict:
    """
    Retrieve system information from the Windows memory image, including
    OS version, architecture, and kernel details.

    Use this tool when the user asks about:
    - What operating system or Windows version the memory image is from
    - System architecture (32-bit vs 64-bit)
    - Kernel or NT build information
    - General information about the captured machine
    - When to start analysis (call this first to warm up the session)

    Returns a dict with:
    - "plugin": "info"
    - "results": dict of key-value pairs, where each key is a system variable
      name (str) and each value is the corresponding system value (str).
      Typical keys include: "Kernel Base", "DTB", "Is64Bit", "IsPAE",
      "NTBuildLab", "NTBuildLabEx", "NtMajorVersion", "NtMinorVersion", etc.

    Forensic context:
    - Call this tool first in any analysis session; it initializes internal
      configuration and caches it, making all subsequent plugin calls faster
    - Use the OS version to determine which artifacts and behaviors are expected
      (e.g., Windows 7 vs Windows 10 have different default processes)
    - The "Is64Bit" value determines whether WoW64 fields from windows_pslist
      or windows_psscan are meaningful
    """
    return session.run_plugin("info")


@mcp.tool()
def windows_pslist() -> dict:
    """
    Run the pslist plugin to enumerate processes from the Windows memory image
    by walking the active process linked list (EPROCESS doubly-linked list).

    Use this tool when the user asks about:
    - Running processes or active programs
    - Process list or what applications were open at the time of capture
    - A specific process by name or PID
    - Process counts, thread counts, or handle counts
    - Process creation or exit times

    Returns a dict with:
    - "plugin": "pslist"
    - "results": list of dicts, each containing:
        "PID": process ID (int),
        "PPID": parent process ID (int),
        "ImageFileName": process name (str),
        "Threads": thread count (int),
        "Handles": handle count (int),
        "SessionId": terminal session ID (int or None),
        "Wow64": whether process is 32-bit on 64-bit OS (bool),
        "CreateTime": process creation timestamp (str),
        "ExitTime": process exit timestamp (str or None),
        "File output": file dump status (str)

    Forensic context:
    - Compare with windows_psscan results to detect hidden or unlinked processes;
      a process found by windows_psscan but missing from windows_pslist suggests
      DKOM (Direct Kernel Object Manipulation) or rootkit activity
    - Use PID values from this output as context when investigating specific
      processes with future tools (e.g., cmdline, dlllist, handles)
    - Unusual parent-child relationships (e.g., svchost.exe not parented by
      services.exe, or cmd.exe spawned by a browser) may indicate process
      injection, lateral movement, or malware execution
    - Use windows_pstree for a hierarchical view of the same data
    """
    return session.run_plugin("pslist")


@mcp.tool()
def windows_psscan() -> dict:
    """
    Run the psscan plugin to find processes by scanning for pool tags in
    physical memory, independent of the OS-maintained process list.

    Use this tool when the user asks about:
    - Hidden, terminated, or unlinked processes
    - Rootkit detection or anti-forensics analysis
    - Processes that may have been removed from the active process list
    - A more thorough or exhaustive process scan
    - DKOM (Direct Kernel Object Manipulation) detection

    Returns a dict with:
    - "plugin": "psscan"
    - "results": list of dicts, each containing:
        "PID": process ID (int),
        "PPID": parent process ID (int),
        "ImageFileName": process name (str),
        "Threads": thread count (int),
        "Handles": handle count (int),
        "SessionId": terminal session ID (int or None),
        "Wow64": whether process is 32-bit on 64-bit OS (bool),
        "CreateTime": process creation timestamp (str),
        "ExitTime": process exit timestamp (str or None),
        "File output": file dump status (str)

    Forensic context:
    - Compare this result set against windows_pslist output: any process present
      here but absent from windows_pslist was unlinked from the active process
      list, which is a strong indicator of rootkit or DKOM activity
    - Terminated processes (with ExitTime set) appear here but not in
      windows_pslist, which is normal — focus on processes without ExitTime
      that are missing from windows_pslist
    - Pool tag scanning operates on physical memory and does not rely on OS
      data structures, making it resistant to kernel-level manipulation
    - Use windows_pstree to visualize parent-child relationships for any
      suspicious PIDs discovered through this scan
    """
    return session.run_plugin("psscan")


@mcp.tool()
def windows_pstree() -> dict:
    """
    Run the pstree plugin to display processes in a parent-child hierarchy
    with depth information, showing how processes were spawned.

    Use this tool when the user asks about:
    - Process tree or process hierarchy
    - Parent-child process relationships
    - Which process spawned which other process
    - Process lineage or ancestry of a specific process
    - Visual or structural overview of running processes

    Returns a dict with:
    - "plugin": "pstree"
    - "results": list of dicts, each containing:
        "PID": process ID (int),
        "PPID": parent process ID (int),
        "ImageFileName": process name (str),
        "Threads": thread count (int),
        "Handles": handle count (int),
        "SessionId": terminal session ID (int or None),
        "Wow64": whether process is 32-bit on 64-bit OS (bool),
        "CreateTime": process creation timestamp (str),
        "ExitTime": process exit timestamp (str or None),
        "Audit": audit name from the SE_AUDIT_PROCESS_CREATION_INFO (str),
        "Cmd": command line from the process parameters (str),
        "Path": image path from the process parameters (str),
        "depth": nesting depth in the tree (int, 0 = root process)

    Forensic context:
    - The "depth" field encodes the tree structure: depth 0 processes are root
      nodes (System, smss.exe), and each increment represents one level of
      parent-child nesting
    - Suspicious patterns include: svchost.exe not under services.exe,
      cmd.exe or powershell.exe spawned by browser or Office processes,
      or deeply nested process chains used to evade detection
    - Compare with windows_psscan to check whether any parent PIDs reference
      processes that have been unlinked or terminated (broken ancestry)
    - Use windows_pslist for a flat list when tree structure is not needed
    """
    return session.run_plugin("pstree")


@mcp.tool()
def windows_cmdline() -> dict:
    """
    Run the cmdline plugin to extract command line arguments for each process.

    Use this tool when the user asks about:
    - Command line arguments or parameters passed to a process
    - How a process was launched or invoked
    - Suspicious command line patterns (encoded PowerShell, LOLBins, etc.)
    - What commands were executed on the system
    - Process execution context or launch parameters

    Returns a dict with:
    - "plugin": "cmdline"
    - "results": list of dicts, each containing:
        "PID": process ID (int),
        "Process": process name (str),
        "Args": full command line string (str)

    Forensic context:
    - Encoded PowerShell commands (powershell -enc ...) are a strong malware
      indicator and should be decoded for further analysis
    - LOLBin abuse patterns (certutil -urlcache, mshta, regsvr32, rundll32
      with URLs) suggest living-off-the-land techniques
    - Use windows_pslist to get full process metadata (PPID, timestamps) for
      processes with suspicious command lines
    - Compare with windows_dlllist to correlate loaded modules against the
      command line intent (e.g., unexpected DLLs in a benign-looking process)
    """
    return session.run_plugin("cmdline")


@mcp.tool()
def windows_envars() -> dict:
    """
    Run the envars plugin to display environment variables for each process.

    Use this tool when the user asks about:
    - Environment variables set for a process
    - PATH, TEMP, COMPUTERNAME, USERNAME, or other env vars
    - System or user environment configuration at the time of capture
    - Malware persistence via environment variable manipulation
    - Process execution context or runtime environment

    Returns a dict with:
    - "plugin": "envars"
    - "results": list of dicts, each containing:
        "PID": process ID (int),
        "Process": process name (str),
        "Block": environment block address (str),
        "Variable": environment variable name (str),
        "Value": environment variable value (str)

    Forensic context:
    - COMPUTERNAME and USERNAME reveal the machine and logged-in user at
      capture time, useful for attribution and lateral movement analysis
    - Unusual PATH entries or injected variables may indicate persistence
      mechanisms (e.g., DLL search order hijacking via modified PATH)
    - Compare environment blocks across processes: malware-spawned processes
      may inherit distinctive variables from their parent
    - Use windows_cmdline to correlate environment variables with the actual
      command line used to launch each process
    """
    return session.run_plugin("envars")


@mcp.tool()
def windows_getsids() -> dict:
    """
    Run the getsids plugin to list Security Identifiers (SIDs) associated
    with each process token.

    Use this tool when the user asks about:
    - Which user or account owns a process
    - Process security identifiers or SIDs
    - Privilege escalation or token manipulation evidence
    - Whether a process is running as SYSTEM, Administrator, or a regular user
    - User account context of running processes

    Returns a dict with:
    - "plugin": "getsids"
    - "results": list of dicts, each containing:
        "PID": process ID (int),
        "Process": process name (str),
        "SID": security identifier string (str),
        "Name": human-readable SID name (str)

    Forensic context:
    - Processes running under unexpected SIDs (e.g., a user-launched process
      with SYSTEM SID) may indicate privilege escalation or token theft
    - Well-known SIDs: S-1-5-18 (SYSTEM), S-1-5-19 (LOCAL SERVICE),
      S-1-5-20 (NETWORK SERVICE) — compare against expected process owners
    - Use windows_pslist to identify the process, then this tool to verify
      its security context
    - Cross-reference with windows_privileges to build a complete picture
      of a process's security posture
    """
    return session.run_plugin("getsids")


@mcp.tool()
def windows_handles() -> dict:
    """
    Run the handles plugin to list open handles for each process, including
    files, registry keys, mutexes, events, and other kernel objects.

    Use this tool when the user asks about:
    - What files, registry keys, or mutexes a process has open
    - Open handles or kernel object references held by a process
    - File locks, named pipes, or shared resources in use
    - Mutex-based malware indicators (unique mutex names for C2 signaling)
    - Resource usage or inter-process communication patterns

    Returns a dict with:
    - "plugin": "handles"
    - "results": list of dicts, each containing:
        "PID": process ID (int),
        "Process": process name (str),
        "Offset": handle table entry offset (str, hex),
        "HandleValue": handle value (str, hex),
        "Type": object type such as File, Key, Mutant, Event (str),
        "GrantedAccess": access mask (str, hex),
        "Name": object name or path (str)

    Forensic context:
    - Unique mutex (Mutant) names are classic malware indicators; many malware
      families create a named mutex to prevent multiple instances
    - File handles reveal which files a process is reading or writing,
      useful for identifying data exfiltration or ransomware activity
    - Registry key handles (Type=Key) show what configuration a process is
      accessing, including persistence locations (Run keys, Services)
    - Use windows_pslist to identify the process, then this tool to
      understand what resources it is actively using
    """
    return session.run_plugin("handles")


@mcp.tool()
def windows_joblinks() -> dict:
    """
    Run the joblinks plugin to display process job object associations,
    showing how processes are grouped into Windows job objects.

    Use this tool when the user asks about:
    - Process job objects or job grouping
    - Process resource limits or job-based restrictions
    - Sandbox or container boundaries for processes
    - Relationships between processes within the same job
    - Active, terminated, or total process counts within a job

    Returns a dict with:
    - "plugin": "joblinks"
    - "results": list of dicts, each containing:
        "Name": job object name (str),
        "PID": process ID (int),
        "PPID": parent process ID (int),
        "Sess": session ID (int),
        "JobSess": job session ID (int),
        "Wow64": whether process is 32-bit on 64-bit OS (bool),
        "Total": total processes assigned to the job (int),
        "Active": currently active processes in the job (int),
        "Term": terminated processes in the job (int),
        "JobLink": job link chain description (str),
        "Process": process name (str)

    Forensic context:
    - Sandboxed applications (browsers, Office) use job objects to limit
      child processes; unexpected processes outside the job may indicate
      sandbox escape
    - Malware may create job objects to manage its spawned processes as a
      group, making job analysis useful for identifying process clusters
    - Use windows_pstree to visualize parent-child hierarchy and compare
      with job grouping to find discrepancies
    - Cross-reference with windows_pslist for full process metadata
    """
    return session.run_plugin("joblinks")


@mcp.tool()
def windows_privileges() -> dict:
    """
    Run the privileges plugin to list token privileges for each process.

    Use this tool when the user asks about:
    - Process privileges or token permissions
    - Privilege escalation indicators (SeDebugPrivilege, SeImpersonatePrivilege)
    - Whether a process has elevated or dangerous privileges enabled
    - Security token analysis for a specific process
    - Enabled vs disabled privileges in a process context

    Returns a dict with:
    - "plugin": "privileges"
    - "results": list of dicts, each containing:
        "PID": process ID (int),
        "Process": process name (str),
        "Value": privilege numeric value (int),
        "Privilege": privilege name such as SeDebugPrivilege (str),
        "Attributes": privilege state like Present/Enabled/Default (str),
        "Description": human-readable description of the privilege (str)

    Forensic context:
    - SeDebugPrivilege enabled in a non-administrative process is a strong
      indicator of privilege escalation or token manipulation
    - SeImpersonatePrivilege and SeAssignPrimaryTokenPrivilege are commonly
      abused in potato-style privilege escalation attacks
    - Compare Attributes field: "Present, Enabled, Default" vs "Present" —
      privileges that are enabled but not default may have been explicitly
      activated by an attacker
    - Use windows_getsids to correlate privilege levels with the actual
      user/group SIDs owning the process token
    """
    return session.run_plugin("privileges")


@mcp.tool()
def windows_sessions() -> dict:
    """
    Run the sessions plugin to list processes grouped by their logon session,
    including session type and associated user name.

    Use this tool when the user asks about:
    - Who was logged into the system at the time of capture
    - Which user session a process belongs to
    - Remote Desktop (RDP) or console sessions
    - Active logon sessions and their associated processes
    - Session types (Console, Services, RDP-Tcp)

    Returns a dict with:
    - "plugin": "sessions"
    - "results": list of dicts, each containing:
        "Session ID": terminal session ID (int),
        "Session Type": session type such as Console or Services (str),
        "Process ID": process ID (int),
        "Process": process name (str),
        "User Name": domain\\username of the session owner (str),
        "Create Time": process creation timestamp (str)

    Forensic context:
    - Multiple active RDP-Tcp sessions may indicate lateral movement or
      unauthorized remote access
    - Processes in Session 0 (Services) are system-level; user processes
      typically appear in Session 1+
    - Compare user names across sessions to detect compromised accounts or
      unauthorized logon activity
    - Use windows_pslist for full process details and windows_envars to
      extract USERNAME/COMPUTERNAME for each session context
    """
    return session.run_plugin("sessions")


@mcp.tool()
def windows_thrdscan() -> dict:
    """
    Run the thrdscan plugin to scan for thread objects in physical memory
    using pool tag scanning.

    Use this tool when the user asks about:
    - Threads running on the system or within a specific process
    - Thread start addresses or entry points
    - Hidden or orphaned threads not linked to any process
    - Thread creation and exit timestamps
    - Thread injection or suspicious thread activity

    Returns a dict with:
    - "plugin": "thrdscan"
    - "results": list of dicts, each containing:
        "Offset": physical offset of the ETHREAD structure (str, hex),
        "PID": owning process ID (int),
        "TID": thread ID (int),
        "StartAddress": thread start address (str, hex),
        "StartPath": module path containing the start address (str),
        "Win32StartAddress": Win32 thread start address (str, hex),
        "Win32StartPath": module path containing the Win32 start address (str),
        "CreateTime": thread creation timestamp (str),
        "ExitTime": thread exit timestamp (str or None)

    Forensic context:
    - Threads with start addresses outside any known module range may
      indicate injected code (remote thread injection via CreateRemoteThread)
    - Orphaned threads (PID referencing a non-existent process) suggest the
      parent process was terminated or unlinked
    - Compare thread start addresses against windows_dlllist module ranges
      to identify threads executing from injected or unmapped memory
    - Use windows_pslist to resolve PID to process name for context
    """
    return session.run_plugin("thrdscan")


@mcp.tool()
def windows_threads() -> dict:
    """
    Run the threads plugin to enumerate process threads by walking each
    process's ThreadListHead linked list (the canonical active-thread view).

    Use this tool when the user asks about:
    - Which threads belong to a running process
    - Per-process thread enumeration or thread ownership
    - Active threads (as opposed to pool-scanned terminated threads)
    - Thread start addresses or entry points for live processes
    - Investigating a specific process's threads after spotting it in pslist

    Returns a dict with:
    - "plugin": "threads"
    - "results": list of dicts, each containing:
        "Offset": virtual offset of the ETHREAD structure (str, hex),
        "PID": owning process ID (int),
        "TID": thread ID (int),
        "StartAddress": thread start address (str, hex),
        "StartPath": module path containing the start address (str or None),
        "Win32StartAddress": Win32 thread start address (str, hex),
        "Win32StartPath": module path containing the Win32 start address
          (str or None),
        "CreateTime": thread creation timestamp (str),
        "ExitTime": thread exit timestamp (str or None)

    Forensic context:
    - Unlike windows_thrdscan (pool-tag scan that can surface terminated or
      unlinked threads), this plugin walks active thread lists, so results
      only reflect currently linked threads — compare the two to spot
      hidden/unlinked threads (presence in thrdscan but not threads)
    - Win32StartAddress pointing outside any legitimate module
      (Win32StartPath is None) is a classic indicator of remote thread
      injection (CreateRemoteThread / NtCreateThreadEx payloads)
    - Use the PID column to resolve to a process name via windows_pslist and
      its command line via windows_cmdline for fuller context
    - Cross-reference with windows_malware_malfind to correlate suspicious threads
      with injected memory regions in the same PID
    """
    return session.run_plugin("threads")


@mcp.tool()
def windows_orphan_kernel_threads() -> dict:
    """
    Run the orphan_kernel_threads plugin to detect kernel threads whose
    start address does not map to any loaded kernel module.

    Use this tool when the user asks about:
    - Rootkits, kernel-mode malware, or kernel implants
    - Kernel threads with no owning driver or module
    - Hidden kernel execution or unlinked kernel code
    - Suspicious activity inside the System process (PID 4)
    - Threads running from non-module kernel memory

    Returns a dict with:
    - "plugin": "orphan_kernel_threads"
    - "results": list of dicts, each containing:
        "Offset": virtual offset of the ETHREAD structure (str, hex),
        "PID": owning process ID, typically 4 (System) or a child kernel
          process such as MemCompression / Registry (int),
        "TID": thread ID (int),
        "StartAddress": kernel thread start address that does not resolve
          to any module (str, hex),
        "StartPath": module path — always None for orphans by definition,
        "Win32StartAddress": Win32 start address (str, hex),
        "Win32StartPath": Win32 module path (str or None),
        "CreateTime": thread creation timestamp (str),
        "ExitTime": thread exit timestamp (str or None)

    Forensic context:
    - Any non-empty result is high-signal: a kernel thread executing outside
      every loaded module is a strong rootkit indicator (e.g., manually
      mapped driver, DKOM-hidden module, shellcode injected into kernel
      memory pools)
    - The plugin filters aggressively (skips terminated/smeared threads and
      userland pointers) so findings are unlikely to be noise — investigate
      each result
    - Resolve the StartAddress against windows_modules and windows_modscan:
      presence in modscan but absence in modules suggests an unlinked module
      that owns the orphan thread
    - Correlate with windows_ssdt and windows_callbacks to find additional
      rootkit hooks tied to the same suspect memory region
    - Use windows_poolscanner to look for orphan kernel objects near the
      thread's start address
    """
    return session.run_plugin("orphan_kernel_threads")


@mcp.tool()
def windows_suspended_threads() -> dict:
    """
    Run the suspended_threads plugin to find userland threads whose
    SuspendCount is greater than zero and were never resumed.

    Use this tool when the user asks about:
    - Process hollowing, process doppelgänging, or EDR evasion indicators
    - Threads left in a suspended state (never resumed)
    - Signs of thread injection paused before execution
    - Anomalies relating to CreateProcess with CREATE_SUSPENDED
    - Detection of techniques described in the Volexity DEF CON 2024 paper

    Returns a dict with:
    - "plugin": "suspended_threads"
    - "results": list of dicts, each containing:
        "Process": owning process image name (str),
        "PID": process ID (int),
        "TID": thread ID (int),
        "StartFile": file path containing the thread start address
          (str or None),
        "StartSymbol": symbol at the thread start address (str or None),
        "StartAddress": thread start address (str, hex),
        "Win32StartFile": file path containing the Win32 start address
          (str or None),
        "Win32StartSymbol": symbol at the Win32 start address (str or None),
        "Win32StartAddress": Win32 thread start address (str, hex)

    Forensic context:
    - Legitimate code routinely creates threads suspended then resumes them;
      this plugin surfaces only threads still suspended at acquisition time,
      which is unusual and correlates strongly with hollowing / evasion
    - Suspended threads whose StartFile or Win32StartFile is None (start
      address outside any mapped module) indicate code running from an
      injected memory region — pair with windows_malware_malfind to confirm
    - The process hollowing pattern pairs a suspended main thread with an
      overwritten image base; correlate this plugin with windows_pslist
      and windows_dlllist to see whether the process's backing image has
      been swapped
    - If the suspended thread's PID also appears in windows_malware_malfind or its
      Win32StartAddress points into a VAD with RWX protection, escalate —
      this is a classic hollowing signature
    - `WorkFoldersShell.dll` is filtered out by the plugin as a known false
      positive, so any result here is after de-noising
    """
    return session.run_plugin("suspended_threads")


@mcp.tool()
def windows_malware_malfind() -> dict:
    """
    Run the malfind plugin to detect process memory regions that potentially
    contain injected code, based on VAD permissions and content heuristics.

    Use this tool when the user asks about:
    - Code injection or process injection detection
    - Suspicious executable memory regions in a process
    - Injected DLLs, shellcode, or reflective loading
    - Memory-resident malware or fileless malware indicators
    - Processes with anomalous memory protection flags (RWX)

    Returns a dict with:
    - "plugin": "malfind"
    - "results": list of dicts, each containing:
        "PID": process ID (int),
        "Process": process name (str),
        "Start VPN": start virtual page number (str, hex),
        "End VPN": end virtual page number (str, hex),
        "Tag": VAD pool tag (str),
        "Protection": memory protection flags such as PAGE_EXECUTE_READWRITE (str),
        "CommitCharge": number of committed pages (int),
        "PrivateMemory": whether memory is private (int),
        "File output": file dump status (str),
        "Notes": detection notes (str),
        "Hexdump": hex dump of the region header (str),
        "Disasm": disassembly of the region header (str)

    Forensic context:
    - PAGE_EXECUTE_READWRITE regions not backed by a file are the primary
      indicator of injected code (shellcode, reflective DLL loading)
    - The Hexdump and Disasm fields allow quick triage: look for MZ headers
      (injected PE) or common shellcode patterns (e.g., NOP sleds, API hashing)
    - Use windows_pslist to identify the affected process, then windows_dlllist
      to check if the region overlaps with any legitimate loaded module
    - Cross-reference with windows_handles to find related file or section
      objects that may reveal the injection source
    """
    return session.run_plugin("malware.malfind")


@mcp.tool()
def windows_vadinfo() -> dict:
    """
    Run the vadinfo plugin to list detailed Virtual Address Descriptor (VAD)
    information for each process, including memory-mapped files.

    Use this tool when the user asks about:
    - Virtual memory layout or address space of a process
    - Memory-mapped files or sections loaded by a process
    - VAD tree entries, memory protection, or commit charge
    - Which files are mapped into a process's address space
    - Detailed memory region metadata beyond what malfind shows

    Returns a dict with:
    - "plugin": "vadinfo"
    - "results": list of dicts, each containing:
        "PID": process ID (int),
        "Process": process name (str),
        "Offset": VAD node offset (str, hex),
        "Start VPN": start virtual page number (str, hex),
        "End VPN": end virtual page number (str, hex),
        "Tag": VAD pool tag (str),
        "Protection": memory protection flags (str),
        "CommitCharge": number of committed pages (int),
        "PrivateMemory": whether memory is private (int),
        "Parent": parent VAD node offset (str, hex),
        "File": path of the memory-mapped file if any (str),
        "File output": file dump status (str)

    Forensic context:
    - The File field reveals DLLs and executables mapped into memory that
      may not appear in windows_dlllist (e.g., manually mapped images)
    - Compare VAD protection flags with expected values: legitimate code
      sections are typically PAGE_EXECUTE_READ, not PAGE_EXECUTE_READWRITE
    - Use windows_malware_malfind for focused detection of injected regions; use
      this tool for comprehensive VAD enumeration
    - Cross-reference with windows_handles (Type=Section) to identify
      shared memory mappings between processes
    """
    return session.run_plugin("vadinfo")


@mcp.tool()
def windows_vadwalk() -> dict:
    """
    Run the vadwalk plugin to walk the VAD tree and display the binary tree
    structure of virtual address descriptors for each process.

    Use this tool when the user asks about:
    - VAD tree structure or binary tree layout
    - Parent, left, and right child relationships between VAD nodes
    - Low-level virtual memory organization of a process
    - VAD node addresses and their start/end ranges
    - Debugging memory layout or verifying VAD tree integrity

    Returns a dict with:
    - "plugin": "vadwalk"
    - "results": list of dicts, each containing:
        "PID": process ID (int),
        "Process": process name (str),
        "Offset": VAD node offset (str, hex),
        "Parent": parent VAD node offset (str, hex),
        "Left": left child VAD node offset (str, hex),
        "Right": right child VAD node offset (str, hex),
        "Start": start address of the region (str, hex),
        "End": end address of the region (str, hex),
        "Tag": VAD pool tag (str)

    Forensic context:
    - A corrupted VAD tree (broken parent/child links) may indicate kernel
      exploitation or memory corruption attacks
    - Use windows_vadinfo for richer metadata (protection, mapped files)
      per VAD entry; this tool focuses on the tree structure itself
    - Compare VAD node counts between windows_vadwalk and windows_vadinfo
      to detect inconsistencies that could signal manipulation
    - Use windows_malware_malfind for targeted detection of suspicious regions
      rather than walking the entire tree
    """
    return session.run_plugin("vadwalk")


@mcp.tool()
def windows_memmap() -> dict:
    """
    Run the memmap plugin to display the virtual-to-physical memory mapping
    for a process, showing how virtual addresses translate to physical offsets.

    Use this tool when the user asks about:
    - Virtual to physical address translation for a process
    - Memory map or physical memory layout of a process
    - Which physical pages back a process's virtual address space
    - Dumping process memory based on physical offsets
    - Memory page sizes and their file offsets in the image

    Returns a dict with:
    - "plugin": "memmap"
    - "results": list of dicts, each containing:
        "Virtual": virtual address (str, hex),
        "Physical": physical address in the memory image (str, hex),
        "Size": size of the mapping in bytes (str, hex),
        "Offset in File": offset within the memory image file (str, hex),
        "File output": file dump status (str)

    Forensic context:
    - Physical addresses can be used to locate data directly in the raw
      memory image file for manual hex analysis or carving
    - Large contiguous mappings may indicate memory-mapped files or large
      allocations worth investigating
    - Use windows_vadinfo for higher-level memory region metadata (protection,
      mapped files) rather than raw page-level mappings
    - This tool produces large result sets; use it for targeted investigation
      of specific processes identified through windows_pslist
    """
    return session.run_plugin("memmap")


@mcp.tool()
def windows_virtmap() -> dict:
    """
    Run the virtmap plugin to list virtual mapped sections of the kernel
    address space, showing how major kernel regions are laid out.

    Use this tool when the user asks about:
    - Kernel virtual address space layout
    - Mapped kernel regions and their address ranges
    - System address space organization (HAL, kernel, drivers, etc.)
    - Kernel memory boundaries or region sizes
    - Overview of how the OS organizes its virtual memory

    Returns a dict with:
    - "plugin": "virtmap"
    - "results": list of dicts, each containing:
        "Region": name or description of the mapped region (str),
        "Start offset": start virtual address of the region (str, hex),
        "End offset": end virtual address of the region (str, hex)

    Forensic context:
    - Kernel regions outside expected address ranges may indicate rootkit
      modifications or kernel memory patching
    - Compare region boundaries with known Windows kernel layout to detect
      anomalous mappings injected by rootkits
    - Use windows_modules and windows_driverscan to correlate driver load
      addresses with the virtual map regions
    - This provides a system-level overview; use windows_vadinfo for
      per-process virtual memory details
    """
    return session.run_plugin("virtmap")


@mcp.tool()
def windows_strings() -> dict:
    """
    Run the strings plugin to map output from the external strings command
    to the process that owns each string's physical memory location.

    Use this tool when the user asks about:
    - Which process owns a specific string found in memory
    - Mapping strings output to processes
    - Searching for URLs, IP addresses, or keywords in process memory
    - Attributing strings from a raw memory dump to specific processes
    - Correlating extracted strings with process activity

    Returns a dict with:
    - "plugin": "strings"
    - "results": list of dicts, each containing:
        "String": the extracted string content (str),
        "Physical Address": physical address where the string was found (str, hex),
        "Result": process(es) that map this physical address (str)

    Forensic context:
    - Requires a pre-generated strings file (from the external `strings`
      utility) passed via plugin configuration; without it, results will
      be empty
    - Strings attributed to unexpected processes (e.g., C2 URLs in a
      system process) are strong indicators of compromise
    - Use windows_pslist to resolve process names from the Result field
    - Cross-reference suspicious strings with windows_netscan to confirm
      network-related IOCs (IP addresses, domains, URLs)
    """
    return session.run_plugin("strings")


@mcp.tool()
def windows_shimcachemem() -> dict:
    """
    Run the shimcachemem plugin to recover the Application Compatibility
    Cache (Shimcache / AppCompatCache) from live kernel memory.

    Use this tool when the user asks about:
    - Evidence of past program execution (what EXEs ran on this system)
    - Shimcache, AppCompatCache, or Application Compatibility entries
    - Program execution history beyond what pslist shows (historical)
    - Investigator questions like "did foo.exe ever run here?"
    - Timeline reconstruction of program activity

    Returns a dict with:
    - "plugin": "shimcachemem"
    - "results": list of dicts, each containing:
        "Order": ordinal position in the cache, newest first (int),
        "Last Modified": file last-modified timestamp as recorded by the
          cache (str, UTC),
        "Last Update": cache-entry last-update timestamp (str, UTC; may
          be None depending on Windows build — only 32-bit Win8/8.1 record
          this column),
        "Exec Flag": whether Windows flagged the file as executed (bool;
          only meaningful on 32-bit Windows 7/8/8.1 — elsewhere the cache
          treats every entry as having been executed),
        "File Size": size of the file as recorded (str, hex),
        "File Path": full NT path of the executable (str)

    Forensic context:
    - Shimcache is recovered from kernel memory rather than from the
      hive on disk, so entries remain available even if the SYSTEM hive
      has not been flushed. It is a major evidence-of-execution source
      alongside windows_registry_amcache and windows_registry_userassist
    - Order=0 is the newest cache entry; walking from 0 downward reveals
      the most recently recorded programs
    - File Path entries that point to temp / user-writable directories
      (AppData, ProgramData, Public, Windows\\Temp) with unusual names are
      high-signal leads — correlate with windows_pslist (are they still
      running?) and windows_registry_amcache (SHA1 and install time)
    - Combine with windows_registry_userassist (interactive execution)
      and windows_registry_scheduled_tasks (scheduled execution) to
      distinguish the invocation vector
    - Shimcache captures execution even if the binary was later deleted,
      making it invaluable for post-incident triage
    """
    return session.run_plugin("shimcachemem")


@mcp.tool()
def windows_vadregexscan(pattern: str, maxsize: int = 128) -> dict:
    """
    Run the vadregexscan plugin to search every process's virtual memory
    (all VADs) for a user-supplied regular expression. This is the first
    parameterized MCP tool in the server — Claude must supply a `pattern`.

    Use this tool when the user asks about:
    - Searching process memory for a specific string, URL, IP, or regex
    - Finding indicators of compromise (IOCs) hidden in user-mode memory
    - Locating configuration strings, keys, or tokens embedded in a process
    - Regex-based hunt across all running processes in one pass
    - Questions like "is the string foo anywhere in memory?" or
      "find any process memory containing /cmd.exe/"

    Arguments:
    - pattern (required): a regular expression (Python `re` syntax). The
      plugin interprets it as UTF-8 bytes internally, so typical ASCII /
      wide-char byte-level regexes work (e.g., `r"https?://[\\w.-]+"`,
      `r"\\\\Device\\\\"`, `r"BEGIN [A-Z ]+ KEY"`).
    - maxsize (optional, default 128): maximum number of bytes of
      surrounding context captured per match.

    Returns a dict with:
    - "plugin": "vadregexscan"
    - "results": list of dicts, each containing:
        "PID": process ID where the match was found (int),
        "Process": image name of that process (str),
        "Offset": virtual address of the match (str, hex),
        "Text": UTF-8 decoded match / context (str),
        "Hex": raw bytes of the match (str repr of the bytes object)

    Forensic context:
    - A high-value general-purpose hunt tool. Unlike windows_strings (which
      needs a pre-generated strings file), this scans live process memory
      directly with a regex
    - Good first probe for IOC hunts: paste in a URL, IP, domain, process
      name, or magic byte sequence and get back every process containing
      it, in one call
    - Large or loose patterns on a busy image can scan tens of GB of VAD
      space; prefer anchored or specific patterns. If the match count is
      huge, tighten the regex first
    - Use the PID column to pivot to windows_pslist for process context,
      windows_cmdline for arguments, and windows_malware_malfind to see
      whether the hit falls inside a suspicious VAD
    - Example hunt queries: `r"\\\\\\\\"` (UNC paths), `r"curl\\.exe"`
      (living-off-the-land), `r"-----BEGIN"` (crypto material leakage),
      `r"powershell\\s*-e"` (encoded PowerShell).
    """
    return session.run_plugin("vadregexscan", pattern=pattern, maxsize=maxsize)


@mcp.tool()
def windows_dlllist() -> dict:
    """
    Run the dlllist plugin to list DLLs and loaded modules for each process
    from the PEB (Process Environment Block) loader data.

    Use this tool when the user asks about:
    - DLLs or shared libraries loaded by a process
    - What modules a process has loaded into memory
    - Suspicious or unexpected DLLs in a process
    - DLL load order, base addresses, or file paths
    - DLL hijacking or side-loading indicators

    Returns a dict with:
    - "plugin": "dlllist"
    - "results": list of dicts, each containing:
        "PID": process ID (int),
        "Process": process name (str),
        "Base": base address of the loaded module (str, hex),
        "Size": size of the module in memory (str, hex),
        "Name": module file name (str),
        "Path": full path of the loaded module (str),
        "LoadCount": reference count for the module (int),
        "LoadTime": time the module was loaded (str),
        "File output": file dump status (str)

    Forensic context:
    - DLLs loaded from unusual paths (e.g., temp directories, user profile)
      are suspicious and may indicate DLL hijacking or malware staging
    - Compare with windows_malware_ldrmodules to detect discrepancies; modules
      missing from one loader list but present in another suggest unlinking
    - Use windows_malware_malfind to check if any loaded module regions have been
      modified in memory (code patching / hooking)
    - Cross-reference with windows_cmdline to verify that loaded DLLs match
      the expected behavior of each process
    """
    return session.run_plugin("dlllist")


@mcp.tool()
def windows_malware_ldrmodules() -> dict:
    """
    Run the ldrmodules plugin to cross-reference modules across the three
    PEB loader lists (InLoad, InInit, InMem) to detect unlinked DLLs.

    Use this tool when the user asks about:
    - Hidden or unlinked DLLs in a process
    - DLL loader list discrepancies or inconsistencies
    - Stealthy DLL injection that removes entries from loader lists
    - Whether all loaded modules appear in all three PEB lists
    - Rootkit or malware hiding techniques at the module level

    Returns a dict with:
    - "plugin": "ldrmodules"
    - "results": list of dicts, each containing:
        "Pid": process ID (int),
        "Process": process name (str),
        "Base": base address of the module (str, hex),
        "InLoad": present in InLoadOrderModuleList (bool),
        "InInit": present in InInitializationOrderModuleList (bool),
        "InMem": present in InMemoryOrderModuleList (bool),
        "MappedPath": file path from the VAD (str)

    Forensic context:
    - A module with False in any of InLoad/InInit/InMem has been unlinked
      from that loader list, which is a classic DLL hiding technique
    - Legitimate modules should appear in all three lists; any discrepancy
      warrants investigation
    - Compare with windows_dlllist which only reads InLoadOrderModuleList;
      this tool provides a more complete view
    - Use windows_malware_malfind to check if the unlinked module's memory region
      contains injected or modified code
    """
    return session.run_plugin("malware.ldrmodules")


@mcp.tool()
def windows_modules() -> dict:
    """
    Run the modules plugin to list kernel modules loaded via the
    PsLoadedModuleList, showing drivers and kernel extensions.

    Use this tool when the user asks about:
    - Loaded kernel drivers or kernel modules
    - Which drivers are loaded on the system
    - Driver base addresses, sizes, or file paths
    - Kernel-level rootkit detection via suspicious drivers
    - System driver inventory

    Returns a dict with:
    - "plugin": "modules"
    - "results": list of dicts, each containing:
        "Offset": module list entry offset (str, hex),
        "Base": base address of the kernel module (str, hex),
        "Size": size of the module in memory (str, hex),
        "Name": module file name (str),
        "Path": full path of the kernel module (str),
        "File output": file dump status (str)

    Forensic context:
    - Kernel modules loaded from non-standard paths (outside
      \\SystemRoot\\system32\\drivers\\) may indicate rootkit drivers
    - Compare with windows_modscan to detect hidden kernel modules that
      have been unlinked from the loaded module list
    - Use windows_driverscan to correlate driver objects with loaded modules
    - Cross-reference module base addresses with windows_ssdt to identify
      which module handles each system call
    """
    return session.run_plugin("modules")


@mcp.tool()
def windows_modscan() -> dict:
    """
    Run the modscan plugin to scan for kernel modules by pool tag in physical
    memory, independent of the OS-maintained module list.

    Use this tool when the user asks about:
    - Hidden or unlinked kernel modules or drivers
    - Kernel rootkit detection via module hiding
    - Drivers that may have been removed from the loaded module list
    - A more thorough kernel module scan than the standard list
    - Previously loaded and unloaded kernel modules

    Returns a dict with:
    - "plugin": "modscan"
    - "results": list of dicts, each containing:
        "Offset": physical offset of the module entry (str, hex),
        "Base": base address of the kernel module (str, hex),
        "Size": size of the module in memory (str, hex),
        "Name": module file name (str),
        "Path": full path of the kernel module (str),
        "File output": file dump status (str)

    Forensic context:
    - Compare with windows_modules: a module found here but missing from
      windows_modules was unlinked from the loaded module list, indicating
      a kernel rootkit hiding its driver
    - Unloaded drivers still leave pool tag artifacts, so this tool can
      find drivers that were loaded temporarily and then removed
    - Use windows_driverscan to correlate driver objects with discovered
      modules for a complete driver analysis
    - Cross-reference suspicious module base addresses with windows_ssdt
      to detect system call hooking
    """
    return session.run_plugin("modscan")


@mcp.tool()
def windows_verinfo() -> dict:
    """
    Run the verinfo plugin to extract PE version information from loaded
    modules, including version numbers for processes and kernel drivers.

    Use this tool when the user asks about:
    - Version information of loaded DLLs or executables
    - PE file version, product version, or build numbers
    - Whether a specific module is an expected version
    - Identifying outdated or patched binaries in memory
    - Verifying module authenticity via version metadata

    Returns a dict with:
    - "plugin": "verinfo"
    - "results": list of dicts, each containing:
        "PID": process ID (int),
        "Process": process name (str),
        "Base": base address of the module (str, hex),
        "Name": module file name (str),
        "Major": major version number (int),
        "Minor": minor version number (int),
        "Product": product version number (int),
        "Build": build number (int)

    Forensic context:
    - Mismatched version numbers for system DLLs (e.g., ntdll.dll with an
      unexpected version) may indicate binary patching or trojanized files
    - Compare version info against known-good baselines for the OS version
      identified by windows_info
    - Use windows_dlllist to get the full path of modules, then this tool
      to verify their version metadata
    - Modules with zeroed or absent version info may be custom-compiled
      malware or debug builds
    """
    return session.run_plugin("verinfo")


@mcp.tool()
def windows_iat() -> dict:
    """
    Run the iat plugin to extract the Import Address Table (IAT) from loaded
    modules, listing API functions imported from external libraries.

    Use this tool when the user asks about:
    - API functions imported by a process or module
    - Import Address Table entries or imported DLL functions
    - What Windows API calls a process is set up to use
    - IAT hooking detection (function addresses pointing outside the library)
    - Behavioral analysis based on imported functions

    Returns a dict with:
    - "plugin": "iat"
    - "results": list of dicts, each containing:
        "PID": process ID (int),
        "Name": module name that imports the function (str),
        "Library": library providing the imported function (str),
        "Bound": whether the import is bound (bool),
        "Function": imported function name (str),
        "Address": resolved function address (str, hex)

    Forensic context:
    - Suspicious imports like VirtualAllocEx, WriteProcessMemory,
      CreateRemoteThread indicate process injection capability
    - IAT hooking: if the Address field points outside the expected Library
      module range, the import has been redirected (API hooking)
    - Use windows_dlllist to verify the base address range of each Library,
      then compare with the resolved Address to detect hooks
    - Cross-reference imported functions with windows_malware_malfind results to
      understand what capabilities injected code may leverage
    """
    return session.run_plugin("iat")


@mcp.tool()
def windows_pe_symbols(
    source: str,
    module: str,
    symbols: str = "",
    addresses: str = "",
) -> dict:
    """
    Run the pe_symbols plugin to resolve PE symbol names to addresses (or
    addresses back to names) for a given loaded module, using PDB data
    downloaded for that image.

    Use this tool when the user asks about:
    - What function lives at a given address inside ntoskrnl / ntdll / ...
    - The address of a specific Windows API inside a loaded library
    - Resolving a suspicious thread start address to a function name
    - Dumping all exported / internal symbols of a particular module
    - Verifying whether an address falls inside a legitimate function

    Arguments:
    - source (required): "kernel" to resolve inside the Windows kernel
      module, or "processes" to resolve inside a loaded user-mode module.
    - module (required): module filename. Examples: "ntoskrnl.exe" for
      the kernel, "ntdll.dll" / "kernel32.dll" for common userland
      libraries.
    - symbols (optional): comma-separated symbol names to resolve into
      addresses (e.g., "NtCreateFile,NtOpenProcess"). When provided,
      results only contain matches for these symbols.
    - addresses (optional): comma-separated hex or decimal addresses to
      resolve into symbol names (e.g., "0x14012a0a0,0x14012b100").
    - When both ``symbols`` and ``addresses`` are empty, every symbol in
      the module is returned (can be very large — use cautiously).

    Returns a dict with:
    - "plugin": "pe_symbols"
    - "results": list of dicts, each containing:
        "Module": module name the symbol belongs to (str),
        "Symbol": symbol name (str),
        "Address": resolved virtual address (str, hex)

    Forensic context:
    - Requires PDB download to succeed on the server (volatility3's symbol
      auto-download mechanism); failures usually mean no internet access
      at startup time
    - Key pivot for suspicious thread analysis: take Win32StartAddress
      from windows_threads / windows_orphan_kernel_threads and call
      this tool with that value to obtain the function name
    - Useful for IAT-hooking detection alongside windows_iat: resolve
      the expected function address here, compare against the imported
      entry's current address
    - Kernel-mode hunts (source="kernel", module="ntoskrnl.exe") are
      the go-to for understanding callbacks, SSDT entries, or rootkit
      hook targets reported by windows_ssdt / windows_callbacks
    """
    return session.run_plugin(
        "pe_symbols",
        source=source,
        module=module,
        symbols=symbols,
        addresses=addresses,
    )


@mcp.tool()
def windows_pedump(base: int, pid: int = 0, kernel_module: bool = False) -> dict:
    """
    Run the pedump plugin to reconstruct a PE image from memory at a
    specified base address and write the resulting .exe / .dll / .sys
    bytes into the directory configured via ``VOL_DUMP_DIR``.

    Use this tool when the user asks about:
    - Extracting a specific executable or DLL from a live process
    - Dumping a suspicious module / driver as a .exe / .dll / .sys file
    - Reconstructing an injected PE for static analysis in IDA, Ghidra,
      or other PE tooling
    - Recovering a hollowed / masqueraded image that no longer exists on
      disk
    - Pulling a kernel driver by base address (pass kernel_module=True)

    Arguments:
    - base (required): virtual base address of the target PE (int). For
      userland modules, the base appears in windows_dlllist as
      "Base"; for kernel drivers, it appears in windows_modules.
    - pid (optional, default 0): if non-zero, restrict search to this
      process. Ignored when kernel_module=True.
    - kernel_module (optional, default False): set True to dump a kernel
      mode PE (driver) instead of a userland image.

    Returns a dict with:
    - "plugin": "pedump"
    - "results": list of dicts, each containing:
        "PID": owning process ID (or 4 / System for kernel modules) (int),
        "Process": image name of the owning process (str),
        "File output": final on-disk path of the reconstructed PE or an
          error string if reconstruction failed

    Forensic context:
    - Requires VOL_DUMP_DIR to be configured; otherwise raises a clear
      error so Claude can prompt the user to set it
    - Typical workflow:
        1. windows_malware_malfind surfaces a suspicious VAD at base B
           inside PID P
        2. windows_pedump(base=B, pid=P) recovers the hollowed / injected
           PE to disk
        3. User runs IDA / Ghidra / YARA on the dumped bytes
    - For hidden rootkit drivers: compare windows_modscan (pool scan)
      against windows_modules (linked list) to find unlinked driver
      bases, then pedump each unlinked base with kernel_module=True
    - Dumped PEs are reconstructed from live memory pages, so section
      alignment and unmapped pages may leave zero-filled regions — this
      is expected and still useful for static analysis
    """
    return session.run_plugin(
        "pedump",
        base=base,
        pid=pid,
        kernel_module=kernel_module,
    )


@mcp.tool()
def windows_callbacks() -> dict:
    """
    Run the callbacks plugin to list kernel callbacks and notification
    routines registered in the Windows kernel.

    Use this tool when the user asks about:
    - Kernel callbacks or notification routines
    - Process/thread/image load notification hooks
    - Registry change callbacks or filesystem filter callbacks
    - Rootkit detection via callback table manipulation
    - What code runs in response to kernel events

    Returns a dict with:
    - "plugin": "callbacks"
    - "results": list of dicts, each containing:
        "Type": callback type such as CreateProcess, CreateThread, LoadImage (str),
        "Callback": address of the callback function (str, hex),
        "Module": module that owns the callback (str),
        "Symbol": resolved symbol name if available (str),
        "Detail": additional details about the callback (str)

    Forensic context:
    - Callbacks pointing to unknown or suspicious modules indicate rootkit
      hooks that intercept kernel events (process creation, image loading)
    - Compare the Module field against windows_modules to verify the callback
      belongs to a legitimate loaded driver
    - CreateProcess and LoadImage callbacks are commonly abused by rootkits
      to inject code into new processes or intercept DLL loading
    - Use windows_driverscan to identify the driver object associated with
      the module hosting the callback
    """
    return session.run_plugin("callbacks")


@mcp.tool()
def windows_devicetree() -> dict:
    """
    Run the devicetree plugin to list the device tree showing relationships
    between drivers and their attached device objects.

    Use this tool when the user asks about:
    - Device objects and their associated drivers
    - Driver-device attachment chains or device stacks
    - Which drivers handle specific device types
    - Filter drivers or device layering in the I/O stack
    - Rootkit detection via rogue device attachments

    Returns a dict with:
    - "plugin": "devicetree"
    - "results": list of dicts, each containing:
        "Offset": device or driver object offset (str, hex),
        "Type": object type, either Driver or Device (str),
        "DriverName": name of the owning driver (str),
        "DeviceName": name of the device object (str),
        "DriverNameOfAttDevice": driver of the attached device (str),
        "DeviceType": device type classification (str)

    Forensic context:
    - Unexpected devices attached to legitimate driver stacks may indicate
      filter driver rootkits intercepting I/O operations
    - Compare driver names against windows_modules and windows_driverscan
      to verify all device-owning drivers are legitimate
    - Filesystem filter drivers (attached to \\FileSystem\\) are commonly
      used by rootkits to hide files from directory listings
    - Use windows_driverirp to examine the IRP handlers of suspicious
      drivers found in the device tree
    """
    return session.run_plugin("devicetree")


@mcp.tool()
def windows_driverirp() -> dict:
    """
    Run the driverirp plugin to list IRP (I/O Request Packet) major function
    handlers for each driver, showing which code handles each I/O operation.

    Use this tool when the user asks about:
    - IRP handlers or I/O dispatch routines for drivers
    - Which function handles read, write, or device control for a driver
    - IRP hooking or driver dispatch table manipulation
    - Rootkit detection via tampered IRP handlers
    - Driver behavior analysis through its dispatch table

    Returns a dict with:
    - "plugin": "driverirp"
    - "results": list of dicts, each containing:
        "Offset": driver object offset (str, hex),
        "Driver Name": name of the driver (str),
        "IRP": IRP major function name such as IRP_MJ_CREATE (str),
        "Address": address of the handler function (str, hex),
        "Module": module containing the handler (str),
        "Symbol": resolved symbol name if available (str)

    Forensic context:
    - IRP handlers pointing outside the owning driver's module range indicate
      IRP hooking, a common rootkit technique to intercept I/O operations
    - Compare the Module field with the Driver Name: mismatches suggest a
      different module has hooked the driver's dispatch table
    - Use windows_modules to verify the expected address range for each
      driver module and detect out-of-range handler addresses
    - Cross-reference with windows_devicetree to understand the full I/O
      stack and identify which drivers are layered together
    """
    return session.run_plugin("driverirp")


@mcp.tool()
def windows_malware_drivermodule() -> dict:
    """
    Run the drivermodule plugin to detect drivers that are not backed by
    a loaded kernel module, indicating potentially hidden rootkit drivers.

    Use this tool when the user asks about:
    - Hidden or orphaned driver modules
    - Drivers without a corresponding loaded kernel module
    - Rootkit driver detection or driver integrity checks
    - Whether all active drivers map to legitimate modules
    - Drivers that may have been loaded and then hidden

    Returns a dict with:
    - "plugin": "drivermodule"
    - "results": list of dicts, each containing:
        "Offset": driver object offset (str, hex),
        "Known Exception": whether this is a known benign exception (bool),
        "Driver Name": name of the driver (str),
        "Service Key": registry service key for the driver (str),
        "Alternative Name": alternative module name if found (str)

    Forensic context:
    - Drivers with no matching module in windows_modules and Known Exception
      set to False are strong rootkit indicators
    - Known Exception=True entries are legitimate drivers that are expected
      to appear without a backing module (e.g., certain Microsoft drivers)
    - Use windows_driverscan to get the full driver object details for any
      suspicious entries discovered here
    - Cross-reference with windows_callbacks and windows_ssdt to determine
      if the hidden driver has hooked any kernel functions
    """
    return session.run_plugin("malware.drivermodule")


@mcp.tool()
def windows_driverscan() -> dict:
    """
    Run the driverscan plugin to scan for driver objects in physical memory
    using pool tag scanning.

    Use this tool when the user asks about:
    - Driver objects loaded on the system
    - Scanning for all drivers including potentially hidden ones
    - Driver start addresses, sizes, or service key names
    - Comprehensive driver inventory from physical memory
    - Comparing against the loaded module list for discrepancies

    Returns a dict with:
    - "plugin": "driverscan"
    - "results": list of dicts, each containing:
        "Offset": physical offset of the driver object (str, hex),
        "Start": driver entry point address (str, hex),
        "Size": driver size in memory (str, hex),
        "Service Key": registry service key name (str),
        "Driver Name": driver object name (str),
        "Name": short name of the driver (str)

    Forensic context:
    - Drivers found here but missing from windows_modules may have been
      unlinked from the loaded module list (rootkit hiding technique)
    - Compare with windows_malware_drivermodule to identify drivers without a
      backing kernel module
    - Use windows_driverirp to examine the IRP dispatch table of any
      suspicious drivers discovered through this scan
    - Cross-reference Start addresses with windows_ssdt to determine if
      a driver provides any system call handlers
    """
    return session.run_plugin("driverscan")


@mcp.tool()
def windows_poolscanner() -> dict:
    """
    Run the poolscanner plugin as a generic pool tag scanner that finds
    various kernel objects by their pool allocations.

    Use this tool when the user asks about:
    - Generic pool tag scanning across all object types
    - Kernel object discovery by pool tags
    - A comprehensive scan for all pool-allocated kernel objects
    - Low-level memory pool analysis
    - Identifying what kernel objects are allocated in pool memory

    Returns a dict with:
    - "plugin": "poolscanner"
    - "results": list of dicts, each containing:
        "Tag": four-character pool tag (str),
        "Offset": offset of the pool allocation (str, hex),
        "Layer": memory layer where the object was found (str),
        "Name": identified object type or name (str)

    Forensic context:
    - This is a low-level scanner; prefer specialized tools like
      windows_psscan, windows_driverscan, or windows_modscan for
      specific object types as they provide richer output
    - Useful for discovering object types not covered by other scanners
      or for validating results from specialized pool scanners
    - Unknown or suspicious pool tags may indicate custom kernel objects
      allocated by rootkits
    - Use windows_bigpools to focus specifically on large pool allocations
    """
    return session.run_plugin("poolscanner")


@mcp.tool()
def windows_ssdt() -> dict:
    """
    Run the ssdt plugin to list the System Service Descriptor Table (SSDT),
    mapping system call indices to their handler addresses and modules.

    Use this tool when the user asks about:
    - System call table or SSDT entries
    - System call hooking or SSDT patching detection
    - Which module handles each system call (syscall)
    - Kernel-level API hooking indicators
    - System call dispatch table integrity

    Returns a dict with:
    - "plugin": "ssdt"
    - "results": list of dicts, each containing:
        "Index": system call index number (int),
        "Address": address of the system call handler (str, hex),
        "Module": module containing the handler (str),
        "Symbol": resolved symbol name such as NtCreateFile (str)

    Forensic context:
    - All SSDT entries should point to ntoskrnl.exe or win32k.sys; entries
      pointing to other modules indicate SSDT hooking by a rootkit
    - Compare Module values against windows_modules to verify the handler
      belongs to a legitimate kernel module
    - SSDT hooking was common in older rootkits (pre-PatchGuard); on 64-bit
      Windows with PatchGuard, SSDT hooks are rarer but still possible via
      PatchGuard bypass techniques
    - Use windows_callbacks for detecting notification-based hooks, which
      are more common on modern Windows than SSDT hooking
    """
    return session.run_plugin("ssdt")


@mcp.tool()
def windows_netscan() -> dict:
    """
    Run the netscan plugin to find network connections and listening sockets
    by scanning physical memory for network-related pool tags.

    Use this tool when the user asks about:
    - Network connections or open sockets on the system
    - What IP addresses or ports a process was communicating with
    - Listening services or active TCP/UDP connections
    - Command and control (C2) communication indicators
    - Network activity at the time of memory capture

    Returns a dict with:
    - "plugin": "netscan"
    - "results": list of dicts, each containing:
        "Offset": physical offset of the network object (str, hex),
        "Proto": protocol such as TCPv4, TCPv6, UDPv4, UDPv6 (str),
        "LocalAddr": local IP address (str),
        "LocalPort": local port number (int),
        "ForeignAddr": remote IP address (str),
        "ForeignPort": remote port number (int),
        "State": connection state such as ESTABLISHED, LISTENING, CLOSED (str),
        "PID": owning process ID (int),
        "Owner": owning process name (str),
        "Created": timestamp when the connection was created (str)

    Forensic context:
    - ESTABLISHED connections to external IPs from unexpected processes are
      strong C2 indicators; check the ForeignAddr against threat intelligence
    - LISTENING sockets on unusual ports may indicate backdoors or reverse
      shells waiting for attacker connections
    - Use windows_pslist to get full details on the owning PID, and
      windows_cmdline to see how the networking process was launched
    - Cross-reference with windows_strings to find URLs or domains that
      correlate with the observed network endpoints
    """
    return session.run_plugin("netscan")


@mcp.tool()
def windows_netstat() -> dict:
    """
    Run the netstat plugin to list network connections by traversing kernel
    networking data structures (partition table walk).

    Use this tool when the user asks about:
    - Active network connections via OS kernel structures
    - A kernel-level view of network activity (complementary to netscan)
    - TCP/UDP connection state from the OS perspective
    - Verifying netscan results against kernel-maintained data
    - Network connections that may not appear in pool tag scans

    Returns a dict with:
    - "plugin": "netstat"
    - "results": list of dicts, each containing:
        "Offset": offset of the network object (str, hex),
        "Proto": protocol such as TCPv4, TCPv6, UDPv4, UDPv6 (str),
        "LocalAddr": local IP address (str),
        "LocalPort": local port number (int),
        "ForeignAddr": remote IP address (str),
        "ForeignPort": remote port number (int),
        "State": connection state such as ESTABLISHED, LISTENING, CLOSED (str),
        "PID": owning process ID (int),
        "Owner": owning process name (str),
        "Created": timestamp when the connection was created (str)

    Forensic context:
    - This plugin walks kernel structures rather than pool tags, so it may
      find connections that windows_netscan misses and vice versa
    - Compare results with windows_netscan: discrepancies may indicate
      network-level rootkit manipulation of kernel structures
    - Use windows_pslist to resolve PID to full process details for any
      suspicious connections
    - Cross-reference foreign addresses with windows_cmdline to identify
      which command initiated the network activity
    """
    return session.run_plugin("netstat")


@mcp.tool()
def windows_filescan() -> dict:
    """
    Run the filescan plugin to scan for FILE_OBJECT structures in physical
    memory using pool tag scanning.

    Use this tool when the user asks about:
    - Files that were open or referenced on the system
    - Scanning for file objects in memory
    - What files were accessed, including deleted or closed files
    - File paths or file names present in the memory image
    - Evidence of specific files (malware, documents, logs)

    Returns a dict with:
    - "plugin": "filescan"
    - "results": list of dicts, each containing:
        "Offset": physical offset of the FILE_OBJECT (str, hex),
        "Name": full file path (str)

    Forensic context:
    - File objects persist in pool memory even after files are closed,
      providing evidence of files that were accessed before capture
    - Search results for known malware filenames, suspicious paths
      (e.g., temp directories, recycle bin), or sensitive documents
    - Use windows_handles (Type=File) to determine which processes
      currently hold open handles to specific files
    - Cross-reference file paths with windows_dlllist to identify
      DLLs loaded from unusual locations
    """
    return session.run_plugin("filescan")


@mcp.tool()
def windows_dumpfiles(
    pid: int = 0,
    filter: str = "",
    filter_ignore_case: bool = False,
    virtaddr: int = 0,
    physaddr: int = 0,
) -> dict:
    """
    Run the dumpfiles plugin to recover cached file contents from memory
    and write the recovered bytes to the directory configured via the
    ``VOL_DUMP_DIR`` environment variable.

    Use this tool when the user asks about:
    - Extracting or recovering a specific file from the memory image
    - Dumping files opened by a specific process (pass the PID)
    - Recovering deleted or in-use files whose content is still cached
    - Pulling a configuration / document / PE from a suspicious process
    - Saving forensic evidence to disk for external analysis

    Arguments (all optional — pass ``0`` / ``""`` to leave unset; the
    defaults dump every file object volatility3 finds, which can be slow
    and produce many files):
    - pid: restrict to files opened by this process ID (int)
    - filter: regex applied to the recovered file's name (str)
    - filter_ignore_case: make ``filter`` case-insensitive (bool)
    - virtaddr: virtual address of a specific _FILE_OBJECT (int)
    - physaddr: physical address of a specific _FILE_OBJECT (int)

    Returns a dict with:
    - "plugin": "dumpfiles"
    - "results": list of dicts, each containing:
        "Cache": cache type such as SharedCacheMap or DataSectionObject (str),
        "FileObject": address of the _FILE_OBJECT (str, hex),
        "FileName": path of the cached file (str),
        "Result": final on-disk path of the dumped bytes or an error string

    Forensic context:
    - The server must be launched with ``VOL_DUMP_DIR`` set (see
      ``claude_desktop_config.json``); otherwise this tool raises a clear
      error. Dumped bytes land in that directory; filename collisions are
      resolved by appending ``-1``, ``-2``, ...
    - Prefer passing a ``pid`` or ``filter`` — a bare call can extract
      hundreds or thousands of cached files
    - Use windows_filescan first to pick targets by FILE_OBJECT address,
      then pass that value as ``virtaddr`` / ``physaddr`` for a precise dump
    - SharedCacheMap entries represent files actively cached by the OS;
      DataSectionObject entries are memory-mapped file sections (EXE/DLL)
    - Cross-reference with windows_handles to identify which process had
      the file open at the time of capture
    """
    return session.run_plugin(
        "dumpfiles",
        pid=pid,
        filter=filter,
        filter_ignore_case=filter_ignore_case,
        virtaddr=virtaddr,
        physaddr=physaddr,
    )


@mcp.tool()
def windows_mutantscan() -> dict:
    """
    Run the mutantscan plugin to scan for mutex (mutant) objects in physical
    memory using pool tag scanning.

    Use this tool when the user asks about:
    - Mutexes or named mutants on the system
    - Malware mutex indicators or unique mutex names
    - Synchronization objects used by processes
    - Whether a known malware mutex exists in memory
    - Named kernel objects used for inter-process signaling

    Returns a dict with:
    - "plugin": "mutantscan"
    - "results": list of dicts, each containing:
        "Offset": physical offset of the mutant object (str, hex),
        "Name": name of the mutex (str)

    Forensic context:
    - Many malware families create uniquely named mutexes to prevent
      multiple instances; searching for known mutex names is a fast
      IOC check (e.g., "Global\\MicrosoftUpdateService" used by some RATs)
    - Use windows_handles (Type=Mutant) to determine which process owns
      each mutex, linking the mutex back to a specific process
    - Unnamed mutexes (empty Name field) are common and usually benign;
      focus investigation on named mutexes with suspicious patterns
    - Cross-reference mutex names with threat intelligence databases
      for known malware family indicators
    """
    return session.run_plugin("mutantscan")


@mcp.tool()
def windows_symlinkscan() -> dict:
    """
    Run the symlinkscan plugin to scan for symbolic link objects in physical
    memory using pool tag scanning.

    Use this tool when the user asks about:
    - Symbolic links or object manager symlinks in the kernel
    - Device name mappings or drive letter assignments
    - How logical names (e.g., C:) map to physical device paths
    - Object namespace redirection or aliasing
    - Potential symlink-based attacks or manipulations

    Returns a dict with:
    - "plugin": "symlinkscan"
    - "results": list of dicts, each containing:
        "Offset": physical offset of the symlink object (str, hex),
        "CreateTime": timestamp when the symlink was created (str),
        "From Name": source name of the symbolic link (str),
        "To Name": target path the symlink points to (str)

    Forensic context:
    - Drive letter mappings (e.g., \\GLOBAL??\\C: -> \\Device\\Harddisk0\\Partition1)
      reveal the disk and partition layout at the time of capture
    - Unusual symlinks redirecting system paths may indicate rootkit
      namespace manipulation to hide files or devices
    - Compare with windows_devicetree to correlate device names referenced
      in symlink targets with actual device objects
    - Use windows_filescan to cross-reference file paths that traverse
      symlinked directories
    """
    return session.run_plugin("symlinkscan")


@mcp.tool()
def windows_registry_hivelist() -> dict:
    """
    Run the registry.hivelist plugin to list all registry hives loaded
    in memory, showing their virtual offsets and file paths.

    Use this tool when the user asks about:
    - Which registry hives are loaded in memory
    - Registry hive file paths or locations
    - SAM, SYSTEM, SOFTWARE, NTUSER.DAT, or other hive files
    - An overview of the registry structure in the memory image
    - Starting point for registry analysis

    Returns a dict with:
    - "plugin": "registry.hivelist"
    - "results": list of dicts, each containing:
        "Offset": virtual offset of the hive in memory (str, hex),
        "FileFullPath": full file path of the registry hive (str),
        "File output": file dump status (str)

    Forensic context:
    - Use the Offset values from this tool as input to
      windows_registry_printkey for targeted registry key enumeration
    - Key hives: SAM (user accounts), SECURITY (policies), SYSTEM
      (services, drivers), SOFTWARE (installed programs), NTUSER.DAT
      (per-user settings)
    - Hives without a file path (e.g., volatile hives) exist only in
      memory and may contain runtime configuration
    - Use windows_registry_hivescan to find additional hives that may
      have been unlinked from the hive list
    """
    return session.run_plugin("registry.hivelist")


@mcp.tool()
def windows_registry_hivescan() -> dict:
    """
    Run the registry.hivescan plugin to scan for registry hive structures
    in physical memory using pool tag scanning.

    Use this tool when the user asks about:
    - Scanning for all registry hives including unlinked ones
    - Finding registry hives that may have been hidden or detached
    - A more thorough hive discovery than the standard hive list
    - Physical offsets of registry hive structures in memory
    - Verifying hivelist results against pool scan findings

    Returns a dict with:
    - "plugin": "registry.hivescan"
    - "results": list of dicts, each containing:
        "Offset": physical offset of the hive structure (str, hex)

    Forensic context:
    - Compare with windows_registry_hivelist: hives found here but missing
      from the list may have been unlinked by a rootkit
    - The Offset values can be used with windows_registry_printkey to
      examine keys within specific hives
    - Pool scanning finds hive remnants even after they are unloaded,
      potentially revealing previously loaded hives
    - Use windows_registry_hivelist first for named hives; use this tool
      when you need to verify completeness or find hidden hives
    """
    return session.run_plugin("registry.hivescan")


@mcp.tool()
def windows_registry_printkey() -> dict:
    """
    Run the registry.printkey plugin to print registry keys, subkeys,
    and values from loaded registry hives.

    Use this tool when the user asks about:
    - Registry key values or data for a specific path
    - Contents of Run/RunOnce keys (persistence mechanisms)
    - Installed software, services, or startup entries in the registry
    - Specific registry paths like HKLM\\SYSTEM\\CurrentControlSet\\Services
    - Registry-based forensic artifacts (MRU lists, typed URLs, etc.)

    Returns a dict with:
    - "plugin": "registry.printkey"
    - "results": list of dicts, each containing:
        "Last Write Time": last modification timestamp of the key (str),
        "Hive Offset": offset of the containing hive (str, hex),
        "Type": entry type, either Key or Value (str),
        "Key": registry key path (str),
        "Name": value name or subkey name (str),
        "Data": value data content (str),
        "Volatile": whether the key is volatile/memory-only (bool)

    Forensic context:
    - Persistence keys: HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run,
      HKLM\\SYSTEM\\CurrentControlSet\\Services — check for malware entries
    - Last Write Time indicates when the key was last modified, useful
      for timeline analysis and correlating with process activity
    - Volatile keys (Volatile=true) exist only in memory and are lost on
      reboot; malware may use these to avoid on-disk evidence
    - Use windows_registry_hivelist first to identify hive offsets, then
      this tool to explore specific keys within those hives
    """
    return session.run_plugin("registry.printkey")


@mcp.tool()
def windows_registry_userassist() -> dict:
    """
    Run the registry.userassist plugin to decode UserAssist registry entries,
    which track program execution history for each user.

    Use this tool when the user asks about:
    - Programs executed by users or application launch history
    - UserAssist records or program usage statistics
    - How many times a program was run and when it was last used
    - User activity or application execution timeline
    - Evidence of specific program execution on the system

    Returns a dict with:
    - "plugin": "registry.userassist"
    - "results": list of dicts, each containing:
        "Hive Offset": offset of the containing hive (str, hex),
        "Hive Name": name of the registry hive (str),
        "Path": registry key path (str),
        "Last Write Time": key last modification time (str),
        "Type": entry type (str),
        "Name": ROT13-decoded program name or path (str),
        "ID": entry identifier (int),
        "Count": number of times the program was executed (int),
        "Focus Count": number of times the window received focus (int),
        "Time Focused": total time the application had focus (str),
        "Last Updated": timestamp of the last execution (str),
        "Raw Data": raw binary data of the entry (str)

    Forensic context:
    - UserAssist entries are ROT13 encoded in the registry; this plugin
      automatically decodes them to reveal actual program paths
    - The Count field shows how many times a user launched each program,
      useful for establishing patterns of behavior
    - Last Updated timestamps help build an execution timeline, correlating
      with process creation times from windows_pslist
    - Use windows_sessions to identify which user account corresponds to
      each NTUSER.DAT hive containing UserAssist data
    """
    return session.run_plugin("registry.userassist")


@mcp.tool()
def windows_registry_certificates() -> dict:
    """
    Run the registry.certificates plugin to list certificates stored in
    the Windows registry certificate store.

    Use this tool when the user asks about:
    - Certificates installed on the system
    - Trusted root certificates or certificate authorities
    - Rogue or malicious certificates added to the store
    - SSL/TLS certificate inventory from the registry
    - Certificate-based trust manipulation indicators

    Returns a dict with:
    - "plugin": "registry.certificates"
    - "results": list of dicts, each containing:
        "Certificate path": registry path of the certificate (str),
        "Certificate section": store section such as Root, CA, My (str),
        "Certificate ID": unique identifier for the certificate (str),
        "Certificate name": common name or subject of the certificate (str)

    Forensic context:
    - Rogue root certificates in the Trusted Root CA store allow attackers
      to perform man-in-the-middle attacks on HTTPS traffic
    - Malware sometimes installs its own CA certificate to intercept
      encrypted communications or sign malicious code
    - Compare certificates against known legitimate Windows root CAs to
      identify unauthorized additions
    - Use windows_registry_printkey to examine the full certificate data
      stored under each certificate's registry path
    """
    return session.run_plugin("registry.certificates")


@mcp.tool()
def windows_registry_scheduled_tasks() -> dict:
    """
    Run the registry.scheduled_tasks plugin to decode Windows Task
    Scheduler entries stored in the registry, including triggers,
    actions, run times, and creation times.

    Use this tool when the user asks about:
    - Scheduled tasks, Task Scheduler jobs, or at/schtasks artifacts
    - Persistence mechanisms via the Task Scheduler
    - Which programs are set to run on a schedule or on event triggers
    - Creation time / last run time of scheduled tasks
    - Malware persistence registered as a scheduled task

    Returns a dict with:
    - "plugin": "registry.scheduled_tasks"
    - "results": list of dicts, each containing:
        "Task Name": task name / path (str),
        "Principal ID": security principal running the task (str),
        "Display Name": display name of the task (str),
        "Enabled": whether the task is enabled (bool),
        "Creation Time": when the task was created (str, UTC),
        "Last Run Time": when the task last ran (str, UTC),
        "Last Successful Run Time": last successful run (str, UTC),
        "Trigger Type": trigger category (Time, Logon, Boot, Event, ...)
          (str),
        "Trigger Description": human-readable trigger detail (str),
        "Action Type": action category (Exec, ComHandler, ...) (str),
        "Action": executable or handler invoked (str),
        "Action Arguments": arguments passed to the action (str),
        "Action Context": security context for the action (str),
        "Working Directory": working directory used when running (str),
        "Key Name": registry key name backing the task (str)

    Forensic context:
    - Scheduled tasks are one of the most common Windows persistence
      techniques (MITRE ATT&CK T1053.005). Pay special attention to
      tasks with Trigger Type = Logon or Boot and actions pointing to
      user-writable paths (AppData, ProgramData, Public)
    - Creation Time vs Last Run Time reveals freshly created persistence
      tasks that have already executed — correlate with windows_pslist
      and process timestamps to link the task to observed activity
    - Action fields containing LOLBins (powershell.exe, rundll32.exe,
      mshta.exe, regsvr32.exe) with obfuscated arguments are high-signal
      persistence indicators
    - Use the Key Name to locate the full registry entry with
      windows_registry_printkey for deeper inspection
    - Cross-reference task creation times against process creation times
      from windows_pslist to identify the process that registered the
      task
    """
    return session.run_plugin("registry.scheduled_tasks")


@mcp.tool()
def windows_registry_getcellroutine() -> dict:
    """
    Run the registry.getcellroutine plugin to detect registry hives whose
    GetCellRoutine function pointer has been hooked to point outside the
    kernel (ntoskrnl) — a registry rootkit indicator.

    Use this tool when the user asks about:
    - Registry rootkits or hooked registry access paths
    - Hidden registry keys that cannot be read via standard hive traversal
    - Kernel-mode tampering of the registry subsystem
    - Signs of registry filter drivers or offensive registry toolkits
    - Integrity check of registry hive access routines

    Returns a dict with:
    - "plugin": "registry.getcellroutine"
    - "results": list of dicts, each containing:
        "Hive Offset": virtual offset of the _CMHIVE structure (str, hex),
        "Hive Name": hive path / name such as \\REGISTRY\\MACHINE\\SYSTEM (str),
        "GetCellRoutine Module": module owning the hooked handler, or None
          if the handler does not resolve to any known module (str or None),
        "GetCellRoutine Handler": virtual address of the handler (str, hex)

    Forensic context:
    - Every registry hive stores a GetCellRoutine callback used to translate
      a cell index into a memory pointer. Legitimately this always resolves
      inside the Windows kernel. Any non-kernel module (or unresolved
      address) is malicious — the plugin's logic only yields hooked hives
    - A non-None GetCellRoutine Module that is not ntoskrnl indicates a
      driver has replaced the handler to intercept or filter registry reads
      (used by rootkits to hide keys/values from hivelist / printkey)
    - An unresolved handler (GetCellRoutine Module = None) means the hook
      points into unbacked memory — likely manually-mapped rootkit code;
      combine with windows_modscan and windows_orphan_kernel_threads to
      locate the owning driver
    - Pair with windows_registry_hivelist to confirm the hive is otherwise
      accessible, and windows_registry_printkey to attempt reading keys via
      the potentially hooked path
    """
    return session.run_plugin("registry.getcellroutine")


@mcp.tool()
def windows_registry_amcache() -> dict:
    """
    Run the registry.amcache plugin to decode AmCache.hve, which records
    metadata about every application, driver, or installer that has
    executed on the system.

    Use this tool when the user asks about:
    - What programs / EXEs were run on this system and when
    - Evidence of execution (MITRE ATT&CK T1005 / investigator questions
      like "did foo.exe ever run here?")
    - Driver or service binary history
    - SHA1 hashes of executed files for IoC matching or sandbox lookup
    - Program install / compile / last-modified timestamps
    - First-time / post-breach triage on an image with no prelogged data

    Returns a dict with:
    - "plugin": "registry.amcache"
    - "results": list of dicts, each containing:
        "EntryType": AmCache entry category such as Programs,
          InventoryApplicationFile, InventoryDriverBinary, etc. (str),
        "Path": full file path of the executable (str),
        "Company": company / vendor reported in PE resources (str),
        "LastModifyTime": registry key last-write time (str, UTC),
        "LastModifyTime2": secondary modification timestamp (str, UTC),
        "InstallTime": recorded install timestamp (str, UTC),
        "CompileTime": PE compilation timestamp (str, UTC),
        "SHA1": SHA1 hash of the file recorded by AmCache (str),
        "Service": name of the service backed by this binary, if any (str),
        "ProductName": product name from PE version info (str),
        "ProductVersion": product version from PE version info (str)

    Forensic context:
    - AmCache is one of the most important evidence-of-execution artifacts
      on Windows — it records binaries that ran even after the executable
      has been deleted from disk. A hit here with a matching SHA1 is a
      very strong indicator of execution
    - LastModifyTime (registry key last-write) usually aligns with the
      first time the binary was executed; correlate with process creation
      times from windows_pslist to place an incident on a timeline
    - Compare SHA1 values against public threat intel / VirusTotal. Entries
      whose Path points to user-writable directories (AppData, ProgramData,
      %TEMP%) with an unsigned or unknown Company are high-signal leads
    - Combine with windows_registry_userassist (execution by user via
      Explorer) and windows_registry_scheduled_tasks (execution by Task
      Scheduler) for a fuller persistence / execution picture
    - Driver entries (EntryType containing InventoryDriverBinary) let you
      enumerate all drivers ever loaded; correlate with windows_modules
      and windows_malware_drivermodule to spot drivers that executed historically
      but are no longer loaded
    """
    return session.run_plugin("registry.amcache")


@mcp.tool()
def windows_malware_skeleton_key_check() -> dict:
    """
    Run the skeleton_key_check plugin to detect the Skeleton Key malware
    by scanning lsass.exe for patched authentication functions.

    Use this tool when the user asks about:
    - Skeleton Key malware detection
    - LSASS authentication tampering or credential theft
    - Active Directory backdoor indicators
    - Patched rc4HmacInitialize or rc4HmacDecrypt functions
    - Domain controller compromise indicators

    Returns a dict with:
    - "plugin": "skeleton_key_check"
    - "results": list of dicts, each containing:
        "PID": process ID of lsass.exe (int),
        "Process": process name (str),
        "Skeleton Key Found": whether the Skeleton Key patch was detected (bool),
        "rc4HmacInitialize": address of rc4HmacInitialize function (str, hex),
        "rc4HmacDecrypt": address of rc4HmacDecrypt function (str, hex)

    Forensic context:
    - Skeleton Key is an in-memory patch to LSASS that allows attackers to
      authenticate as any user with a master password, without modifying
      actual user credentials
    - A True value in "Skeleton Key Found" is a definitive indicator of
      compromise on a domain controller
    - Use windows_pslist to verify that lsass.exe is running with expected
      parameters and parent process (should be wininit.exe)
    - Cross-reference with windows_malware_malfind to check for other code
      injections in the lsass.exe process
    """
    return session.run_plugin("malware.skeleton_key_check")


@mcp.tool()
def windows_mbrscan() -> dict:
    """
    Run the mbrscan plugin to scan for and parse potential Master Boot
    Records (MBRs) in the memory image.

    Use this tool when the user asks about:
    - Master Boot Records or MBR analysis
    - Bootkit or boot-level malware detection
    - Disk partition layout found in memory
    - Boot code integrity or MBR tampering
    - Disk signatures or bootable partition indicators

    Returns a dict with:
    - "plugin": "mbrscan"
    - "results": list of dicts, each containing:
        "Potential MBR at Physical Offset": physical offset (str, hex),
        "Disk Signature": disk signature identifier (str),
        "Bootcode MD5": MD5 hash of the boot code section (str),
        "Full MBR MD5": MD5 hash of the entire MBR (str),
        "PartitionIndex": partition table entry index (int),
        "Bootable": whether the partition is marked bootable (bool),
        "BootFlag": boot flag value (str),
        "PartitionType": filesystem or partition type (str),
        "PartitionTypeRaw": raw partition type byte (str),
        "StartingLBA": starting logical block address (str, hex),
        "StartingCylinder": starting cylinder number (int),
        "StartingCHS": starting CHS address (str),
        "StartingSector": starting sector number (int),
        "EndingCylinder": ending cylinder number (int),
        "EndingCHS": ending CHS address (str),
        "EndingSector": ending sector number (int),
        "SectorInSize": partition size in sectors (str, hex)

    Forensic context:
    - Compare Bootcode MD5 against known-good MBR hashes for the OS
      version; mismatches may indicate bootkit infection
    - Bootkits like TDL4, Rovnix, or Carberp modify the MBR to load
      malicious code before the operating system starts
    - Multiple MBR candidates at different offsets may indicate previous
      MBR contents preserved in memory after modification
    - Use windows_info to identify the OS version and determine the
      expected boot code for comparison
    """
    return session.run_plugin("mbrscan")


@mcp.tool()
def windows_truecrypt() -> dict:
    """
    Run the truecrypt plugin to search for cached TrueCrypt passphrases
    remaining in memory.

    Use this tool when the user asks about:
    - TrueCrypt passphrases or encryption keys in memory
    - Full-disk encryption password recovery
    - Cached encryption credentials from TrueCrypt volumes
    - Evidence of encrypted volume usage on the system
    - Decryption key extraction for forensic access

    Returns a dict with:
    - "plugin": "truecrypt"
    - "results": list of dicts, each containing:
        "Offset": memory offset where the passphrase was found (str, hex),
        "Length": length of the passphrase in bytes (int),
        "Password": the cached passphrase string (str)

    Forensic context:
    - TrueCrypt caches passphrases in kernel memory while volumes are
      mounted; this plugin can recover them if the volume was mounted
      at the time of capture
    - Recovered passphrases can be used to decrypt TrueCrypt volumes for
      further forensic examination of their contents
    - Also works with VeraCrypt in some cases, as it shares the same
      passphrase caching mechanism
    - Use windows_pslist to check if TrueCrypt.exe or VeraCrypt.exe
      processes were running at the time of capture
    """
    return session.run_plugin("truecrypt")


@mcp.tool()
def windows_getservicesids() -> dict:
    """
    Run the getservicesids plugin to generate a mapping of Windows service
    names to their computed Security Identifiers (SIDs).

    Use this tool when the user asks about:
    - Service SIDs or service account security identifiers
    - Mapping a SID back to a Windows service name
    - Which services have associated security identifiers
    - Service-level access control or permission analysis
    - Resolving unknown SIDs found in process tokens

    Returns a dict with:
    - "plugin": "getservicesids"
    - "results": list of dicts, each containing:
        "SID": computed service SID string (str),
        "Service": Windows service name (str)

    Forensic context:
    - Service SIDs (S-1-5-80-...) are computed from service names and
      used for per-service access control; this tool provides the mapping
    - Use this output to resolve unknown SIDs found in windows_getsids
      results, identifying which service a process token belongs to
    - Malware that installs itself as a service will have a computable
      service SID that appears in this list
    - Cross-reference with windows_registry_printkey on the Services
      registry key to correlate service configurations with their SIDs
    """
    return session.run_plugin("getservicesids")


@mcp.tool()
def windows_statistics() -> dict:
    """
    Run the statistics plugin to display memory space statistics, showing
    how many pages are valid, swapped, or invalid in the memory image.

    Use this tool when the user asks about:
    - Memory image quality or completeness
    - How many valid vs invalid pages are in the memory dump
    - Swapped or paged-out memory statistics
    - Overall memory utilization at the time of capture
    - Whether the memory image has sufficient data for analysis

    Returns a dict with:
    - "plugin": "statistics"
    - "results": list of dicts, each containing:
        "Valid pages (all)": total valid pages (int),
        "Valid pages (large)": valid large pages (int),
        "Swapped Pages (all)": total swapped pages (int),
        "Swapped Pages (large)": swapped large pages (int),
        "Invalid Pages (all)": total invalid pages (int),
        "Invalid Pages (large)": invalid large pages (int),
        "Other Invalid Pages (all)": other invalid pages (int)

    Forensic context:
    - A high ratio of invalid pages may indicate an incomplete or
      corrupted memory dump, reducing the reliability of other plugins
    - Swapped pages represent data that was paged to disk at capture time;
      this data may be missing from analysis unless the pagefile is available
    - Run this tool early to assess image quality before investing time
      in detailed analysis with other plugins
    - Use windows_info to get OS version context for interpreting the
      memory layout statistics
    """
    return session.run_plugin("statistics")


@mcp.tool()
def windows_crashinfo() -> dict:
    """
    Run the crashinfo plugin to parse and display the header information
    from a Windows crash dump file.

    Use this tool when the user asks about:
    - Crash dump header or metadata
    - Whether the memory image is a crash dump format
    - System time or uptime recorded in the crash dump
    - Number of processors or machine type from the dump header
    - Crash dump type (full, kernel, or mini dump)

    Returns a dict with:
    - "plugin": "crashinfo"
    - "results": list of dicts, each containing:
        "Signature": crash dump signature string (str),
        "MajorVersion": OS major version (int),
        "MinorVersion": OS minor version (int),
        "DirectoryTableBase": DTB address (str, hex),
        "PfnDataBase": PFN database address (str, hex),
        "PsLoadedModuleList": loaded module list address (str, hex),
        "PsActiveProcessHead": active process list head (str, hex),
        "MachineImageType": processor architecture identifier (int),
        "NumberProcessors": number of processors (int),
        "KdDebuggerDataBlock": debugger data block address (str, hex),
        "DumpType": type of crash dump (str),
        "SystemUpTime": system uptime at crash (str),
        "Comment": crash dump comment if present (str),
        "SystemTime": system time at crash (str),
        "BitmapHeaderSize": bitmap header size for full dumps (int),
        "BitmapSize": bitmap size for full dumps (int),
        "BitmapPages": number of bitmap pages (int)

    Forensic context:
    - This plugin only works with crash dump format images; raw memory
      images will produce no results
    - The SystemTime and SystemUpTime fields provide the exact time of
      the crash, anchoring the forensic timeline
    - Use windows_info for general OS information that works with all
      image formats, not just crash dumps
    - NumberProcessors and MachineImageType help verify the system
      configuration matches the expected target
    """
    return session.run_plugin("crashinfo")


@mcp.tool()
def windows_bigpools() -> dict:
    """
    Run the bigpools plugin to list large pool allocations tracked by the
    Windows kernel in the big page pool table.

    Use this tool when the user asks about:
    - Big pool allocations or large kernel memory allocations
    - Kernel pool tag analysis or pool tag statistics
    - Driver memory usage or kernel object allocations
    - Suspicious large allocations that may indicate rootkit or exploit activity
    - Non-paged pool or paged pool consumption

    Returns a dict with:
    - "plugin": "bigpools"
    - "results": list of dicts, each containing:
        "Allocation": base address of the allocation (str, hex),
        "Tag": four-character pool tag identifying the allocator (str),
        "PoolType": pool type such as NonPagedPool or PagedPool (str),
        "NumberOfBytes": size of the allocation in bytes (str, hex),
        "Status": whether the allocation is free or in use (str)

    Forensic context:
    - Pool tags identify which kernel component or driver made the allocation;
      unknown or suspicious tags may indicate rootkit-allocated memory
    - Cross-reference pool tags with known Windows driver tags to identify
      anomalous allocations (e.g., tags not matching any legitimate driver)
    - Large non-paged pool allocations are commonly used by rootkits to store
      injected code or hooked function tables in kernel space
    - Use windows_pslist and windows_psscan to correlate suspicious allocations
      with process activity on the system
    """
    return session.run_plugin("bigpools")


@mcp.tool()
def windows_kpcrs() -> dict:
    """
    Run the kpcrs plugin to enumerate every Windows Kernel Processor
    Control Region (KPCR) structure and its PRCB (Processor Control
    Block) offset — one KPCR per logical CPU.

    Use this tool when the user asks about:
    - How many CPUs / cores were online at capture time
    - KPCR / PRCB addresses for each processor
    - Per-CPU kernel state starting points for deeper analysis
    - Verifying the image's SMP layout matches the system profile

    Returns a dict with:
    - "plugin": "kpcrs"
    - "results": list of dicts (one row per logical CPU), each containing:
        "Offset": virtual address of the _KPCR structure (str, hex),
        "PRCB Offset": virtual address of the embedded _KPRCB (str, hex)

    Forensic context:
    - Row count equals the logical CPU count visible at acquisition
      time; an unexpected count can indicate a corrupted image or the
      wrong symbol profile
    - The PRCB pointer is the entry point for per-CPU kernel state
      (current thread, idle thread, DPC queues). Many other plugins
      (e.g. windows_timers) rely on these offsets internally
    - Mismatched or zero PRCB offsets can be a smear / corruption
      indicator on live-acquired images
    """
    return session.run_plugin("kpcrs")


@mcp.tool()
def windows_unloadedmodules() -> dict:
    """
    Run the unloadedmodules plugin to list kernel drivers / modules that
    have been unloaded but whose names the kernel still tracks in its
    MmUnloadedDrivers history array.

    Use this tool when the user asks about:
    - Drivers that were loaded then unloaded during the capture window
    - Traces of transient kernel malware (e.g. load → exploit → unload)
    - Historical driver activity no longer visible in windows_modules
    - Unload timestamps for forensic timeline construction
    - Signs of a rootkit that deliberately unloads itself to hide

    Returns a dict with:
    - "plugin": "unloadedmodules"
    - "results": list of dicts, each containing:
        "Name": driver / module filename (str),
        "StartAddress": original load base address (str, hex),
        "EndAddress": end of the driver's loaded range (str, hex),
        "Time": timestamp when the driver was unloaded (str, UTC)

    Forensic context:
    - Windows keeps a small ring of recently-unloaded driver entries
      (MmUnloadedDrivers); this plugin reads that ring. A short name
      appearing here but absent from both windows_modules and
      windows_modscan is a classic load-and-unload rootkit pattern
    - Compare Time values against suspicious process creation or
      network activity timestamps to connect a driver's lifecycle to
      observed behavior
    - StartAddress / EndAddress give you the memory range the driver
      occupied; correlate with windows_callbacks / windows_ssdt hook
      entries pointing into those ranges to attribute hooks to the
      unloaded driver
    - An unexpectedly large number of unloaded drivers may indicate
      repeated crash / reload cycles on the image
    """
    return session.run_plugin("unloadedmodules")


@mcp.tool()
def windows_svcscan() -> dict:
    """
    Run the svcscan plugin to enumerate Windows services by scanning the
    services.exe process memory for service record signatures.

    Use this tool when the user asks about:
    - Windows services, service configuration, or installed services
    - Which services are running, stopped, or set to auto-start
    - Service binaries, service DLLs, or service host mapping
    - Malicious services used for persistence (e.g., scheduled-boot payload)
    - Suspicious or unknown services that do not ship with Windows

    Returns a dict with:
    - "plugin": "svcscan"
    - "results": list of dicts, each containing:
        "Offset": virtual offset of the service record (str, hex),
        "Order": ordinal position within the enumerated set (int),
        "PID": process ID hosting the service — typically services.exe or
          a svchost.exe group (int),
        "Start": start type (Auto / Manual / Disabled / System / Boot) (str),
        "State": current runtime state (Running / Stopped / Paused / ...)
          (str),
        "Type": service type flags (Kernel Driver, Win32 Own Process, etc.)
          (str),
        "Name": internal service name (str),
        "Display": human-readable display name (str),
        "Binary": resolved service binary path or ServiceMain entrypoint
          (str),
        "Binary (Registry)": raw ImagePath value from the registry (str),
        "Dll": service DLL for svchost-hosted services (str or None)

    Forensic context:
    - Services configured with Start=Auto whose Binary points to a
      temp/user-writable path (e.g., AppData, ProgramData) are classic
      persistence indicators
    - Cross-reference Binary and Binary (Registry): divergence can indicate
      service hijacking (registry tampering without restart) or unhooking
    - Unusual service types (e.g., Kernel Driver pointing to an unsigned
      or non-standard path) pair with windows_modules and windows_driverscan
      for further rootkit analysis
    - Correlate the PID column against windows_pslist to identify the
      hosting svchost.exe group, then chain to windows_dlllist to inspect
      loaded service DLLs
    - Compare with windows_svclist (when available) to spot list/scan
      discrepancies — a service present here but not in svclist suggests
      DKOM/unlinking of the service record
    """
    return session.run_plugin("svcscan")


@mcp.tool()
def windows_svclist() -> dict:
    """
    Run the svclist plugin to enumerate Windows services by walking the
    services.exe doubly linked list of service records (list-based view,
    as opposed to svcscan's signature scan).

    Use this tool when the user asks about:
    - The canonical list of services currently registered with SCM
    - Running services in their linked order
    - A list-walk view of services for comparison against svcscan results
    - Detection of hidden services via list/scan discrepancy
    - Persistence mechanisms registered with the Service Control Manager

    Important: this plugin supports only 64-bit Windows 10 build 15063 and
    later. On older Windows 7 / 8 / 8.1 or 32-bit samples it will log a
    warning and return an empty result — use windows_svcscan instead.

    Returns a dict with:
    - "plugin": "svclist"
    - "results": list of dicts with the same schema as windows_svcscan:
        "Offset", "Order", "PID", "Start", "State", "Type", "Name",
        "Display", "Binary", "Binary (Registry)", "Dll"

    Forensic context:
    - svclist walks the in-memory linked list of service records used by
      SCM, while svcscan discovers records by signature scanning — any
      service present in svcscan but missing from svclist is a strong
      rootkit / DKOM indicator (the record was unlinked from SCM's list
      but still lives in memory)
    - Use the two tools together: run windows_svcscan and windows_svclist,
      then diff the Name column. This is the logic the deprecated
      windows.svcdiff wrapper (canonical: windows.malware.svcdiff)
      performs internally
    - If svclist returns empty on a supported OS, the services.exe VAD
      scan failed — investigate process integrity with windows_pslist
      and windows_malware_malfind for PID of services.exe
    """
    return session.run_plugin("svclist")


if __name__ == "__main__":
    mcp.run()

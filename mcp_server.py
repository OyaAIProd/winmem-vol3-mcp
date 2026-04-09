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

mcp = FastMCP("winmem-vol3-mcp")
session = Session(IMAGE_PATH)


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
        "Offset(V)": virtual offset of EPROCESS (str, hex),
        "Threads": thread count (int),
        "Handles": handle count (int),
        "SessionId": terminal session ID (int or None),
        "Wow64": whether process is 32-bit on 64-bit OS (bool),
        "CreateTime": process creation timestamp (str),
        "ExitTime": process exit timestamp (str or None)

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
        "Offset": physical offset of EPROCESS (str, hex),
        "Threads": thread count (int),
        "Handles": handle count (int),
        "SessionId": terminal session ID (int or None),
        "Wow64": whether process is 32-bit on 64-bit OS (bool),
        "CreateTime": process creation timestamp (str),
        "ExitTime": process exit timestamp (str or None)

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
        "Offset(V)": virtual offset of EPROCESS (str, hex),
        "Threads": thread count (int),
        "Handles": handle count (int),
        "SessionId": terminal session ID (int or None),
        "Wow64": whether process is 32-bit on 64-bit OS (bool),
        "CreateTime": process creation timestamp (str),
        "ExitTime": process exit timestamp (str or None),
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
        "Offset(V)": virtual offset of the job object (str, hex),
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


if __name__ == "__main__":
    mcp.run()

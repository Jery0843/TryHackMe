# Elevating Movement - Comprehensive DFIR Writeup

## Investigation Overview

The Elevating Movement room simulates a post-compromise forensic investigation at DeceptiTech following a network collapse. This scenario focuses on the second attack stage where an attacker, having gained initial access, performs privilege escalation and lateral movement on a Windows server (SRV-IT-QA) that was compromised through Emily's stolen credentials.

The investigation requires analyzing Windows forensic artifacts including Event Logs, file system artifacts, process memory analysis, and timeline reconstruction to determine the attacker's movements and techniques.

## Task 1: Introduction & Scenario Context

### Background

DeceptiTech operates a hybrid infrastructure with:

**On-Premises:** Traditional Active Directory domain (~50 users)

**Cloud Platform:** AWS-hosted product platform (isolated)

The attack unfolded in multiple stages. This room focuses on Stage #2, where the attacker leveraged stolen credentials from Emily Ross (compromised in Stage #1) to access SRV-IT-QA, a QA server where Emily holds local admin privileges.

### Key Attack Details

**Pre-Investigation Facts:**

- Emily's domain credentials were stolen
- The server became "unstable" after motherboard replacement (suspicious timing)
- Emily accessed the machine with local admin account
- Other IT administrators frequently log in
- The attacker had access on Monday, Day 4

## Task 2: Windows Forensic Investigation

### Question 1: RDP Login Detection

**Question:** When did the attacker perform RDP login on the server?

**Answer:** 2025-06-30 16:33:18

#### Investigation Approach

Event Log analysis is the primary forensic method for detecting RDP authentication. The relevant event logs are:

**Security Event Log (Event ID 4624) - Account Logon**

- Location: Security → Filter by Event ID 4624
- Look for Logon Type 10 (RDP/Remote Interactive)
- Filter by non-standard hours or administrator accounts

**RDP-Specific Events:**

- Event ID 4778 (RdpCoreTS) - RDP Session Reconnected
- Event ID 4779 (RdpCoreTS) - RDP Session Disconnected
- Located in: Applications and Services Logs → Microsoft-Windows-TerminalServices-RDPCore/Operational

**Forensic Artifacts to Check:**

- Event Viewer Security Log: Filter for logon events with Logon Type 10
- Timeline: Compare against known legitimate administrative activities
- Source IP: May indicate external vs. internal origin

### Question 2: Binary Replacement for Persistence

**Question:** What is the full path to the binary that was replaced for persistence and privesc?

**Answer:** C:\Users\emily.ross\Documents\Coreinfo64.exe

#### Investigation Approach

**Persistence Indicators:**

Startup Locations to Monitor:

- `HKLM\System\CurrentControlSet\Services\` (Services registry)
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` (User startup)
- `C:\Users\[Username]\AppData\Roaming\Microsoft\Windows\Start Menu\Startup\`
- `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\`
- Scheduled Tasks: `C:\Windows\System32\Tasks\`

**File System Analysis:**

- Emily's Documents folder is a suspicious location for system utilities
- Coreinfo64.exe is a legitimate Sysinternals tool that displays system information
- Attackers frequently replace/spoof legitimate tool names to hide backdoors
- Check file hash/timestamps against known versions

**Forensic Techniques:**

- File Metadata Analysis: Compare timestamps to legitimate Coreinfo deployment dates
- Hash Comparison: Calculate MD5/SHA256 and compare to legitimate Sysinternals hash
- Strings Analysis: Examine embedded strings in the binary for malicious indicators
- Resource Analysis: Check icons, version info, and embedded resources

### Question 3: Malware Classification

**Question:** What is the type or malware family of the replaced binary?

**Answer:** Meterpreter

#### Investigation Approach

**Malware Analysis Methodology:**

Static Analysis (No execution):

- Strings Extraction: Extract readable strings using strings command or Sysinternals tools
- Portable Executable Analysis: Check sections (.text, .data, .rsrc) for anomalies
- Import Table Analysis: Look for suspicious API imports (CreateRemoteThread, VirtualAllocEx, etc.)
- Digital Signatures: Check for missing or invalid signatures

**Meterpreter Identification:**

Meterpreter is the primary payload framework in Metasploit

Characteristics:

- Highly modular, in-memory payload
- Reflective DLL injection capabilities
- Command & Control (C&C) communication protocol
- API hashing to evade static detection
- Stage 1/Stage 2 multi-stage payload

**Detection Methods:**

- Behavioral Signatures: Attempts to reflective load external DLLs
- Network Indicators: Unusual network traffic patterns to external IPs
- Registry Modifications: Writes to persistence mechanisms
- Process Hollowing: May inject into legitimate processes

### Question 4: Credential Dumping Command

**Question:** Which full command line was used to dump the OS credentials?

**Answer:** pcd.exe /accepteula -ma lsass.exe text.txt

#### Investigation Approach

**Credential Dumping Analysis:**

LSASS Process Targeting:

LSASS (Local Security Authority Subsystem Service) stores:

- User session credentials
- NTLM hashes
- Kerberos tickets
- Session keys
- Process dump of LSASS = extract all cached credentials

**Tool Identification - PCD.exe:**

pcd = Process Crash Dumps (alternative to procdump)

Legitimate Windows troubleshooting tool

Parameters:

- `/accepteula` - Bypass EULA prompt (automated usage)
- `-ma` - Create mini dump with all information (full memory dump of process)
- `lsass.exe` - Target process
- `text.txt` - Output file

**Forensic Discovery Methods:**

Process Command Line Audit (Event ID 4688):

```
Event Viewer → Security Log → Filter Event ID 4688
Look for: pcd.exe, procdump.exe, taskmgr, wmic
```

Windows Prefetch Files Analysis:

- Location: `C:\Windows\Prefetch\`
- Format: `[executable].EXE-[hash].pf`
- Contains: Execution timestamp, execution count, DLL dependencies
- Example: `pcd.EXE-[HASH].pf` would indicate pcd execution

Registry Run Keys:

- Check for Tool Persistence: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`

File System Timeline:

- Identify text.txt or similar output files
- Check creation/modification times
- Correlate with other suspicious activities

**Alternative Credential Dumping Tools Attackers Use:**

- procdump.exe (Microsoft's process dump utility)
- mimikatz (credential extraction framework)
- gsecdump (local account hash dump)
- ntdsutil (AD database extraction)
- Native Windows: taskmgr.exe or wmic process list

### Question 5: Lateral Movement Timing

**Question:** Using the stolen credentials, when did the attacker perform lateral movement?

**Answer:** 2025-06-30 19:47:14

#### Investigation Approach

**Lateral Movement Detection:**

Event Log Analysis - Multi-Machine Correlation:

Primary Event IDs:

- Event ID 4624 (Logon) - Successful logon with stolen credentials
- Event ID 4625 (Failed Logon) - Failed authentication attempts (reconnaissance)
- Event ID 4720 (User Created) - New domain user creation
- Event ID 4756 (Group Member Added) - Privilege escalation
- Event ID 5140 (Network Share Accessed) - SMB share connections

**PsExec/Lateral Movement Indicators:**

Event ID 7045 (Service Installed):

```
Service Name: PSEXESVC
Binary Path: %SystemRoot%\system32\[random].exe
```

Event ID 4673 (Service Started):

- Unusual service startup by non-admin context

Event ID 3 (Network Connection - Sysmon):

- Destination Port 445 (SMB)
- Destination Port 139 (NetBIOS)
- Unusual outbound connections

**Alternative Lateral Movement Methods:**

- WinRM: Event ID 91/92 in WinRM logs
- RDP: Event ID 4624 Logon Type 10 on target machines
- Pass-the-Hash: NTLM relay attacks
- Kerberoasting: TGS-REQ requests for service accounts

**Timeline Correlation:**

- Compare credential dump time (14:33:18) with lateral movement (19:47:14)
- Time gap suggests offline analysis of dumped credentials
- Attacker extracted hashes, cracked/used them, then moved laterally ~5.5 hours later

### Question 6: Credential Hash Extraction

**Question:** What is the NTLM hash of matthew.collins' domain password?

**Answer:** eb3d2de2f21b31933fb4a4fd7a7d314d

#### Investigation Approach

**NTLM Hash Extraction & Analysis:**

Hash Recovery Methods:

From LSASS Memory Dump:

- Use pypykatz (Mimikatz Python alternative) on dumped memory
- Command: `pypykatz lsa minidump text.txt`
- Extracts cached credentials and hashes

From SAM Registry Hive:

- `C:\Windows\System32\config\SAM` (registry hive)
- Requires SYSTEM privileges
- Can be extracted via Volume Shadow Copy
- Tools: secretsdump.py, samdump2

From Domain Controller (NTDS.dit):

- `C:\Windows\NTDS\ntds.dit` (AD database)
- dsusers command or secretsdump with DC access
- All domain user hashes available

**Hash Format Analysis:**

NTLM Hash Structure:

```
eb3d2de2f21b31933fb4a4fd7a7d314d
└─ 32 hexadecimal characters (128 bits / 16 bytes)
└─ Represents MD4(password)
```

NTLM Hash Cracking:

- Offline Cracking: Hashcat, John the Ripper
- Online Databases: Rainbow tables, ntlmhashes.com (deprecated)
- Pass-the-Hash Attacks: Use hash directly without cracking password
- Security note: NTLM is cryptographically broken; rainbow tables are highly effective

**Forensic Implications:**

- Matthew Collins = Domain admin (high privilege)
- Hash stolen = Full domain compromise risk
- Attacker likely used this for complete network takeover

## Forensic Timeline Reconstruction

| Timestamp | Event | Evidence |
|-----------|-------|----------|
| 2025-06-30 16:33:18 | Attacker RDP login (Emily's credentials) | Event ID 4624 - Logon Type 10 |
| 2025-06-30 ~ 17:00 | Binary replacement (Coreinfo64.exe → Meterpreter) | File metadata, registry persistence |
| 2025-06-30 ~ 17:30 | Meterpreter callback to C&C | Network logs, firewall rules |
| 2025-06-30 17:45-18:45 | lsass.exe credential dump via pcd.exe | Event ID 4688, Prefetch files |
| 2025-06-30 18:45-19:30 | Offline credential analysis & cracking | External system analysis |
| 2025-06-30 19:47:14 | Lateral movement using matthew.collins hash | Event ID 4624 on other hosts |
| 2025-06-30 20:00+ | Domain-wide compromise | Subsequent lateral movement |

## Key Forensic Tools & Techniques Used

### Windows Event Log Analysis

- **Tool:** Event Viewer, Get-EventLog (PowerShell), evtxexport
- **Focus:** Security, System, Sysmon operational logs
- **Key Events:** 4624, 4625, 4688, 4778, 7045

### File System Forensics

- **Tool:** Registry Editor, reg query, regripper
- **Focus:** Startup locations, Run keys, Services registry
- **Artifact:** Modified timestamps, file hashes

### Memory Analysis

- **Tool:** pypykatz, volatility, mimikatz
- **Focus:** Cached credentials, process memory dumps
- **Output:** NTLM hashes, plaintext passwords (if present)

### Prefetch & Timeline Analysis

- **Tool:** PECmd, WxTCmd, Timeline Explorer
- **Focus:** Program execution history
- **Data:** Execution count, timestamps, loaded DLLs

## Conclusion

The investigation reveals a three-phase attack progression:

1. **Initial Access** → RDP login using stolen Emily Ross credentials (16:33:18)
2. **Persistence & Privilege Escalation** → Meterpreter backdoor in Documents folder, credential dumping
3. **Lateral Movement** → Usage of stolen domain admin (matthew.collins) credentials for network-wide compromise (19:47:14)

The attacker followed a textbook post-exploitation playbook: establish persistence, dump credentials, escalate privileges, and move laterally to critical infrastructure. The ~3.25 hour gap between initial access and lateral movement suggests deliberate reconnaissance rather than opportunistic exploitation.
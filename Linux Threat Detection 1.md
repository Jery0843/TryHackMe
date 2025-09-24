# TryHackMe — Linux Threat Detection 1 — Walkthrough

---

## Overview

Welcome to an in‑depth walkthrough of TryHackMe's **Linux Threat Detection 1** room. This document mirrors the hands‑on investigation steps used to detect Linux attacks via log analysis. We focus on SSH brute force attacks, web‑service exploitation, and process‑tree analysis — core skills for SOC analysts handling Linux environments.

---

## Room Prerequisites

Before following this walkthrough you should have completed:

- **Linux Logging for SOC** — understanding common Linux log sources
- **MITRE ATT&CK Framework basics** — familiarity with tactics & techniques
- **Basic Linux CLI skills** — comfortable navigating the shell

---

## Lab Setup

Connect to the target machine using the provided credentials:

```
IP Address: 10.10.47.42
Username: ubuntu
Password: Secure!
Connection: SSH

# Example connection
ssh ubuntu@10.10.47.42
```

---

# Task 2: Initial Access via SSH

### Understanding SSH Attack Vectors

SSH is a frequent entry point for attackers. Common risks include:

- **Key‑based risks**: private keys leaked or stolen (repos, backups, or malware).
- **Password risks**: weak or default passwords, brute force attacks.

### Hands‑on Analysis: SSH Log Investigation

Start by inspecting SSH‑related entries in the authentication log:

```bash
# View SSH events
cat /var/log/auth.log | grep "sshd"
```

This will show successful logins, failed attempts, connection handshakes and authentication method details.

**Question 1 — When did the ubuntu user log in via SSH for the first time?**

```bash
cat /var/log/auth.log | grep "sshd" | grep "ubuntu" | grep "Accepted" | head -1
```

**Answer:** `2024-10-22`

**Question 2 — Did the ubuntu user use SSH keys instead of a password?**

Inspect the authentication method in the log entry for `publickey` vs `password`.

**Answer:** Yes (`publickey`).

---

# Task 3: Detecting SSH Attacks

### Identifying Brute Force Patterns

Brute force indicators:

- Many `Failed password` entries from same IP
- Attempts across common usernames
- Successful login following a flood of failures

### Practical Detection Exercise

**Question 1 — When did the SSH password brute force start?**

```bash
cat /var/log/auth.log | grep "Failed password" | head -5
```

**Answer:** `2025-08-21`

**Question 2 — Which four users did the botnet attempt to breach?**

```bash
cat /var/log/auth.log | grep "Failed password" | awk '{print $9}' | sort | uniq
```

**Answer:** `root`, `roy`, `sol`, `user`

**Question 3 — Which IP managed to breach the root user?**

```bash
cat /var/log/auth.log | grep "Accepted password for root"
```

Look for the source IP in the `Accepted` entry.

**Answer:** `91.224.92.79`

### Attack Timeline Summary

Typical progression:

1. Reconnaissance — scanning SSH ports
2. Brute force — multiple account attempts
3. Success — valid credentials discovered
4. Persistence — attacker establishes foothold

---

# Task 4: Initial Access via Services

## Web Application Attack Vectors

Public‑facing apps can be exploited via RCE (T1190), vulnerable plugins, exposed APIs, and command injection.

### Analyzing the TryPingMe Application

The lab’s web application accepts ping input without proper sanitization, allowing command injection.

**Question 1 — What is the path to the Python file the attacker attempted to open?**

```bash
cat /var/log/nginx/access.log | grep -E "(ls|cat|whoami)"
```

**Answer:** `/opt/trypingme/main.py`

**Question 2 — What's the flag inside the opened file?**

```bash
cat /opt/trypingme/main.py
```

**Answer:** `THM{*_**_vulnerable!}`

### Web Attack Detection Strategies

Look for:

- Commands or shell characters in URL parameters (`;`, `&&`, `|`, `` ` ``)
- Unusual 500 responses then 200 responses
- Strange user agents or repeated POSTs to odd endpoints

---

# Task 5: Detecting Service Breach

## Process Tree Analysis Fundamentals

Process trees reveal the origin of suspicious commands and the chain of execution. They help answer: which service was compromised and how did the attacker execute commands?

### Using `auditd` for Process Tracking

Useful commands:

```bash
# Search for specific command execution
ausearch -i -x whoami

# Find parent process using PID
ausearch -i --pid [PARENT_PID]

# List all child processes of a parent
ausearch -i --ppid [PARENT_PID] | grep 'proctitle'
```

### Practical Investigation Exercise

**Question 1 — What is the PPID of the suspicious `whoami` command?**

```bash
ausearch -i -x whoami
```

Inspect the `ppid` field.

**Answer:** `1018`

**Question 2 — What is the PID of the TryPingMe app?**

Trace upward using the parent PID:

```bash
ausearch -i --pid 1018
```

**Answer:** `577`

**Question 3 — Which program did the attacker use to open a reverse shell?**

Check child process `proctitle` entries for network or shell commands:

```bash
ausearch -i --ppid 577 | grep 'proctitle'
```

**Answer:** `python` (the attacker used Python to run shell/network commands)

### Example Process Tree

```
systemd (PID 1)
└── python3 /opt/webapp/app.py (PID 577)
    └── /bin/sh -c whoami (PID 1018)
        └── whoami (PID 1019)
```

This helps establish origin, method, and impact.

---

# Task 6: Advanced Initial Access

## Beyond Traditional Attack Vectors

Additional threats:

- **Supply chain**: compromised tooling or packages
- **Malicious packages** on ecosystems (PyPI, npm)
- **Human‑led social engineering** and watering hole attacks
- **Insider threats**

### Detection Challenges & Methods

- Behavioral analysis and baselining
- File integrity monitoring (FIM)
- Network traffic analysis
- Comprehensive `auditd` rules and correlation

**Question 1 — Which Initial Access technique is likely used if a trusted app suddenly runs malicious commands?**

**Answer:** Supply Chain Compromise

**Question 2 — Which detection method can detect a variety of Initial Access techniques?**

**Answer:** Process Tree Analysis

---

# Key Detection Commands Reference

### SSH Analysis Commands

```bash
# View SSH-related logs
cat /var/log/auth.log | grep "sshd"

# Find failed login attempts
grep "Failed password" /var/log/auth.log

# Identify successful logins
grep "Accepted" /var/log/auth.log

# Count failed attempts per IP
grep "Failed password" /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -nr
```

### Web Log Analysis Commands

```bash
# View nginx access logs
cat /var/log/nginx/access.log

# Search for command injection patterns
grep -E "(;|&&|\||`)" /var/log/nginx/access.log

# Find suspicious status code patterns
grep " 500 " /var/log/nginx/access.log
```

### Auditd Investigation Commands

```bash
# Search by command name
ausearch -i -x [COMMAND]

# Search by process ID
ausearch -i --pid [PID]

# Search by parent process ID
ausearch -i --ppid [PPID]

# Search by key (if audit rules configured)
ausearch -k [KEY_NAME]
```

---

# Real‑World Application

## Building Detection Rules (SIEM)

**SSH Brute Force Detection**

```
Failed SSH attempts > 5 from same IP within 5 minutes
+ Successful SSH login from same IP within 30 minutes
= High-confidence brute force success
```

**Web Application Exploitation**

```
Multiple 500 errors from same IP
+ 200 response with suspicious parameters
+ System commands in URL parameters
= Potential command injection
```

**Process Tree Anomalies**

```
Web server process spawning shell commands
+ Network connections from unexpected processes
+ File system modifications by web processes
= Likely web shell or RCE
```

---

# Defensive Recommendations

### SSH Hardening

- Implement key‑based authentication
- Use `fail2ban` or equivalent for brute force protection
- Change default SSH port (defense in depth)
- Restrict source IP ranges where possible

### Web Application Security

- Input validation & sanitization
- Deploy a Web Application Firewall (WAF)
- Regular security testing & patching
- Principle of least privilege for web processes

### Monitoring Enhancement

- Comprehensive `auditd` rules and FIM
- Real‑time log analysis & alerting
- Behavioral baselining for services

---

# Conclusion

**Linux Threat Detection 1** teaches core detection techniques:

- SSH brute force detection using authentication logs
- Web application attack identification from access logs
- Process tree analysis for root cause investigation

Keep practicing these skills and progress to: `Bulletproof Penguin` (hardening), `Linux Privilege Escalation` (post‑compromise detection), and `Advanced Linux Logging` (monitoring strategies).

---

*End of walkthrough.*

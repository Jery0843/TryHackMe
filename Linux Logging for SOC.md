# Linux Logging for SOC: A Hands-On Journey into Linux Logs

## Introduction

Linux is everywhere---from traditional servers to cloud-native
containers. As a SOC analyst, mastering Linux log investigation is
crucial to detecting compromises and suspicious activity. This room
guides you through common Linux logs, how to analyze them, and how
runtime monitoring works in practical terms using a prepared VM.

------------------------------------------------------------------------

## Task 1: Introduction

You start by accessing the VM and preparing to assume the root role
with:

``` bash
sudo su
```

The goal is to explore Linux logs stored in plain text in `/var/log` and
understand their formats. This room focuses on Linux servers without a
graphical interface.

------------------------------------------------------------------------

## Task 2: Working With Text Logs

Linux logs events like system operations, cron jobs, and time
synchronization in `/var/log/syslog`.

Check initial lines of syslog:

``` bash
cat /var/log/syslog | head
```

Filter specific logs (e.g., cron jobs):

``` bash
cat /var/log/syslog | grep CRON
```

Discover login-related logs by searching with keywords in `/var/log`:

``` bash
grep -R -E "auth|login|session" /var/log
```

### Questions & Answers:

**Which time server domain did the VM contact to sync its time?**\
`ntp.ubuntu.com`

**What is the kernel message from Yama in /var/log/syslog?**\
`Becoming mindful.`

------------------------------------------------------------------------

## Task 3: Authentication Logs

`/var/log/auth.log` captures user logins, sudo commands, SSH events, and
user management.

List all opened and closed user sessions:

``` bash
cat /var/log/auth.log | grep -E 'session opened|session closed'
```

Filter SSH login attempts (accepted and failed):

``` bash
cat /var/log/auth.log | grep "sshd" | grep -E 'Accepted|Failed'
```

Find user management events (additions, deletions):

``` bash
cat /var/log/auth.log | grep -E '(passwd|useradd|usermod|userdel)\['
```

### Questions & Answers:

**Which IP address failed to log in on multiple users via SSH?**\
`10.14.94.82`

**Which user was created and added to the "sudo" group?**\
`xerxes`

------------------------------------------------------------------------

## Task 4: Common Linux Logs

Explore other logs such as:

-   `/var/log/kern.log` for kernel messages\
-   `/var/log/dpkg.log` for Debian package installations\
-   Bash history files per user for command history

Check the unzip version installed:

``` bash
grep unzip /var/log/dpkg.log
```

Review bash history for a flag:

``` bash
grep -r "flag" /home/*
```

or read bash history files:

``` bash
cat /home/ubuntu/.bash_history
cat /root/.bash_history
```

### Questions & Answers:

**Which version of unzip was installed on the system?**\
`6.0-28ubuntu4.1`

**What is the flag you see in one of the users' bash history?**\
`THM{****_**_remember}`

------------------------------------------------------------------------

## Task 5: Runtime Monitoring

Understand Linux system calls like `execve` which execute programs.

### Knowledge Questions:

**Which Linux system call is commonly used to execute a program?**\
`execve`

**Can a typical program open a file or create a process bypassing system
calls?**\
`Nay`

------------------------------------------------------------------------

## Task 6: Using Auditd

Auditd monitors runtime events like process execution and file access.

Search auditd logs for wget download event:

``` bash
ausearch -i -k proc_wget
```

Find when `secret.thm` was first opened:

``` bash
ausearch -i -k file_thmsecret
```

Locate network range scanned (no dedicated key, so search for scanning
tools):

``` bash
ausearch -i | grep -E "nmap|masscan|scan"
```

or extract IPs scanned:

``` bash
ausearch -i | grep -Eo "([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?"
```

### Questions & Answers:

**When was the secret.thm file opened for the first time?**\
`08/13/25 18:36:54`

**What is the original file name downloaded from GitHub via wget?**\
`naabu_2.3.5_linux_amd64.zip`

**Which network range was scanned using the downloaded tool?**\
`192.168.50.0/24`

------------------------------------------------------------------------

## Task 7: Conclusion

You have explored multiple Linux log sources and learned practical
commands to investigate incidents:

-   Linux logging may seem chaotic but provides critical insight.\
-   Logs live in `/var/log/` and are mostly plain text.\
-   Top logs for SOC: `auth.log`, app-specific logs, and runtime logs
    via `auditd`.\
-   Bash history is unreliable for investigations; `auditd` or
    alternative tools are preferred.

You are now ready to investigate Linux systems more effectively,
bridging from initial access to final compromise discovery using Linux
logs.

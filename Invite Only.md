# TryHackMe Writeup – Invite Only (Premium Room)

## Room Overview

"Invite Only" is a premium TryHackMe room where you step into the shoes of an SOC analyst working at **Managed Server Provider TrySecureMe**. Early in the morning, a Level 1 (L1) analyst flagged two suspicious indicators: an IP address and a SHA256 hash. These were escalated to you for deeper analysis. Your mission: to investigate these indicators using the in-house threat intelligence tool **TryDetectThis2.0**, map the attack chain, and extract actionable threat intelligence.

This room is designed to simulate the kind of real-world investigation SOC teams conduct when faced with potential intrusions. It combines **file analysis, malware family identification, and open-source intelligence (OSINT) research** into a single structured investigation. The journey is both technical and story-driven, giving learners an engaging way to practice threat hunting.

---

## Task Walkthrough with Descriptions and Q/A

### **Task 1: File Identification**

**Description:** Using TryDetectThis2.0, the flagged SHA256 hash resolved to an executable file. The system identified the file name as `syshelpers.exe`. This marks the first suspicious artifact in our chain.
**Q:** What is the name of the file identified with the flagged SHA256 hash?
**A:** `syshelpers.exe`

---

### **Task 2: File Type**

**Description:** Further metadata revealed that the flagged hash belonged to a `Win32 EXE`. This confirms it is a Windows executable, a common format used for malware delivery.
**Q:** What is the file type associated with the flagged SHA256 hash?
**A:** `Win32 EXE`

---

### **Task 3: Execution Parents**

**Description:** By analyzing execution lineage, we discovered that the flagged binary was executed by two parent processes: first `361GJX7J`, followed by `installer.exe`. These artifacts help us trace the infection chain back to its origin. The parent hashes were also noted for further investigation.
**Q:** What are the execution parents of the flagged hash? List the names chronologically, using a comma as a separator.
**A:** `361GJX7J,installer.exe`

---

### **Task 4: Dropped File**

**Description:** The analysis revealed that `installer.exe` dropped another malicious file named `Aclient.exe`. Dropped files often serve as payloads or persistence mechanisms within a malware campaign.
**Q:** What is the name of the file being dropped? Note down the hash value for later use.
**A:** `Aclient.exe`

---

### **Task 5: Malicious Dropped Files**

**Description:** The second parent hash was investigated further. It was responsible for dropping multiple malicious files: executables (`searchhost.exe`, `syshelpers.exe`) and VBScript files (`nat.vbs`, `runsys.vbs`). This variety highlights the attacker’s multi-layered approach to persistence and execution.
**Q:** Research the second hash in question 3 and list the four malicious dropped files in the order they appear (from up to down), separated by commas.
**A:** `searchhost.exe,syshelpers.exe,nat.vbs,runsys.vbs`

---

### **Task 6: Malware Family**

**Description:** All identified files and activities pointed toward the **AsyncRAT** malware family. AsyncRAT is a remote access trojan (RAT) commonly used for persistence, remote control, and data theft.
**Q:** Analyse the files related to the flagged IP. What is the malware family that links these files?
**A:** `asyncrat`

---

### **Task 7: Original Report**

**Description:** External OSINT research revealed that these indicators were originally documented in a public report titled **"From Trust to Threat: Hijacked Discord Invites Used for Multi-Stage Malware Delivery."** The report described how attackers leveraged compromised Discord invites for delivering malware.
**Q:** What is the title of the original report where these flagged indicators are mentioned?
**A:** `From Trust to Threat: Hijacked Discord Invites Used for Multi-Stage Malware Delivery`

---

### **Task 8: Cookie Stealing Tool**

**Description:** The attackers employed a tool named **ChromeKatz**. It was specifically designed to exfiltrate browser cookies, providing attackers with session hijacking capabilities and access to user accounts.
**Q:** Which tool did the attackers use to steal cookies from the Google Chrome browser?
**A:** `ChromeKatz`

---

### **Task 9: Phishing Technique**

**Description:** The phishing method identified was **ClickFix**, a deceptive technique used to lure users into clicking malicious links. This social engineering method made it easier to redirect unsuspecting victims to malicious payloads.
**Q:** Which phishing technique did the attackers use?
**A:** `ClickFix`

---

### **Task 10: Platform Used for Redirection**

**Description:** The attackers exploited **Discord** as their platform of choice for redirection. Legitimate-looking Discord invites were hijacked and repurposed, redirecting users into the attacker’s infrastructure.
**Q:** What is the name of the platform that was used to redirect a user to malicious servers?
**A:** `Discord`

---

## Final Thoughts

This room demonstrates the **importance of pivoting across multiple indicators of compromise (IOCs)** — from hashes and IPs to execution parents and dropped files. It ties technical investigation with OSINT research, showing how SOC analysts can transform raw flagged data into actionable threat intelligence.

Through this challenge, learners not only practice file analysis and IOC tracing but also uncover the social engineering techniques (like **ClickFix**) and adversarial abuse of popular platforms (like **Discord**). The journey concludes with a complete attribution to the **AsyncRAT** malware family, emphasizing how multi-stage delivery chains are built in the wild.

---

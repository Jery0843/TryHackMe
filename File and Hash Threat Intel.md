## Room: https://tryhackme.com/room/fileandhashthreatintel
## Introduction

**File and Hash Threat Intel** is a beginner-friendly blue team challenge on TryHackMe designed for SOC analysts and cybersecurity learners. This room teaches practical skills in malware detection, hash analysis, and threat intelligence workflows by simulating real-world scenarios where attackers disguise malicious files using misleading names and extensions.

## Learning Objectives

By completing this walkthrough, you will learn to:
- Detect suspicious file naming conventions and double extensions used for masquerading malware
- Extract and analyze file hashes using PowerShell and CMD on Windows systems  
- Use VirusTotal and MalwareBazaar to classify threats and identify MITRE ATT&CK techniques
- Perform sandbox analysis with Hybrid Analysis to uncover stealthy behaviors
- Apply these techniques to real-world SOC workflows for incident response

## Prerequisites

- Access to the TryHackMe File and Hash Threat Intel room
- Basic understanding of Windows command line
- Familiarity with threat intelligence concepts

---

## Task 1: Introduction (No Questions)

Read through the introduction material about the scenario. You are an L1 analyst who must analyze suspicious binaries flagged by EDR tools and determine if they are benign or malicious within 60 minutes.

---

## Task 2: Filenames and Paths

### Objective
Learn to identify suspicious file naming indicators that malware uses to evade detection.

### Key Concepts
- **Double extensions**: Files like `payroll.pdf.exe` where attackers append legitimate extensions before executable extensions
- **System binary impersonation**: Malware named to look like legitimate Windows files
- **Misleading names**: Files with names designed to appear harmless

### Question & Answer

**Q1:** One file displays one of the indicators mentioned. Can you identify the file and the indicator? (Answer: file, property)

**Answer:** `payroll.pdf, Double extensions`

**Explanation:** Looking at the files in the CTI folder on the desktop, you'll find `payroll.pdf.exe` which uses a double extension technique - a common evasion method where malware appears to be a PDF document but is actually an executable file.

---

## Task 3: File Hash Lookup

### Objective
Learn to generate file hashes and use threat intelligence platforms to analyze suspicious files.

### Key Commands

#### Windows Command Prompt:
```cmd
certutil -hashfile <filename> SHA256
```

#### Windows PowerShell:
```powershell
Get-FileHash -Algorithm SHA256 <filename>
```

### Step-by-Step Process

1. **Navigate to the CTI files location:**
   - Go to Desktop → CTI files folder
   - Files are located at: `C:\Users\Matthew.Collins\Desktop\CTI_Files\`

2. **Generate file hashes using either method above**

3. **Analyze hashes on threat intelligence platforms:**
   - **VirusTotal**: https://www.virustotal.com/
   - **MalwareBazaar**: https://bazaar.abuse.ch/

### Questions & Answers

**Q1:** What is the SHA256 hash of the file bl0gger?

**Commands:**
```cmd
cd C:\Users\Matthew.Collins\Desktop\CTI_Files
certutil -hashfile bl0gger SHA256
```

**Answer:** `2672b6688d7b32a90f9153d2ff607d6801e6cbde61f509ed36d0450745998d58`

**Q2:** On VirusTotal, what is the threat label used to identify the malicious file?

**Steps:**
1. Copy the hash from Q1
2. Go to VirusTotal.com
3. Paste the hash in the search box
4. Look for the threat label in the detection results

**Answer:** `trojan.graftor/flystudio`

**Q3:** When was the file first submitted for analysis? (Answer format: YYYY-MM-DD HH:MM:SS)

**Steps:**
1. On the VirusTotal page for the hash
2. Click on the "Details" tab
3. Look for "First submission" timestamp

**Answer:** `2025-05-15 12:03:49`

**Q4:** According to MalwareBazaar, which vendor classified the Morse-Code-Analyzer file as non-malicious?

**Steps:**
1. Generate hash for Morse-Code-Analyzer file:
   ```cmd
   certutil -hashfile "Morse-Code-Analyzer" SHA256
   ```
2. Search this hash on MalwareBazaar
3. Look for vendor classifications

**Hash:** `1f8806869616c18cbae9ffcf581c0428915d32fb70119df16d08078d92d1a5e3`

**Answer:** `CyberFortress`

**Q5:** On VirusTotal, what MITRE technique has been flagged for persistence and privilege escalation for the Morse-Code-Analyzer file?

**Steps:**
1. Search the Morse-Code-Analyzer hash on VirusTotal
2. Go to the "Behavior" tab
3. Look for MITRE ATT&CK techniques related to persistence/privilege escalation

**Answer:** `DLL Side-Loading`

---

## Task 4: Sandbox Analysis

### Objective
Use Hybrid Analysis for dynamic malware analysis to understand file behavior and execution patterns.

### Platform
**Hybrid Analysis**: https://hybrid-analysis.com/

### Questions & Answers

**Q1:** What tags are used to identify the bl0gger.exe malicious file on Hybrid Analysis? (Answer: Tag1, Tag2, Tag3)

**Steps:**
1. Use the hash from Task 3 Q1: `2672B6688D7B32A90F9153D2FF607D6801E6CBDE61F509ED36D0450745998D58`
2. Search this hash on Hybrid Analysis
3. Look for tags associated with the file

**Answer:** `BlackMoon, Discovery, windows-server-utility`

**Q2:** What was the stealth command line executed from the file?

**Steps:**
1. On Hybrid Analysis results page
2. Look for executed commands
3. Find the command that runs silently (with `/s` flag)

**Answer:** `regsvr32 %WINDIR%\Media\ActiveX.ocx /s`

**Explanation:** This command silently registers a library component without showing user notifications.

**Q3:** Which other process was spawned according to the process tree?

**Steps:**
1. Look at the process tree section in Hybrid Analysis
2. Identify spawned processes

**Answer:** `werfault.exe`

**Q4:** The payroll.pdf application seems to be masquerading as which known Windows file?

**Steps:**
1. Get hash of payroll.pdf file
2. Analyze on Hybrid Analysis  
3. Look for process impersonation indicators

**Answer:** `svchost.exe`

**Q5:** What associated URL is linked to the file?

**Steps:**
1. Use hash: `D202ED020ED8E36BD8A0F5B571A19D386C12ABECB2A28C989D50BBF92C78F54E`
2. Search on Hybrid Analysis
3. Look for "Associated URLs" section

**Answer:** `hxxp://121.182.174.27:3000/server.exe`

**Q6:** How many extracted strings were identified from the sandbox analysis of the file?

**Steps:**
1. On the Hybrid Analysis results page
2. Look for extracted strings count

**Answer:** `454`

---

## Task 5: Threat Intelligence Challenge

### Objective
Comprehensive analysis of a sophisticated malware sample using multiple threat intelligence sources.

### Questions & Answers

**Q1:** What is the SHA256 hash of the file?

**Steps:**
1. Generate hash of the target file in the challenge
2. Use the file hash commands from Task 3

**Answer:** `43b0ac119ff957bb209d86ec206ea1ec3c51dd87bebf7b4a649c7e6c7f3756e7`

**Q2:** What family labels are assigned to the file on VirusTotal?

**Steps:**
1. Search the hash from Q1 on VirusTotal
2. Look for malware family classifications

**Answer:** `akira, filecryptor`

**Q3:** How many security vendors have flagged the file as malicious?

**Steps:**
1. On VirusTotal results page
2. Check the detection score (malicious/total)

**Answer:** `61`

**Q4:** Name the text file dropped during the execution of the malicious file.

**Steps:**
1. Search hash on Hybrid Analysis or VirusTotal
2. Look in behavior analysis for dropped files

**Answer:** `akira_readme.txt`

**Q5:** What PowerShell script is observed to be executed?

**Steps:**
1. Check behavior analysis on sandbox platforms
2. Look for PowerShell command execution

**Answer:** `Get-WmiObject Win32_Shadowcopy | Remove-WmiObject`

**Explanation:** This script is commonly used by ransomware to delete shadow copies, preventing file recovery.

**Q6:** What is the MITRE ATT&CK ID associated with this execution?

**Steps:**
1. The PowerShell command from Q5 relates to inhibiting system recovery
2. Look up the MITRE technique for this behavior

**Answer:** `T1490`

**Explanation:** T1490 - Inhibit System Recovery, used by ransomware to prevent victims from restoring their files.

---

## Key Takeaways for SOC Analysts

### Essential Skills Developed
1. **Hash-Based Detection:** Every file has a unique cryptographic fingerprint that remains unchanged regardless of filename modifications
2. **Multi-Platform Analysis:** Combining results from VirusTotal, MalwareBazaar, and Hybrid Analysis provides comprehensive threat intelligence  
3. **Behavioral Analysis:** Understanding process trees, dropped files, and network communications helps build complete attack narratives
4. **MITRE ATT&CK Mapping:** Connecting observed behaviors to standardized adversary tactics and techniques

### Professional Workflow Integration
- **Validate suspicious alerts** using file hashes
- **Enrich incident data** with threat intelligence  
- **Make rapid triage decisions** based on behavioral indicators
- **Document findings** for incident response teams

### Tools Mastery
- **Windows Hash Generation**: `certutil` and `Get-FileHash` commands
- **VirusTotal**: Multi-engine scanning and community intelligence
- **MalwareBazaar**: Malware sample sharing and classification
- **Hybrid Analysis**: Dynamic sandbox analysis and behavior monitoring

---

## Additional Resources

### Recommended Tools for Further Learning
- **Autoruns**: Microsoft tool with VirusTotal integration for system analysis
- **Process Monitor**: Real-time file system and registry monitoring
- **Wireshark**: Network traffic analysis for C2 communications

### Next Steps
- Complete related TryHackMe rooms: "Intro to Cyber Threat Intel", "Pyramid of Pain"
- Practice with real malware samples in controlled environments
- Study MITRE ATT&CK framework for technique mapping

---

## Conclusion

The File and Hash Threat Intel room provides fundamental skills essential for modern cybersecurity defense operations. By mastering file hash analysis, threat intelligence enrichment, and behavioral analysis techniques, SOC analysts can effectively detect, classify, and respond to file-based threats in production environments.

Remember: Always validate evidence before making decisions, use multiple intelligence sources for comprehensive analysis, and document your findings with supporting evidence for incident response teams.

---

*This walkthrough is for educational purposes only. Always use these techniques responsibly and in authorized environments.*

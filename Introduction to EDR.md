## Room : https://tryhackme.com/room/introductiontoedrs

# Executive summary

Endpoint Detection and Response (EDR) extends beyond traditional antivirus by providing continuous endpoint telemetry, behavioral and anomaly detection, IOC-based matching, ATT&CK mapping, and powerful response actions such as host isolation, process termination, quarantine, remote shell, and artifact collection. Throughout the room, a series of guided tasks reinforced the understanding of EDR architecture, telemetry sources, detection logic, and triage workflow, culminating in a simulated investigation to answer practical questions across multiple endpoints.

# Task 1 — Introduction

**Core idea:** EDR continuously monitors endpoints, detects advanced threats, and provides rich context with process trees, timelines, and historical visibility.

**Key feature that gives full context:** Visibility.

### Answers:

* Which feature of EDR provides a complete context for all the detections?  
    **Answer:** Visibility.
    
* Which process spawned sc.exe?  
    **Answer:** cmd.exe.
    

# Task 2 — Foundations and feature pillars

**Three pillars:** Visibility, Detection, Response.

* Visibility includes process/registry/file/user activity and process trees to reconstruct the attack story; detections blend signatures, behavior, and ML; response enables isolation, kill, quarantine, remote access.
    

### Answers:

* Which feature of EDR provides a complete context for all the detections?  
    **Answer:** Visibility.
    
* Which process spawned sc.exe?  
    **Answer:** cmd.exe.
    

**Emphasis:** EDR is host-centric and complements but doesn’t replace network-level controls.

# Task 3 — Beyond the Antivirus

**Analogy:** AV is like immigration checking passports against a known list; EDR is like in-airport security monitoring ongoing behavior via cameras and sensors.

Scenario comparison showed AV often misses obfuscated PowerShell, memory injection, and unusual parent-child chains; EDR correlates behaviors, flags anomalies, and shows full attack chains.

### Answers:

* In the analogy, what presents an AV?  
    **Answer:** Immigration check.
    
* Which legitimate process was hijacked?  
    **Answer:** svchost.exe.
    
* Which solution might mark this activity as clean?  
    **Answer:** Antivirus (AV).
    

# Task 4 — How an EDR works

Agents (sensors) on endpoints collect rich telemetry and can do local detections; the central console correlates, enriches with threat intel, applies ML/analytics, and surfaces alerts with severity.

EDR integrates with the broader security stack and feeds SIEM for centralized investigations.

### Answers:

* Which component collects telemetry?  
    **Answer:** agent.
    
* An EDR agent is also known as?  
    **Answer:** Sensor.
    

# Task 5 — EDR Telemetry

**Telemetry types:** process executions/terminations, network connections, command-line activity, file/folder modifications, registry changes, and more.

This “black box” data lets analysts reconstruct timelines, identify root cause, and discern benign vs. malicious behaviors even when actions seem individually normal.

### Answers:

* Which telemetry helps detect C2?  
    **Answer:** Network connections.
    
* Where are Windows configuration settings stored?  
    **Answer:** Registry.
    

# Task 6 — Detection and Response Capabilities

**Detection techniques:**

* Behavioral detection: flags unusual parent-child chains (e.g., winword.exe spawning powershell.exe).
    
* Anomaly detection: flags deviation from endpoint baselines.
    
* IOC matching: correlates with known malicious hashes/domains/URLs.
    
* MITRE ATT&CK mapping: contextualizes tactics and techniques.
    
* Machine learning: detects complex/fileless/multi-stage patterns.
    

**Response capabilities:**

* Isolate host, terminate process, quarantine files, remote shell, artifact collection (memory, logs, folders, registry hives).
    

### Answer:

* Which feature helps identify threats based on known malicious behaviors?  
    **Answer:** IOC matching.
    

# Task 7 — Investigate an alert on EDR (Simulated triage)

**Scenario:** Triage medium/high-severity detections across multiple hosts via process trees, network telemetry, and threat intel labelling.

### Answers:

* Which tool was launched by CMD.exe to download the payload on DESKTOP-HR01?
    
    ![](https://cdn.hashnode.com/res/hashnode/image/upload/v1756425496156/6c0a047b-8e3b-4d5d-a5f5-8ec907fe594d.png align="center")
    
      
    **Answer:** cURL.exe.
    
* What is the absolute path to the downloaded malware on DESKTOP-HR01?
    
    ![](https://cdn.hashnode.com/res/hashnode/image/upload/v1756425597257/bbf43c7c-6d92-4418-881d-958e09a3bbdd.png align="center")
    
      
    **Answer:** C:\\Users\\Public\\install.exe.
    
* What is the absolute path to the suspicious syncsvc.exe on WIN-ENG-LAPTOP03?
    
    ![](https://cdn.hashnode.com/res/hashnode/image/upload/v1756425623399/82b78130-4aba-493d-8514-94ec9af09550.png align="center")
    
      
    **Answer:** C:\\Users\\haris.khan\\AppData\\Local\\Temp\\syncsvc.exe.
    
* On which URL was the exfiltration attempt being made on WIN-ENG-LAPTOP03?
    
    ![](https://cdn.hashnode.com/res/hashnode/image/upload/v1756425651428/89fbec28-0d0c-4079-b94a-c1b9816a8bb8.png align="center")
    
      
    **Answer:** https://files-wetransfer.com/upload/session/ab12cd34ef56/dump\_2025.dmp.
    
* What was UpdateAgent.exe labelled by Threat Intel on DESKTOP-DEV01?
    
    ![](https://cdn.hashnode.com/res/hashnode/image/upload/v1756425664894/5535c5e4-595a-45e4-a97f-fe41089e45d8.png align="center")
    
      
    **Answer:** Known internal IT utility tool.
    

# Task 8 — Conclusion and analyst takeaways

**Practical outcomes:**

* **Architectural understanding:** agents (sensors) feed a central console with correlated alerts and contextual evidence.
    
* **Detection depth:** EDR spots behaviors, anomalies, and complex chains that evade AV-only controls.
    
* **Response readiness:** analysts can contain and remediate quickly using isolation, kills, quarantine, remote access, and artifact collection.
    
* **Investigation efficiency:** process trees, command lines, network flows, and ATT&CK mapping reduce time-to-triage and improve decision confidence.
    

**Strategic advice:**

* Pair EDR with SIEM, NDR, email gateways, IAM, and DLP for defense-in-depth.
    
* Maintain tuned baselines and curated detection content; ingest high-quality threat intel for better IOC matching.
    
* Establish clear playbooks for common detections (e.g., PowerShell misuse, LOLBins, process injection, suspicious network beacons).
    
* Use retrospective hunting across historical telemetry to identify spread, persistence, and additional compromised assets.
    

This write-up can be used as a professional after-action report or knowledge note for future SOC onboarding, tabletop exercises, and tool tuning sessions.

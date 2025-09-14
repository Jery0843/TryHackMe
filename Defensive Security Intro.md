## Room : https://tryhackme.com/room/defensivesecurityintro

**Difficulty:** Easy  
**Expected Time:** ~25 minutes  

---

## 📝 Overview

This room introduces the fundamentals of **Defensive Security**, also called **Blue Team** operations, focusing on safeguarding and monitoring networks and systems. You'll explore concepts such as Security Operations Center (SOC), Digital Forensics and Incident Response (DFIR), Malware Analysis, and SIEM tools. The room also includes a practical exercise simulating SOC work to identify and respond to a security alert.

---

##  Task 1: Introduction to Defensive Security

**Question:**  
Which team focuses on defensive security?

**Answer:** Blue Team — responsible for protecting, detecting, and responding to threats within an organization.

---

##  Task 2: Exploring the Security Operations Center (SOC)

Learn about the roles and responsibilities of a **Security Operations Center (SOC)** team:

- **Monitoring for intrusions**, policy violations, suspicious activity, and vulnerabilities  
- Enforcing **policy adherence**, spotting unauthorized behaviors and intrusion attempts  
- Prioritizing **threat detection and response** based on analysis of logs and alerts  

**Question:**  
What would you call a team of cybersecurity professionals that monitors a network and its systems for malicious events?

**Answer:** Security Operations Center (SOC).

---

##  Task 3: Digital Forensics

**Overview of Digital Forensics:**  
Digital forensics involves preserving, analyzing, and interpreting data from systems to investigate incidents. Key focus areas include:

- **File System**: Recovering deleted, partially overwritten, or created files from storage  
- **System Memory**: Analyzing volatile memory for malware or suspicious processes running only in RAM  
- **System Logs**: Reviewing system logs—even if an attacker attempts to erase traces, remnants may remain  
- **Network Logs**: Examining network traffic to detect anomalies or active attacks  

---

##  Task 4: Incident Response

Learn about the **Incident Response process**, often structured in four key phases:

1. **Preparation** – Establishing teams, tools, policies, and training to handle incidents proactively  
2. **Detection & Analysis** – Identifying incidents through alerts and logs and evaluating their scope and severity  
3. **Containment, Eradication & Recovery** – Isolating affected systems, removing threats, and restoring operations  
4. **Post-Incident Activity** – Conducting reviews to learn from the incident, improve policies, and refine defenses  

**Sample Question:**  
What phase of the incident response process involves providing "cyber awareness" training to employees?

---

##  Task 5: Practical Example — Using SIEM Simulation

You're a SOC analyst using a **Security Information and Event Management (SIEM)** dashboard simulation. Your goal:

1. Click **View Site** within the room to open the SIEM simulation  
2. Follow step-by-step instructions to examine alerts and logs  
3. Identify and escalate the relevant incident  
4. Perform appropriate response actions (e.g., blocking an IP)  
5. The flag appears upon successful completion  

**Sample Flag:** `THM{THREAT-BLOCKED}`

---

##  Summary Table of Concepts & Flow

| Task | Focus Area | Key Takeaway |
|------|------------|--------------|
| 1 | Defensive Security Team | Blue Team |
| 2 | SOC Roles | Monitoring, detection, response |
| 3 | Digital Forensics | File system, memory, logs |
| 4 | Incident Response | 4-phase response framework |
| 5 | SIEM Simulation | Practical alert investigation → Flag: **THM{THREAT-BLOCKED}** |

---

##  Final Thoughts

This room is an excellent introduction to Blue Team operations. You'll learn:

- The core responsibilities of defensive security teams  
- How digital forensics aids in incident investigations  
- The structured approach of incident response  
- Hands-on experience with SIEM tooling and alert handling  

---

###  Tips

- Focus not only on answers but also on the logic behind defense processes  
- Understand each component—SOC, DFIR, IR phases—rather than just memorizing terms  
- Try to find more rooms or resources that deepen these defensive cybersecurity skills  

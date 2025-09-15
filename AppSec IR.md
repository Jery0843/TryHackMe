# AppSec IR: Turning Application Incidents into Win-Cidents! 🕵️‍♂️💻

## Introduction

Welcome to the thrilling crossover of **Application Security (AppSec)** and **Incident Response (IR)**! In this room, we explored how attackers target applications, how security teams respond, and how the overlap between AppSec and IR creates a superhero combo for defending modern apps.

By the end of this adventure, you'll understand not just how to patch a vulnerability, but **how to think like a defender while dancing on the fine line between code and chaos**.

---

## Task 1: Introduction to AppSec IR

### What We Learned

* **AppSec IR** is the fusion of traditional IR practices with application security.
* Modern breaches often start in applications — **web apps now account for \~60% of breaches**.
* Learning Objectives:

  * Understand the intersection between AppSec & IR
  * Prepare for application incidents
  * Respond effectively to incidents
  * Learn from incidents to prevent future attacks

**Key Takeaway:** “Failing to prepare for AppSec incidents is like leaving your treasure chest unlocked in a pirate town!” 🏴‍☠️

No answers required here—just strap in for the ride.

---

## Task 2: AppSec IR Fundamentals

### Why AppSec IR Matters

AppSec IR ensures that when vulnerabilities arise, your response is **fast, precise, and informed by knowledge of the application itself**.

**Core Phases Influenced by AppSec:**

1. **Preparation** – Secure coding & testing
2. **Detection & Identification** – Logs, alerts, and bug bounty reports
3. **Containment** – Stop attacks before they spread
4. **Eradication** – Remove root causes
5. **Recovery** – Restore systems & learn lessons

### Collaboration

The magic of AppSec IR is **teamwork**: developers and security responders working together. Example:

* AppSec team identifies the vulnerable code and provides a patch
* IR team deploys a WAF rule to block attacks temporarily

### Tools We Use

* **SIEM:** Aggregates logs & detects anomalies
* **WAF:** Blocks malicious traffic patterns/IPs
* **RASP:** Detects attacks in real-time inside the app
* **Threat Intelligence:** Provides IOCs and TTPs

**Scenario:** ShopSmart, an online retailer, suffers a SQL injection attack during a seasonal sale. AppSec IR comes to the rescue! 🛒💥

**QA:**

* **Which tool analyses logs & aggregates security events?** `SIEM` ✅
* **Which IR phase deploys emergency WAF rules?** `Containment` ✅

---

## Task 3: Preparing for Application Incidents

### Preparation is Key 🔑

* **Secure by Design:** Integrate security from day one
* **Observability:** Log authentication attempts, API calls, errors, etc.
* **Monitoring:** Centralized dashboards & alerts (Elastic Stack, Splunk, Sentinel)

### IR Playbooks

Playbooks document **step-by-step responses** for specific threats.
Example for SQLi:

1. Update WAF rules
2. Block offending IPs
3. Patch vulnerable code
4. Monitor logs post-fix

**QA:**

* **Approach reducing likelihood of incidents:** `Secure by Design` ✅
* **OWASP category for poor observability:** `A09: Security Logging and Monitoring Failures` ✅
* **Document outlining IR steps:** `IR Playbooks` ✅

---

## Task 4: Responding to an Application Incident

### Detection & Identification 🔍

* **Log anomalies**: Spike in database errors
* **User reports**: Feedback from users
* **Bug bounty**: Incentivized vulnerability reporting

### Containment 🛑

* **Disable vulnerable endpoint** (feature flag)
* **Apply WAF rules** to block malicious patterns/IPs
* **Stop the spread**: Isolate compromised accounts/systems

**QA:**

* **Incentivised third-party vulnerability detection:** `Bug Bounty` ✅
* **Mechanism to disable features instantly:** `Feature Flag` ✅
* **Tool to block malicious traffic:** `WAF` ✅

---

## Task 5: Remediation & Recovery

### Eradication 🔧

* Patch vulnerabilities (`hotfix`)
* Remove malicious artifacts (malware, web shells)
* Preserve forensic evidence
* Reset credentials / revoke compromised accounts

### Restoration & Validation ✅

* Test systems thoroughly
* Re-enable fixed endpoints
* Monitor for recurrence

### Lessons Learned

* Conduct a **post-mortem**
* Produce an **incident report** detailing timeline, root cause, and recommendations

**QA:**

* **Developer action to patch vulnerability:** `hotfix` ✅
* **Routes re-enabled during:** `Containment` phase ✅
* **Process of learning lessons:** `Post-mortem` ✅
* **Document produced:** `Incident Report` ✅

---

## Task 6: Practical AppSec IR in Action

### Steps Completed

1. Booted AttackBox & Target Machine
2. Accessed the ShopSmart application front end (`10.10.173.77`)
3. Investigated logs:

   ```bash
   ssh appsecir@10.10.173.77
   cd /home/appsecir/Documents/Logs
   grep 'successful login' application-incident-logs.jsonl
   ```
4. Detected the IDOR vulnerability in `/users/:id/profile`
5. Identified attacker activity, victim account, and timestamps
6. Disabled vulnerable endpoint using admin ID `999`
7. Monitored logs for suspicious access patterns
8. Verified that endpoint was secured and restored normal operations

**QA / Findings:**

* **Vulnerability Type:** `IDOR (Insecure Direct Object Reference)`
* **Affected Endpoint:** `/users/:id/profile`
* **Attacker Activity:** Confirmed unauthorized access
* **Affected User:** `Account ID 103 - Email: aaron.miller@company.thm`
* **Containment Action:** Disabled vulnerable endpoint
* **Flag:** *Hidden for self-validation* ✅

---

## Task 7: Conclusion

### Turning Incidents into Win-Cidents! 🎉

* AppSec IR combines security awareness with rapid, effective response
* Preparedness, detection, containment, eradication, and recovery are key
* Learning from incidents ensures a safer future for applications
* Collaboration between developers and IR teams is essential

**Final Thoughts:**
"An incident is not a setback; it’s a lesson wrapped in chaos. Learn, adapt, and respond faster next time!" 🚀

---

*End of Write-Up*

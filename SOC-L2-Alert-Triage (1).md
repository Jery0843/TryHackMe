# SOC L2 Alert Triage

## Room Overview

This room sits inside the SOC Level 2 learning path and focuses on the core L2 responsibility: taking an alert that L1 has already triaged and escalated, then performing the deeper log analysis, verdict-making, and advanced response actions that L1 cannot perform alone.

The key distinction taught throughout the room is that **L1 optimizes for triage speed**, while **L2 optimizes for triage quality and depth**.

| Aspect | Level 1 | Level 2 |
|---|---|---|
| **Trigger** | New security alert | Escalated alert |
| **Focus** | Quick alert triage within SLA | Deeper log analysis and response |
| **Tools** | Ticketing system + SIEM | Wider range of SOC and IT tools |
| **Response** | Quarantine file, approve SOAR playbook | Manually clean malware, disable users, isolate hosts |

---

## Task 1 - Introduction

*No graded question.*

This task sets the stage: escalated alerts may represent exfiltration, ransomware, or wiper activity, and the room's objective is to teach the L2 workflow, SOC best practices, and the senior analyst mindset.

**Prerequisites:**
- Senior Security Analyst Intro room
- SOC Team Internals module

---

## Task 2 - SOC L2 Workflow

**Question:** What is the most common trigger for L2 to start the triage?
**Answer:** `Escalated alert`

### Explanation

Unlike L1, whose workflow always begins with a fresh alert firing in the SIEM, an L2 analyst's day-to-day work begins when L1 has already reviewed an alert and pushed it upward because it needs deeper investigation, coordination with other teams, or an advanced response action. Occasionally an L2 may also be triggered by a direct urgent request from management or an MSSP customer, but escalation from L1 remains the dominant trigger.

---

## Task 3 - Log Analysis as L2

**Question:** Should you understand the rule purpose before triaging the alert? (Yea/Nay)
**Answer:** `Yea`

**Question:** What term is used for a chronological list of events (related to the attack)?
**Answer:** `Timeline`

### Explanation

Before touching any logs, the analyst must know exactly what technique the triggered detection rule is designed to catch - otherwise, the investigation starts blind and risks missing the actual attack pattern.

Once the rule's purpose is understood, the L2 workflow follows two stages:

1. **See what happened** - quick SIEM queries to build a high-level "story" (why did the rule fire, what happened next, what caused the initial trigger)
2. **Build a detailed timeline** - a full chronological reconstruction of process, file, and network activity across every involved host, used to surface hidden indicators such as dropped DLLs, C2 domains, or malicious IPs

When the story alone can't answer every open question, L2 analysis becomes a **threat hunting loop**:

> Form a hypothesis → Build a timeline to close the gaps → Evaluate whether the story is complete → Repeat if it isn't

---

## Task 4 - Threat Response

**Question:** What is the term for a temporary response that stops the threat from spreading?
**Answer:** `Containment`

**Question:** You see clearly malicious activity on a corporate device. You also know about an ongoing pentest, but the red teamers do not respond. Would you isolate the device before receiving confirmation? (Yea/Nay)
**Answer:** `Yea`

### Explanation

Response in the L2 workflow follows a strict logic gate:

```
Verify the activity → Determine true/false positive → Respond accordingly → Resolve the case → Capture lessons learned
```

**Verification of activity** means confirming legitimacy directly with the affected party before jumping to conclusions - asking the user if a login was theirs, confirming a new admin account with IT, or checking a suspicious API call with DevOps. If there's no response and the risk is high, the account or host gets disabled/isolated **by default** rather than left exposed.

**Response to true positives** scales with blast radius. A single infected laptop might only need an EDR quarantine, while a large-scale intrusion could require RDP/SSH access to hosts, disabling identities in Entra ID, subnet isolation, and emergency patching.

**Response to major incidents** follows the classic three-phase IR model:

| Phase | Action |
|---|---|
| **Containment** | Isolate hosts or disable users to stop the threat from spreading, applied immediately even before the investigation is complete |
| **Eradication** | Remove malware, rotate stolen credentials, revoke exposed privileges |
| **Recovery** | Lift containment, patch the root-cause vulnerability, and monitor for reinfection |

This is why isolating a device with clearly malicious activity is the correct call even when a pentest is technically in progress - without confirmation from the red team, you cannot assume the activity is sanctioned, and the cost of a false containment is far lower than the cost of an active real intrusion left unchecked.

**Response to false positives** still requires action, just at lower urgency - three common outcomes:
- **False Positive Tuning** - fixing a flawed detection query
- **Security Hardening** - fixing an exposed risk the FP incidentally revealed (e.g., open RDP)
- **Team Improvement** - correcting an L1 analysis mistake through mentorship

**Resolving the case** always includes three non-negotiable steps:
1. Log evidence of every action taken in a centralized ticketing system
2. Inform the wider SOC team (especially about anything novel)
3. Keep external parties like MSSP customers updated with a summary

---

## Task 5 - Learning Lessons & Practical Challenge

This task combines a reflection principle with a hands-on simulation covering a fake **Claude Desktop installer** that actually delivers an infostealer.

### Challenge Phase 1 - Analysis (drag-and-drop into buckets)

**See What Happened** *(first 5 minutes)*
- Quickly review what the malware is doing now and how urgent the situation is
- Check the past activity: who launched Claude and where it was downloaded from

**Build a Timeline** *(detailed investigation)*
- Trace and note the malware's full process, file, and network activity up to the present time
- Reconstruct the complete attack timeline and collect indicators of compromise (IOCs)

**Make Your Verdict** *(summarize what you've learned)*
- Reach a **True Positive** verdict and proceed to the Response stage with the collected IOCs
- Determine the root cause of Claude running malware: supply chain compromise, prompt injection, or an imposter binary

### Challenge Phase 2 - Response Actions (ordered sequence)

The scenario reveals that the "Claude Desktop" installer was actually an infostealer downloaded from a fake **claude.top** website. The correctly ordered response sequence:

1. **Isolate** the infected `LPT-1601` from the network *(Containment)*
2. **Eradicate** the infostealer and its files from the host *(Eradication)*
3. **Rotate** all stolen passwords, keys, and tokens *(Eradication)*
4. **Lift** host isolation and inform the user and your team *(Recovery)*
5. **Monitor** - ask your team to keep an eye on the user/host *(Recovery / monitoring)*

> This directly mirrors the NIST Containment → Eradication → Recovery model taught in Task 4 - isolate first to stop spread, clean the host and rotate compromised credentials, then only lift isolation once the threat is fully removed, followed by continued monitoring for reinfection.

### Challenge Phase 3 - Lessons Learned (select the 4 best options)

The four correct reflection actions for this incident:

1. Search for attack indicators on the other workstations
2. Communicate with your L1 on how to improve escalation comments
3. Build an early-stage detection rule that covers malicious downloads
4. Suggest enabling a web filter to block fake websites

**Incorrect distractors:** *replacing the EDR vendor outright* and *disciplining the affected user* - both go against the senior mindset taught in this room. A single miss doesn't justify a vendor swap, and blaming the end user contradicts the "learn, don't punish" culture senior analysts are expected to build within their SOC team.

### Flag

The challenge flag is generated dynamically per session inside the embedded static site once all three phases are completed correctly, so it will be unique to your run and appear directly on the results screen after phase 3 is checked.

---

## Task 6 - Conclusion

*No graded question.*

This task confirms room completion and points toward the next room, **Report Writing for SOC L2**, which builds on this incident by teaching how to document it in a professional report for stakeholders and MSSP customers.

---

## Key Takeaways

- L2 triage begins with **escalation**, not raw alerts - always understand the detection rule's purpose first
- Investigation follows **"see what happened" → "build a timeline"**, looping as a threat hunt when the story is incomplete
- Response follows a strict **verify → classify → respond → resolve → reflect** logic gate
- Major incidents follow the **Containment → Eradication → Recovery** model, with containment applied immediately even before investigation completes
- Case resolution always requires **logging, internal communication, and external updates**
- Lessons learned should focus on **systemic improvement** (detection rules, escalation quality, hardening) - not vendor blame or user punishment
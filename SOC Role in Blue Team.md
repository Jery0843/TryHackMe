# SOC Role in Blue Team — Writeup 

## Room overview

**Goal:** Learn where the SOC sits in an organization, what Blue Team does, how SOC roles are structured, and how a SOC L1 analyst can advance their career. The room mixes conceptual knowledge (org structure, responsibilities) with practical career advice (skills, next roles, MSSP vs internal SOC).

---

## 1) What is the Blue Team? — description

**Description:**
The Blue Team is the defensive crew — the people and processes that detect, respond to, and limit damage from attacks. They operate the Security Operations Center (SOC), build detections, tune tools, and collaborate with other security teams (e.g., GRC, Red Team, CIRT). The Blue Team’s job is to keep attackers out, spot them fast when they get in, and remediate effectively.

**Q:** Does Blue Team focus on defensive or offensive security?
**A:** `Defensive`

---

## 2) Where does the SOC sit in company structure? — description

**Description:**
Large organizations usually route security decisions to a CISO (Chief Information Security Officer). The CISO oversees departments like SOC (Blue Team), Red Team, GRC, AppSec, and Incident Response. SOC analysts (technical staff) report to a SOC manager, who reports to a director or CISO depending on the org.

**Q:** Which senior role typically makes key cyber security decisions?
**A:** `CISO`

**Q:** What is the common name for roles like SOC analysts and engineers?
**A:** `Blue Team`

---

## 3) SOC team composition — description

**Description:**
A typical SOC includes:

* **L1 Analysts** — Junior triage: review alerts, do initial enrichment, escalate to L2 if needed.
* **L2 Analysts** — Deeper investigations, hunting, playbook execution, complex triage.
* **Engineers** — Tune and maintain tools (SIEM, EDR), create detection rules, automate tasks.
* **Manager** — Operational oversight, staffing, KPIs.
  Outside SOC, a **CIRT**/CSIRT handles full-scale incidents and forensics.

**Q:** Which department handles active or urgent cyber incidents?
**A:** `CIRT`

---

## 4) Internal SOC vs MSSP — description

**Description:**
Two environments to work in — both teach valuable skills but differ in pace and exposure:

* **Internal SOC:** Focus on one organization. You learn depth (business context, specific tech stack). Shifts can be calmer.
* **MSSP (Managed Security Service Provider):** Monitor many customers and tech stacks. Fast-paced, lots of variety, steeper learning curve early on (great for exposure and experience).

**Q:** How would you call a cyber security company providing SOC services?
**A:** `MSSP`

---

## 5) Career ladder and how to progress — description

**Description:**
Typical progression: **L1 Analyst → L2 Analyst → Threat Hunter/Incident Responder or SOC Engineer → Manager → Director/CISO**. But routes vary: some move sideways into AppSec, Forensics, or DevSecOps. Key early goal: get real incident-handling experience and learn to think like an attacker.

**Practical tips to advance:**

1. **Master fundamentals** — TCP/IP, Windows/Unix internals, basic scripting.
2. **Learn your tools** — SIEM queries, EDR triage, network captures.
3. **Get certifications** (helpful early ones: CompTIA Security+, Splunk fundamentals, CEH; later: OSCP, GIAC certs).
4. **Practice** — CTFs, home lab, threat hunts.
5. **Document & communicate** — write clear incident notes and playbooks.

**Q:** Which role naturally continues your SOC L1 analyst journey?
**A:** `SOC L2 Analyst`

---

## 6) Day-in-the-life — description

**Description:**
A typical L1 shift includes:

* Reviewing SIEM/EDR alerts and tickets.
* Performing initial enrichments (WHOIS, VirusTotal, process/parent checks).
* Escalating validated incidents to L2/CIRT.
* Updating the ticket with evidence and remediation suggestions.
* Attending handover and daily standups.

Pro tip: produce reproducible steps for L2 so they don’t waste time redoing initial work.

---

## 7) Specialised Blue Team roles — description

**Description:**
As you gain experience, you can specialize:

* **Threat Intelligence Analyst** — tracks threat actors and TTPs.
* **Digital Forensics Analyst** — deep disk/memory analysis.
* **AppSec/DevSecOps** — integrate security into SDLC.
* **AI Security Researcher** — defensive models and adversarial ML.

Specialization often follows broad experience in SOC or CIRT.

---

## 8) Four golden rules for SOC analysts — description

**Description:**

1. **Learn from every alert.** Each alert is a lesson.
2. **Think like an attacker.** Ask: how would I bypass detection?
3. **Verify everything.** Don’t assume — evidence matters.
4. **Get involved.** Volunteer for hunts, write-ups, or tool automation.

---

## 9) Final challenge — description

**Description:**
The room’s final interactive challenge places you in the CISO chair, assigning roles to incidents. It tests your understanding of which team should respond to each incident type (SOC, CIRT, Red Team, etc.). Completing it yields the room’s flag.

**Q:** What flag did you claim after completing the final challenge?
**A:** `[FLAG HIDDEN]`

---

## 10) Quick-career checklist (one page)

**Must-have skills:** networking, OS internals, SIEM queries, EDR basics, scripting (Python/Bash/PowerShell), incident reporting.

**Nice-to-have:** malware basics, forensics, threat intel, cloud security, logging pipelines.

**Certs to consider:** Security+, Splunk fundamentals, Azure/AWS security fundamentals, then GIAC/OSCP as you specialize.

**Daily habit:** read one security blog, play one challenge, document one lesson.

---

## Final summary — description

**Description:**
This room gives a concise map of Blue Team roles and the practical steps to move from L1 to more senior and specialized positions. It clarifies the differences between internal SOCs and MSSPs, shows where CIRT fits, and lays out the career path and skill-building steps to accelerate your progress. Think of L1 as your foundation — steady, repetitive work that builds the muscle memory you need to handle bigger incidents later.

---

*End of document.*

## Room : https://tryhackme.com/room/jrsecanalystintrouxo

**Focus**: Role overview, triage mindset, quick alert investigation, escalation, containment.

---

## Task 1 — A Career as a Junior (Associate) Security Analyst

**Role**: Triage Specialist.  
**Answer** for *"What will be your role as a Junior Security Analyst?"* → **Triage Specialist**.

### Practical takeaway:
Responsibilities include:
- Monitoring/investigating alerts
- Managing tools
- Writing basic IDS signatures
- Escalating to Tier 2/Team Lead when required

---

## Task 3 — A Day in the Life: Alert Handling, IP Check, Escalation, Containment

The in-room *"View Site"* opens a mock SIEM/alert console.

### Identify the malicious indicator
The alert flags an unauthorized connection attempt.  
**Malicious IP observed in alerts**: `221.181.185.159`.

### Scan/verify threat reputation
The room presents an “IP Scanner” widget; entering `221.181.185.159` returns it as malicious.

**Real-world equivalent commands:**

```bash
# AbuseIPDB (replace $API_KEY and confirm ToS)
curl -G https://api.abuseipdb.com/api/v2/check --data-urlencode "ipAddress=221.181.185.159" -d maxAgeInDays=90 -H "Key: $API_KEY" -H "Accept: application/json"

# Whois lookup
whois 221.181.185.159

# Passive DNS
dig -x 221.181.185.159 +short
```

**Answer** for *"What was the malicious IP address in the alerts?"* → `221.181.185.159`.

---

### Escalate appropriately
Choose SOC Team Lead: **Will Griffin**.  
**Answer** for *"To whom did you escalate the event associated with the malicious IP address?"* → **Will Griffin**.

---

### Contain by blocking the IP
Use the room’s “Block IP” control with `221.181.185.159` to receive the final flag.

**Answer** for *"After blocking the malicious IP address on the firewall, what message did the malicious actor leave for you?"* → `THM{UNTIL-WE-MEET-AGAIN}`.

**Real-world equivalent commands (examples; do not run blindly in production):**

```bash
# Linux nftables
sudo nft add table inet filter
sudo nft add chain inet filter input { type filter hook input priority 0 ; }
sudo nft add rule inet filter input ip saddr 221.181.185.159 drop

# Linux iptables
sudo iptables -A INPUT -s 221.181.185.159 -j DROP

# UFW (Ubuntu)
sudo ufw deny from 221.181.185.159

# Palo Alto (CLI example concept)
set address 221_181_185_159 ip-netmask 221.181.185.159/32
set address-group Blocked_IPs static 221_181_185_159
commit

# Cisco ASA
access-list OUTSIDE-IN deny ip host 221.181.185.159 any
access-group OUTSIDE-IN in interface outside

# Windows Defender Firewall (PowerShell)
New-NetFirewallRule -DisplayName "Block 221.181.185.159" -Direction Inbound -RemoteAddress 221.181.185.159 -Action Block
```

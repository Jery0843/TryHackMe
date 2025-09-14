## Room : https://tryhackme.com/room/sessionforensics
## 📖 Prologue: Trouble at TryFlufMe  
The TryFlufMe (TFM) team called me in. Something wasn’t right.  
Their internal admin portal had been behaving strangely — a normal user suddenly pulling **admin-level tricks**.  

Logs were messy. Security Analysts were stuck. They needed an **Application Forensics Specialist** (that’s me). My mission: **unravel the mystery of the stolen sessions and forged tokens** before things spiraled further.  

Time to dig in.  

---

## 🔑 Task 2 – Sessions & JWT: The Foundation  
Before I dived into the crime scene, I needed to recap my knowledge about sessions and JWTs.  

Sessions are like the **keys to a hotel room** — the server holds the room number, while you only carry the keycard (session ID). JWTs, on the other hand, are more like **boarding passes** — they hold all the info inside them, no central database needed.  

But that flexibility comes at a price: if the boarding pass (JWT) is forged or tampered with, boom — instant access.  

### 📝 Answers
- **What security mechanism do you have to implement when introducing JWT?**  
👉 `revocation`  
- **What is the attack called when an attacker steals your session ID?**  
👉 `session hijacking`  

---

## 🔍 Task 3 – Inspecting the Evidence  
I cracked open the logs. Sessions and JWTs appeared everywhere.  

- **Session cookies**: stored safely with `HttpOnly; Secure`.  
- **JWT tokens**: base64 blobs floating in `Authorization` headers and browser storage.  

I decoded one:  
```bash
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```
Payloads revealed usernames, roles, and expiry times. Some tokens were legit. Some… felt off.  

### 📝 Answers
- **Where would you find logs useful for investigating privilege escalation?**  
👉 `application logs`  
- **Where would you find logs useful for mapping user-agent and IP addresses?**  
👉 `web server logs`  
- **Which logs would you check if a JWT token has been forged?**  
👉 `Identity Provider logs`  

---

## 🕵️‍♀️ Task 4 – The Crime Scene  
The files landed on my desk:  

- `webserver.log` → showed browsing with a legit token, then suddenly switching to a **forged one**.  
- `app.log` → screamed about a **role mismatch** (user suddenly became admin).  
- `idp.log` → clean. IdP had **never issued admin tokens**.  
- `browser_dump.txt` → ah, jackpot. A **malicious JWT** lurked in localStorage.  

I decoded the malicious token. Something strange… its algorithm was `none`. **Classic JWT forgery trick**.  

The perpetrator? A familiar name: **FluffyCat** 🐱.  
At first, just a harmless user. But with a tampered JWT, FluffyCat clawed their way into the admin portal.  

### 📝 Answers
- **What user-agent can be seen in the logs?**  
👉 `Mozilla/5.0`  
- **Based on the logs, what kind of tokens are we dealing with?**  
👉 `JWT`  
- **What is the IdP server that issued the tokens?**  
👉 `auth.catportal.internal`  
- **Which user has requested the tokens?**  
👉 `FluffyCat`  
- **Which role change triggered the warning?**  
👉 `admin`  
- **What was the malicious token used?**  
👉  
```text
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VybmFtZSI6IkZsdWZmeUNhdCIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTcyMTQzMTgwMCwiZXhwIjoxNzIxNDM1NDAwfQ
```
- **What algorithm did the malicious token use?**  
👉 `none`  
- **What was the previous legitimate token?**  
👉  
```text
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6IkZsdWZmeUNhdCIsInJvbGUiOiJ1c2VyIiwiZXhwIjoxNzIxNDM1NDAwfQ.WMKctz1p5KLwNP_C7XXcWbP8uEpbwSeEY_hU_dhG6Rk
```
- **What algorithm did the legitimate token use?**  
👉 `HS256`  

---

## 🛡️ Task 5 – Containment & Hardening  
I briefed SecOps:  

- **Immediate containment** → Revoke all FluffyCat sessions, rotate credentials, invalidate tokens.  
- **Audit** → comb through logs for any more forged tokens.  
- **Temporary lockdown** → restrict admin portal until trust is restored.  

Then, to prevent history repeating:  

1. **Strong Signature Validation** – reject `alg: none` and enforce proper signature checks.  
2. **Issuer Validation** – tokens must match `auth.catportal.internal`.  
3. **Secure Storage** – no more tokens in localStorage; switch to `HttpOnly` cookies.  
4. **Token Verification & Reuse Detection** – cross-check claims, expiration, and issuer at every step.  

### 📝 Answers
- **What can you add to ensure a JWT token is not tampered with?**  
👉 `token verification`  

---

## 🏁 Task 6 – Conclusion  
The case closed with one clear lesson: **logs never lie**.  

By stitching together **web, app, IdP, and browser evidence**, I uncovered FluffyCat’s climb from an ordinary user to a rogue admin.  

The weakness? A **JWT validation flaw**.  
The fix? **Strict signature enforcement and smarter token handling**.  

Another day, another cat burglar caught. 🐾  

---

## 🎯 Achievement  
Room Completed: ✅ 100%  
Difficulty: **Medium**  
Time Taken: ~60 min  

---

🔥 **Top 3 Tags:**  
`#JWT` `#SessionHijacking` `#Forensics`  

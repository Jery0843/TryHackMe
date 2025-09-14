## Room : https://tryhackme.com/room/offensivesecurityintro

**Difficulty:** Easy  
**Expected Time:** ~15 minutes  

---

## 📝 Overview

In this beginner-friendly room, you're introduced to **Offensive Security** and get hands-on experience hacking a simulated web application—**FakeBank**—using the directory brute-forcing tool **Gobuster**. By mimicking a hacker's actions, you'll practice ethical hacking in a safe, legal environment.

---

##  Task 1: What is Offensive Security?

You're asked:

> Which of the following options better represents the process where you simulate a hacker's actions to find vulnerabilities in a system?  
> - Offensive Security  
> - Defensive Security

**Answer:** *Offensive Security*  
> Reason: It involves simulating hacker behavior to uncover vulnerabilities before a cybercriminal does.

---

##  Task 2: Hacking Your First Machine

### Step 1: Start the Machine

Launch the VM for the FakeBank application and open the browser and terminal interface.

### Step 2: Open the Terminal

On the right side of the interface, click the **Terminal** icon to start typing commands.

### Step 3: Use Gobuster to Discover Hidden Directories

Run:

```bash
gobuster -u http://fakebank.thm -w wordlist.txt dir
```

- `-u` specifies the target URL (`http://fakebank.thm`)  
- `-w` specifies the wordlist (`wordlist.txt`)  
- `dir` tells Gobuster to use directory brute-forcing mode  

Example output:

```
/images (Status: 301)  
/bank-transfer (Status: 200)  
```

### Step 4: Access the Bank Transfer Page

Navigate to:

```
http://fakebank.thm/bank-transfer
```

This is the hidden admin portal that allows money transfers.

### Step 5: Exploit the Vulnerability

Use the admin interface to transfer **$2000** from account **2276** to **8881**.  
After submitting, you should see a “Success, transfer complete” message.  
Return to your account view to see your updated balance.  
The page will display the room’s **flag**:

**Flag:** `BANK-HACKED`

### Step 6: Terminate the Machine

Click the red **Terminate** button in the TryHackMe interface to stop the VM.

---

##  Task 3: Careers in Cyber Security

This section explains various roles within offensive security:

- **Penetration Tester** – Finds and exploits security vulnerabilities.  
- **Red Teamer** – Simulates real-world attacks to test security defenses.  
- **Security Engineer** – Designs and maintains systems and controls to prevent cyberattacks.

No answers are required—just read and proceed.

---

##  Summary Table of Commands & Steps

| Step | Action | Command / Note |
|------|--------|----------------|
| 1 | Start the VM | Click **Start Machine** |
| 2 | Open terminal | Click terminal icon on right pane |
| 3 | Run Gobuster | `gobuster -u http://fakebank.thm -w wordlist.txt dir` |
| 4 | Discover hidden page | Look for `/bank-transfer` |
| 5 | Perform transfer | Navigate to `/bank-transfer`, send $2000 from `2276` → `8881` |
| 6 | Capture flag | Look for “BANK-HACKED” message on account page |
| 7 | Terminate VM | Click **Terminate** button |

---

##  Final Thoughts

This room is an excellent hands-on introduction to ethical hacking. You'll learn:

- Why thinking like a hacker (Offensive Security) is vital  
- How to use **Gobuster** for web directory discovery  
- The real-world impact of unsecured admin portals

---

###  Tips

- Always read the task instructions carefully—understanding why something is done is as important as knowing how.  
- Practice with the command line often—it builds fluency with tools like Gobuster.  
- After completing, try more TryHackMe rooms to explore other facets of cybersecurity.

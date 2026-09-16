# Operation Slither

**Room Type:** OSINT / SOCMINT  
**Objective:** Identify members of the Sneaky Viper group by following publicly leaked intelligence across platforms.

---

## Task 1 - The Leader

### 📌 Given Information

We are provided with a hacker forum post advertising leaked company data. The only actionable intelligence in the post is a username:

```
@v3n0mbyt3_
```

This suggests a username-based OSINT investigation.

### Step 1 - Broad Username Enumeration

**What we did**

We searched the username across common social platforms using:
- Google search
- Username search engines
- Manual platform lookups

Example queries:
- `v3n0mbyt3_ social media`
- `"v3n0mbyt3_" profile`

**Why**

Attackers often reuse the same handle across platforms. The goal was to identify where the user is active, not just where the account exists.

### Step 2 - Platform Correlation

**What we found**

The username appeared on multiple platforms, but one platform showed:
- Recent activity
- Casual posts
- Replies and conversations

This platform was **Threads**, in addition to Twitter/X.

### ✅ Task 1 - Question 1

> Aside from Twitter / X, what other platform is used by v3n0mbyt3_?

**Answer:**
```
threads
```

### Step 3 - Threads Profile Analysis

**What we did**

On the Threads profile we carefully reviewed:
- Posts
- Replies
- Comment sections
- Conversations with other users

**Why**

Sensitive data is often leaked in comments and replies, not main posts.

### Step 4 - Suspicious Content Discovery

Inside a comment thread involving another user, we observed:
- A long, random-looking string
- High entropy
- Characters consistent with Base64 encoding

Example pattern:
```
VEhNe3...
```

### Step 5 - Decoding the Data

**What we did**

We tested the string using a Base64 decoder (CyberChef / online decoder).

**Result**

The decoded output revealed a valid TryHackMe flag format.

### ✅ Task 1 - Question 2

> What is the value of the flag?

**Answer:**
```
THM{sl1th3ry_tw33tz_4nd_l34ky_<REDACTED>}
```

---

## Task 2 - The Sidekick

### 📌 Given Information

A second forum post appears, but the operator handle is hidden. The task explicitly hints to use information from Task 1.

### 🔍 Step 1 - Social Graph Pivot

**What we did**

Instead of starting fresh, we reviewed the Threads conversation from Task 1.

We identified a recurring user who:
- Directly interacted with v3n0mbyt3_
- Spoke as an insider
- Referred to shared operations

This strongly suggested a second operator.

### ✅ Task 2 - Question 1

> What is the username of the second operator talking to v3n0mbyt3 from the previous platform?

**Answer:**
```
_myst1cv1x3n_
```

### Step 2 - Username Enumeration (Second Operator)

**What we did**

We searched `_myst1cv1x3n_` across platforms.

**Result:**

An active Instagram profile using the same handle.

### Step 3 - Instagram Profile Analysis

**What we checked**
- Bio
- Captions
- Comments
- External links

We noticed:
- A comment containing an encoded string claiming to be a flag
- A link to an external SoundCloud profile

### Step 4 - Decoy Flag Identification

**Why it was suspicious**
- The encoded string was too obvious
- Placed directly under a comment saying "Flag is here"
- Did not require any pivoting

This strongly suggested a **decoy**.

### Step 5 - External Platform Pivot (SoundCloud)

**What we did**

We followed the SoundCloud link from the Instagram bio.

We found:
- A profile with 4 audio tracks

### Step 6 - Full Asset Enumeration

**What we checked**

For each track:
- Description
- Comments
- Metadata

**Why**

Real flags are often hidden deeper than the first asset.

### Step 7 - Real Flag Discovery

Inside the description of **Prototype2**, we found:
- A Base64-encoded string
- Embedded naturally inside descriptive text

Decoding revealed the real flag.

### ✅ Task 2 - Question 2

> What is the value of the flag?

**Answer:**
```
THM{s0cm1nt_00ps3c_f1ng3r_<REDACTED>}
```

---

## Task 3 - The Last Operator

### 📌 Given Information

A new post advertises advanced phishing infrastructure, mentioning:
- Terraform
- Evilginx
- GoPhish
- MFA bypass
- Red-team tooling

This strongly indicates a technical / infrastructure-focused operator.

### Step 1 - Technical Platform Pivot

**What we did**

We searched for usernames and aliases connected to:
- Phishing frameworks
- Terraform repositories
- Red-team infrastructure

This led us to a GitHub profile linked to the operation.

### ✅ Task 3 - Question 1

> What is the handle of the third operator?

**Answer:**
```
sh4d<REDACTED>
```

### Step 2 - Platform Identification

**What we observed**

The operator was active on GitHub, hosting multiple repositories related to phishing infrastructure.

### ✅ Task 3 - Question 2

> What other platform does the third operator use?

**Answer:**
```
github
```

### Step 3 - Repository Analysis

**What we did**

We focused on the original repository, not forks.

Key actions:
- Reviewed commit history
- Inspected infrastructure files

### Step 4 - Critical OPSEC Failure

Inside commit history, we found a committed file:
```
terraform.tfstate
```

Terraform state files often contain:
- Secrets
- Passwords
- Output variables

### Step 5 - Secret Extraction

Inside the state file outputs, we discovered:
- A Base64-encoded value labeled as a password

Decoding revealed the final flag.

### ✅ Task 3 - Question 3

> What is the value of the flag?

**Answer:**
```
THM{sh4rp_f4ngz_l34k3d<REDACTED>}
```

---

## 🏁 Final Summary

This room was completed by chaining:
- Username OSINT
- Social interaction analysis
- External media pivoting
- Decoy detection
- Developer platform investigation
- Infrastructure artifact analysis

Each step relied on publicly available intelligence and logical pivots, mirroring real-world SOCMINT investigations.

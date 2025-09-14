## Room : https://tryhackme.com/room/cryptofailures
## Summary / Vulnerability in one line
The application builds a `secure_cookie` by applying PHP's `crypt()` (DES variant) to **8-byte chunks** of the string `user:USER_AGENT:ENC_SECRET_KEY`, concatenating the outputs. Because DES `crypt()` operates on 8-byte blocks with a short (2-character) salt, you can align attacker-controlled bytes (via `User-Agent`) so that a single unknown byte of the `ENC_SECRET_KEY` is isolated in one 8-byte block and brute-forced by comparing `crypt()` outputs. Once the ENC key is recovered, forge a `secure_cookie` for `user=admin` and read the web flag.

---

## Environment & prerequisites
- TryHackMe attacking VM (or local Linux box)
- Network access to the target (replace `10.10.122.185` with your box IP)
- Tools installed:
  - `php-cli` and `php-curl`
  - `curl`
  - `awk`, `sed`, `tr`, `grep`
  - `nano`/`vim` (optional)

Install (Debian/Ubuntu):

```bash
sudo apt update
sudo apt install -y php-cli php-curl curl
```

---

## Recon — inspect the target and cookies
First, request the web root and inspect `Set-Cookie` headers:

```bash
curl -s -D - -A 'testUA' http://10.10.122.185/ -o /dev/null | grep -i '^Set-Cookie'
```

You should see at least two cookies:
- `user` (defaults to `guest` on the target)
- `secure_cookie` (a concatenation of `crypt()` outputs; the first two characters represent the 2-char salt)

Extract the `secure_cookie` string and the salt (first two characters):

```bash
SEC=$(curl -s -D - -A 'testUA' http://10.10.122.185/ -o /dev/null \
      | awk -F'Set-Cookie: ' '/secure_cookie/ {print $2}' \
      | sed 's/;.*//' | tr -d '\r\n')

echo "secure_cookie from server: $SEC"

# first two chars are salt
SALT=${SEC:0:2}
echo "detected salt: $SALT"
```

> **Note:** Some servers URL-encode cookie values in the header (you may see `%2F` etc.). Work with the raw cookie string returned above for extracting salt.

---

## Recovering `ENC_SECRET_KEY` (automation)

**Concept:** craft `User-Agent` strings with lengths that align the unknown bytes of `ENC_SECRET_KEY` into a single 8-byte block within the plaintext `user:USER_AGENT:ENC_SECRET_KEY`. For each alignment, try all printable characters and compare the single-block `crypt()` output with the corresponding substring in `secure_cookie` until you find a match. Iterate byte-by-byte.

Below is a ready-to-run PHP script (save as `recover_key.php`). It is derived from the approach used in public writeups and tailored for this room. **It does not contain any flags** — run it against the target to recover the ENC key.

```php
<?php
// recover_key.php
// USAGE: edit $url and $start_len then run: php recover_key.php

$url = "http://10.10.122.185/";   // <-- target
$start_len = 176;                   // adjust if needed (multiple of 8 start)

// candidate plaintext characters (printable ASCII)
$payload = " !\"#\$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~";
$parts_payload = str_split($payload,1);

function get_cookie_from_url($url, $user_agent){
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HEADER, true);
    curl_setopt($ch, CURLOPT_NOBODY, true);
    curl_setopt($ch, CURLOPT_USERAGENT, $user_agent);
    $response = curl_exec($ch);
    if ($response === false) {
        fwrite(STDERR, "curl error: " . curl_error($ch) . "\n");
        curl_close($ch);
        return null;
    }
    curl_close($ch);
    preg_match_all('/^Set-Cookie:\s*(.*)$/mi', $response, $matches);
    $cookie_array = [];
    if (!empty($matches[1])) {
        foreach ($matches[1] as $cookie) {
            $cookieParts = explode('=', $cookie, 2);
            $cookieValue = explode(';', $cookieParts[1])[0];
            $cookie_array[trim($cookieParts[0])] = trim($cookieValue);
        }
    }
    return $cookie_array;
}

$ENC_SECRET_KEY = "";
for ($i = $start_len; $i > 0; $i--) {
    if (substr($ENC_SECRET_KEY, -1) == "}") {
        break;
    }

    $user_agent = str_repeat("i", $i);
    $cookie_array = get_cookie_from_url($url, $user_agent);
    if (!$cookie_array) { fwrite(STDERR, "No cookie returned for UA length $i\n"); continue; }

    if (!isset($cookie_array['secure_cookie']) || !isset($cookie_array['user'])) {
        fwrite(STDERR, "secure_cookie or user cookie not found for UA length $i\n");
        continue;
    }

    $s_cookie = urldecode($cookie_array['secure_cookie']);
    $username = $cookie_array['user'];
    $c_string = $username . ":" . $user_agent . ":" . $ENC_SECRET_KEY;
    $c_octet_len = count(str_split($c_string,8));
    $parts_of_scookie = str_split($s_cookie,13);
    $hash = substr($s_cookie, 0, 2);

    if (strlen($c_string) % 8 == 7) {
        $last7 = substr($c_string, -7);
    } else {
        $last7 = substr($c_string, -7);
    }

    $found = false;
    foreach ($parts_payload as $p) {
        $trial = crypt($last7 . $p, $hash);
        if ($parts_of_scookie[$c_octet_len - 1] === $trial) {
            echo "Found next character: '$p' (UA length $i)\n";
            $ENC_SECRET_KEY .= $p;
            $found = true;
            break;
        }
    }
}

echo "\nRecovered ENC_SECRET_KEY (partial/complete): " . $ENC_SECRET_KEY . "\n";
?>
```

**Run:**

```bash
php recover_key.php
```

**Notes:**
- If the script doesn't find characters, adjust `$start_len` (increase or decrease) and re-run.
- The script uses printable ASCII as a candidate set; if the key contains non-printables, expand the payload accordingly.

---

## Forging an admin cookie (once ENC key is known)

**Goal:** Build `secure_cookie` for `user=admin` that matches the server's verification, then visit the site as `admin` to reveal the web flag.

**Steps**

1. Choose an 8-character User-Agent (we use `AAAAAAAA` in examples). It must match in both the cookie-building step and the final request.

2. Extract the server salt from a real cookie (see Recon section). Use it to compute `crypt()` outputs.

3. Build the plaintext input used by the server for cookie generation:

```bash
UA='AAAAAAAA'
ENC_KEY='REPLACE_WITH_YOUR_RECOVERED_KEY'
TEXT="admin:${UA}:${ENC_KEY}"
```

4. Generate the forged `secure_cookie` using the server salt (example code uses the salt previously extracted into `$SALT`):

```bash
export TEXT SALT
FORGED=$(php -r '
$text = getenv("TEXT");
$salt = getenv("SALT");
$cookie = "";
foreach (str_split($text, 8) as $el) {
    $cookie .= crypt($el, $salt);
}
echo $cookie;
')

echo "forged secure_cookie: $FORGED"
```

5. Send a request as `admin` with the forged cookie and the same UA:

```bash
curl -s -A "$UA" -H "Cookie: user=admin; secure_cookie=${FORGED}" http://10.10.122.185/ | sed -n '1,200p'
```

**Expected:** The site should respond with a successful page that contains the web flag (masked in this writeup). Example (masked):

```
congrats: THM{ok_you_f0und_w3b_fl4g_********}. Now I want the key.
```

> **Important:** If the server regenerates a new salt on each request, ensure you **fetch the cookie / salt immediately before** forging and reuse that same salt to compute the forged cookie.

---

## Submission formats (how TryHackMe expects you to submit)
- **What is the value of the web flag?**
  - Format: `THM{**_***_*****_***_****_*******}`  
  - Example (masked): `THM{ok_you_f0und_w3b_fl4g_********}`

- **What is the encryption key?**
  - Format: `THM{...}` (longer).  
  - Example (masked): `THM{Tradit*****_Own_Cryp*****_..._********}`

> **Do not paste full flags in public or shared writeups.** When sharing, mask most of the flag as shown above.

---

## Troubleshooting & common pitfalls
- **`You are not logged in` after forging**
  - Ensure you used the exact same UA when generating the forged cookie and when sending the request.
  - Ensure `$SALT` matches the server's cookie salt (first two characters of the `secure_cookie` the server issued).
  - Check whether the server URL-encodes the cookie value — if so, URL-encode your forged cookie before sending.
  - Confirm `ENC_KEY` is exact and contains no trailing newlines or extra quotes.

- **`crypt()` variant mismatch**
  - The writeup targets DES `crypt()`; if the target uses a different `crypt()` variant (rare here), the output lengths/format differ. Adjust parsing split sizes accordingly.

- **Timing / rate limits**
  - Brute-force loops may be slow. If the server rate-limits, slow down the loop or run the script from a place that avoids triggering rate limits.

---

## Appendix — Quick commands reference

```bash
# show Set-Cookie headers
curl -s -D - -A 'testUA' http://10.10.122.185/ -o /dev/null | grep -i '^Set-Cookie'

# extract server secure_cookie and salt
SEC=$(curl -s -D - -A 'testUA' http://10.10.122.185/ -o /dev/null \
      | awk -F'Set-Cookie: ' '/secure_cookie/ {print $2}' \
      | sed 's/;.*//' | tr -d '\r\n')
SALT=${SEC:0:2}

# run the key recovery script
php recover_key.php

# generate forged cookie (after setting TEXT and SALT)
export TEXT SALT
php -r '
$text = getenv("TEXT");
$salt = getenv("SALT");
$cookie = "";
foreach (str_split($text, 8) as $el) { $cookie .= crypt($el, $salt); }
echo $cookie;
'

# final request with forged cookie
curl -s -A "AAAAAAAA" -H "Cookie: user=admin; secure_cookie=${FORGED}" http://10.10.122.185/ | sed -n '1,200p'
```

---

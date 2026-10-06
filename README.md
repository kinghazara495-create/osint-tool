# OSINT Toolkit

Two public-data OSINT tools and a password-strength checker, written in Python
with no API keys required.

Built as a learning project. Every module was tested against live targets, and
the bugs found during testing are documented here because they are the more
useful part of the story.

---

## Tools

| Tool | What it does |
|---|---|
| `osint_email.py` | Assesses an email address: can the domain receive mail, is it protected against spoofing (SPF/DMARC), has the address appeared in a known breach |
| `osint_domain.py` | Assesses a domain: WHOIS registration data, full DNS record dump, subdomain enumeration, PTR reverse lookup, optional zone-transfer check, and a scored posture summary |
| `password_strength.py` | Password strength checker (see the caveat below) |

## Requirements

```bash
pip install dnspython requests
```

Python 3.11+.

## Usage

```bash
# Email assessment
python osint_email.py someone@example.com
python osint_email.py someone@example.com --json report.json
python osint_email.py --demo-secrets

# Domain assessment
python osint_domain.py example.com
python osint_domain.py example.com --subs
python osint_domain.py example.com --json domain.json

# Zone transfer check (authorized targets only)
python osint_domain.py example.com --axfr --i-own-this
```

---

## Authorised use

These tools read **public data only**: the DNS registry, the WHOIS registry, and
a privacy-preserving hash API. No credentials are handled, nothing is
exploited, and no data is sent to any server operated by the author.

Run them against domains and addresses you own, or ones you have explicit
written authorisation to assess.

Two flags generate real traffic against third-party infrastructure and are
therefore opt-in:

- `--subs` runs a subdomain dictionary lookup
- `--axfr` attempts a DNS zone transfer, which is an access attempt against a
  nameserver. It additionally requires `--i-own-this` so it can never fire by
  accident.

---

## Design notes

Three decisions in here matter more than the code, because each one fixes a
class of wrong answer rather than a single bug.

### 1. "We failed to ask" is not "the answer is no"

Every lookup returns a status alongside its values: `found`, `nxdomain`,
`no-answer`, `timeout`, or `error`. A timeout is never collapsed into "no record
exists". That distinction is the difference between a tool that reports GitHub
as spoofable when it is not, and one that does not.

This was a real bug. `osint_domain.py` originally reported **zero findings** for
a domain that refuses all inbound mail, because it treated "an MX record exists"
as proof that mail works. That is exactly inverted for a **Null MX** (RFC 7505),
where the record's entire purpose is to tell the internet to stop delivering
mail to that domain.

### 2. Your resolver is part of the tool

Measured on the development machine:

```
system resolver,  5s   FAIL  -> LifetimeTimeout
system resolver, 15s   FAIL  -> LifetimeTimeout
1.1.1.1,         15s   OK in 0.37s
8.8.8.8,         15s   OK in 0.42s
```

Some ISP resolvers handle large `TXT` responses badly. Since SPF and DKIM live in
`TXT` records, that makes the resolver a reliability decision, not a config
detail. Both tools try the system resolver first, then fall back to Cloudflare
and Google.

### 3. Data arrives chunked

DNS `TXT` records are returned as multiple quoted strings that must be rejoined
before parsing. GitHub's SPF record splits **in the middle of an IP address**:

```
"... ip4:62.253.2" "27.114 ip4:166.78.69.169 ..."
```

Naive string handling silently corrupts that into `62.253.2` + `27.114`. The
`.replace('"', "")` that rejoins the chunks is load-bearing, and this is the
test that proved it.

### Breach checks without leaking the email

The HIBP lookup uses the k-anonymity range API: SHA-1 the address locally,
transmit only the first 5 hex characters, and match the returned suffixes on
this machine. The service learns that *someone* hashed an email; with several
hundred candidates sharing your prefix, the address is not identifiable. The
full hash never leaves the machine.

### `secrets`, not `random`

`osint_email.py --demo-secrets` demonstrates why: `random.seed(1234)` makes a
sequence perfectly reproducible, while `secrets` is not seedable. Use `random`
for shuffling a playlist and `secrets` for anything an attacker benefits from
guessing.

---

## Known limitations

- **`password_strength.py` uses `input()`, which echoes the password to the
  screen and into shell history.** It should use `getpass.getpass()`. Its
  character-class scoring also follows older guidance rather than NIST
  SP 800-63B, and its top five labels ("Perfect", "Mastered", and above) are
  unreachable because the maximum achievable score is 5. Treat it as a
  demonstration of the problem, not as something to type real passwords into.
- **No reverse-IP lookup.** `osint_domain.py` does PTR (one hostname per IP),
  which needs no API key. Reverse IP (every domain on an IP) needs a paid
  provider, so it is omitted rather than faked.
- **Subdomain enumeration uses a ~70-word built-in list**, not a full
  wordlist. It finds common names only.
- **Rate limiting is per-run only.** There is no persistent throttle across
  runs, so repeated runs against one target will generate real traffic.
- **DKIM selector discovery is a fixed six-name list**, not bruteforced.

---

## Licence

MIT. See `LICENSE`.

The bundled code is original. Any real deployment needs a human review before
you point it at someone else's infrastructure.
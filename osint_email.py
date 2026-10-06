"""
osint_email.py - A small, honest OSINT tool for assessing an email address.

WHAT THIS IS
    Gathers ONLY publicly available data about an email address:
      - does the domain resolve, and can it receive mail (MX / A records)
      - is the domain protected against spoofing (SPF / DMARC)
      - has the address appeared in a known breach (HIBP)

    It never sends credentials anywhere, never opens a webhook, and never
    sends your full email address to a third party.

USAGE
    python osint_email.py you@example.com
    python osint_email.py you@example.com --json report.json

TEACHING NOTES are inline as numbered steps. Read them, then delete the comments
once you understand each part and can rebuild it yourself.
"""

# ── STEP 1: IMPORTS ────────────────────────────────────────────────────────
# Standard library first. "hashlib" hashes, "secrets" generates random values
# that are safe for security use, "json" writes the report, "re" does pattern
# matching, "sys" handles command-line arguments.
#
# "dns.resolver" is dnspython: it asks a DNS server questions like "what are
# this domain's MX records?". Python's built-in socket module can get an IP
# address but CANNOT get MX/TXT records, which is why we need this package.
#
# "requests" does HTTPS calls to the HIBP API.
import argparse
import hashlib
import json
import re
import secrets  # noqa: F401  (used in the bonus section below)
import sys

import dns.resolver
import requests

# ── STEP 2: EMAIL FORMAT VALIDATION ───────────────────────────────────────
# A deliberately simple regex. The goal is NOT perfect RFC 5322 compliance
# (which is famously impossible). The goal is to catch obvious typos before we
# waste a DNS lookup on nonsense.
#
# Break it down:
#   [^@\s]+      one or more characters that are NOT "@" or whitespace
#   @            literal @
#   [^@\s]+      domain part, same rule
#   \.[a-z]{2,}  a dot then 2+ letters (top-level domain)
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[a-zA-Z]{2,}$")


def is_valid_shape(email: str) -> bool:
    """Step 2. Cheap check before spending a network round-trip."""
    return bool(EMAIL_RE.match(email.strip()))


# ── STEP 3: SAFE DNS LOOKUP ────────────────────────────────────────────────
# This is the most important function in the file. Real DNS queries fail in
# several DIFFERENT ways, and each failure means something different:
#
#   NXDOMAIN  -> the domain does not exist at all (typo, or dead domain)
#   NoAnswer -> the domain exists but has NO record of that type
#               (e.g. no MX record, which is itself a finding)
#   Timeout   -> network problem, not a finding about the domain
#   NoNameservers -> dnspython config problem, not a finding
#
# A good tool must NOT report "no MX record" and "the internet is down" the
# same way. Collapsing those is how OSINT tools end up crying wolf.
#
# dns.resolver.NXDOMAIN and dns.resolver.NoAnswer are both subclasses of
# dns.resolver.DNSException, so we catch the specific ones first, then the
# general one as a backstop.
def dns_lookup(name: str, record_type: str, attempts: int = 2) -> tuple[list[str], str]:
    """Return (values, status) where status is one of:
       found | nxdomain | no-answer | timeout | error

    TWO HARD-WON LESSONS ARE ENCODED HERE.

    LESSON 1 - retries. TXT records (where SPF and DMARC live) are often long and
    slow. A single 5-second timeout on a busy resolver produces a false
    "missing" finding. "We failed to ask" and "the answer is no" are completely
    different claims, and only the second one is a finding.

    LESSON 2 - resolver fallback. Measured on this machine: the system resolver
    timed out on github.com TXT at 5s AND at 15s, while 1.1.1.1 answered in
    0.37s. Some ISP resolvers handle large TXT responses badly. So we try the
    system resolver first, then fall back to public resolvers. A hardcoded
    "nameserver" is not a detail, it is a reliability decision.
    """
    # (label, nameservers or None for system)
    strategies = [
        ("system", None),
        ("cloudflare", ["1.1.1.1"]),
        ("google", ["8.8.8.8"]),
    ]

    definitive = {"nxdomain", "no-answer"}
    last_status = "error: not attempted"

    for label, nameservers in strategies:
        for attempt in range(1, attempts + 1):
            resolver = dns.resolver.Resolver()
            if nameservers:
                resolver.nameservers = nameservers
            resolver.timeout = 5
            resolver.lifetime = 5
            try:
                answers = resolver.resolve(name, record_type)
                return [str(rdata).strip() for rdata in answers], "found"
            except dns.resolver.NXDOMAIN:
                # Definitive. The name does not exist. No resolver will disagree.
                return [], "nxdomain"
            except dns.resolver.NoAnswer:
                # Also definitive: name exists, no record of this type.
                return [], "no-answer"
            except dns.resolver.Timeout:
                last_status = f"timeout (last resolver tried: {label})"
                continue          # transient -> retry this resolver
            except dns.resolver.DNSException as exc:
                last_status = f"error: {type(exc).__name__} ({label})"
                break             # config problem -> next resolver
    return [], last_status


# ── STEP 3b: MX LOOKUP THAT UNDERSTANDS "NULL MX" ─────────────────────────
# BUG FOUND WHILE TESTING THIS TOOL, and it is worth understanding.
#
# The first version asked for MX records and reported "can receive mail: True"
# whenever ANY record came back. Testing against example.com produced:
#
#     MX (found): 0 .
#     can receive mail : True        <-- WRONG, and confidently wrong
#
# "0 ." is a NULL MX (RFC 7505). Preference 0 with the exchange set to the DNS
# root "." means: "this domain accepts NO mail, ever." It is how you tell the
# internet not to deliver mail to a domain at all.
#
# So the naive rule "MX exists therefore mail works" is exactly inverted for the
# null case. Three real outcomes exist, not two:
#
#     no MX record at all   -> default behaviour; mail MAY be delivered to an A
#                              record if that address exists (implicit MX)
#     normal MX records     -> mail is delivered to those exchangers
#     null MX "0 ."         -> mail is REFUSED. The strongest "no" there is.
#
# The fix is to keep the structured MX objects (which dnspython gives us with
# .preference and .exchange) instead of flattening them to strings, because the
# distinction lives in those fields.
def dns_lookup_mx(domain: str) -> dict:
    """Interpret MX records correctly, including the null MX case."""
    records_raw, status = dns_lookup_mx_raw(domain)
    if status != "found":
        return {
            "status": status,
            "null_mx": False,
            "records": [],
            "can_receive_mail": False if status in ("nxdomain", "no-answer") else None,
            "explanation": {
                "nxdomain": "domain does not exist",
                "no-answer": "no MX record and no A record, so mail cannot be delivered",
            }.get(status, f"DNS {status}; this is NOT a finding about the domain"),
        }

    # Re-query structurally. The string form is for display; the null-MX test
    # needs the real .preference and .exchange fields.
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5
    for ns in (None, ["1.1.1.1"], ["8.8.8.8"]):
        r = dns.resolver.Resolver()
        if ns:
            r.nameservers = ns
        r.timeout = 5
        r.lifetime = 5
        try:
            answers = r.resolve(domain, "MX")
            break
        except dns.resolver.DNSException:
            answers = None
    if answers is None:
        return {"status": "error", "null_mx": False, "records": records_raw,
                "can_receive_mail": None, "explanation": "could not read MX structure"}

    records = [f"{a.preference} {str(a.exchange).rstrip('.')}" for a in answers]
    is_null = all(a.preference == 0 and str(a.exchange).strip() == "." for a in answers)

    if is_null:
        return {"status": "found", "null_mx": True, "records": records,
                "can_receive_mail": False,
                "explanation": ("NULL MX (RFC 7505): this domain explicitly "
                                "refuses all inbound mail")}

    # No null MX, but the implicit-MX case still needs the A record.
    a_recs, _ = dns_lookup(domain, "A")
    return {"status": "found", "null_mx": False, "records": records,
            "can_receive_mail": True,
            "explanation": f"normal MX, {len(records)} exchanger(s)"}


def dns_lookup_mx_raw(domain: str) -> tuple[list[str], str]:
    """Plain MX fetch that keeps dnspython's structured objects intact."""
    strategies = [None, ["1.1.1.1"], ["8.8.8.8"]]
    last = "error: not attempted"
    for ns in strategies:
        r = dns.resolver.Resolver()
        if ns:
            r.nameservers = ns
        r.timeout = 5
        r.lifetime = 5
        try:
            answers = r.resolve(domain, "MX")
            return [f"{a.preference} {str(a.exchange).rstrip('.')}" for a in answers], "found"
        except dns.resolver.NXDOMAIN:
            return [], "nxdomain"
        except dns.resolver.NoAnswer:
            return [], "no-answer"
        except dns.resolver.Timeout:
            last = "timeout"
        except dns.resolver.DNSException as exc:
            last = f"error: {type(exc).__name__}"
    return [], last
# ── STEP 4: SPF ANALYSIS ───────────────────────────────────────────────────
# SPF (Sender Policy Framework) lives in a TXT record on the ROOT domain and
# declares which servers are allowed to send email as this domain.
#
# It looks like:  v=spf1 include:_spf.google.com ip4:1.2.3.4 ~all
#                                                          ^^^^^
# The "all" mechanism at the end is the security decision:
#
#   -all   (hardfail)  strict: anything else is rejected. GOOD.
#   ~all   (softfail)  lenient: mark as suspicious but allow. COMMON.
#   +all   (pass all)  "anyone anywhere may send as this domain". DANGEROUS,
#                     and a real finding if you see it.
#   ?all   (neutral)   no policy stated. WEAK.
#
# A domain with NO spf record at all is spoofable, because nothing constrains
# who can send as it.
def analyse_spf(domain: str) -> dict:
    txt, status = dns_lookup(domain, "TXT")
    if status != "found":
        return {
            "record": None,
            "status": status,
            "verdict": "UNKNOWN (could not read TXT records)",
            "all_mechanism": None,
        }

    spf_line = None
    for record in txt:
        # A TXT record can be split into several quoted chunks. Rejoin before
        # searching, or "v=spf1 " can be chopped in half.
        joined = record.replace('"', "")
        if "v=spf1" in joined:
            spf_line = joined
            break

    if spf_line is None:
        return {
            "record": None,
            "status": "no spf record",
            "verdict": "MISSING - this domain can be spoofed",
            "all_mechanism": None,
        }

    # Pull out the "all" mechanism, which is the part that carries policy.
    # A small all() guard keeps this from raising on a malformed record.
    all_mech = None
    for token in spf_line.split():
        if token in ("-all", "~all", "+all", "?all"):
            all_mech = token
            break

    if all_mech == "+all":
        verdict = "DANGEROUS (+all allows anyone to send as this domain)"
    elif all_mech == "-all":
        verdict = "STRICT (-all rejects unknown senders)"
    elif all_mech == "~all":
        verdict = "LENIENT (~all marks unknown senders suspicious but allows)"
    elif all_mech == "?all":
        verdict = "WEAK (?all states no policy)"
    else:
        verdict = f"present, no explicit 'all' mechanism found ({spf_line[:80]})"

    return {
        "record": spf_line,
        "status": "found",
        "verdict": verdict,
        "all_mechanism": all_mech,
    }


# ── STEP 5: DMARC ANALYSIS ─────────────────────────────────────────────────
# DMARC is a TXT record on a SUBDOMAIN: _dmarc.example.com
# It tells receiving mail servers what to DO when SPF or DKIM fails.
# The p= tag is the policy:
#   p=none        monitor only, no action. Very common.
#   p=quarantine  send to spam. Better.
#   p=reject      refuse it. Strongest.
def analyse_dmarc(domain: str) -> dict:
    txt, status = dns_lookup(f"_dmarc.{domain}", "TXT")
    if status in ("nxdomain", "no-answer"):
        return {"record": None, "status": "missing", "policy": None,
                "verdict": "MISSING - no DMARC policy published"}
    if status != "found":
        return {"record": None, "status": status, "policy": None,
                "verdict": f"UNKNOWN ({status})"}

    record = None
    for r in txt:
        joined = r.replace('"', "")
        if "v=DMARC1" in joined:
            record = joined
            break

    if record is None:
        return {"record": None, "status": "no dmarc record", "policy": None,
                "verdict": "MISSING - no DMARC policy published"}

    policy = None
    for token in record.split(";"):
        token = token.strip()
        if token.startswith("p="):
            policy = token[2:].strip()
            break

    return {
        "record": record,
        "status": "found",
        "policy": policy,
        "verdict": {
            "reject": "STRONG (p=reject refuses failing mail)",
            "quarantine": "GOOD (p=quarantine spams failing mail)",
            "none": "MONITOR ONLY (p=none takes no action)",
        }.get(policy, f"unrecognised policy: {policy}"),
    }


# ── STEP 6: BREACH CHECK VIA K-ANONYMITY ──────────────────────────────────
# This is the part most OSINT tools get wrong, so read it slowly.
#
# Naive approach: upload the email to the breach service and ask "is it
# breached?" That hands a stranger your email address. Bad.
#
# K-anonymity approach: SHA-1 the email yourself, send only the FIRST 5
# characters of that hash. The service returns every hash suffix starting with
# those 5 characters (about 800 of them). You do the matching LOCALLY.
#
#   email:  abdulsamad@example.com
#   sha1:   5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
#   send:   5BAA6                <- 5 hex chars out of 40
#   receive: ~800 suffixes
#   compare locally -> exact match means breached
#
# The service learns only that SOMEONE hashed an email. With ~800 candidates
# sharing your prefix, your email is not identifiable. This is exactly how
# Firefox Monitor and Have I Been Pwned work.
#
# Uses stdlib hashlib, so nothing about the email leaves this machine except
# 5 characters of an irreversible hash.
HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/{}"


def check_breaches(email: str) -> dict:
    email = email.strip().lower()
    sha1 = hashlib.sha1(email.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    try:
        resp = requests.get(
            HIBP_RANGE_URL.format(prefix),
            headers={"User-Agent": "osint-email-learning-tool"},
            timeout=15,
        )
    except requests.RequestException as exc:
        return {"status": f"network error: {type(exc).__name__}", "count": 0,
                "sources": [], "privacy": "full email never left this machine"}

    if resp.status_code == 404:
        return {"status": "no breach records for this hash prefix", "count": 0,
                "sources": [], "privacy": "full email never left this machine"}
    if resp.status_code != 200:
        return {"status": f"HTTP {resp.status_code}", "count": 0, "sources": [],
                "privacy": "full email never left this machine"}

    # Each line is "SUFFIX:COUNT". Compare suffixes case-insensitively.
    count, sources = 0, []
    for line in resp.text.splitlines():
        if ":" not in line:
            continue
        candidate, _, times = line.partition(":")
        if candidate.strip().upper() == suffix:
            count = int(times.strip() or 0)
            # HIBP names breaches in a separate API; the range endpoint gives us
            # the count, which is the privacy-preserving part. Naming the source
            # needs the paid / authenticated endpoint, so we stop here on purpose.
            sources = ["see haveibeenpwned.com for the breach names"]

    return {
        "status": "found" if count else "not found in HIBP",
        "count": count,
        "sources": sources,
        "privacy": "only 5 chars of a SHA-1 hash were transmitted",
    }


# ── STEP 7: BONUS - WHY secrets, NOT random ───────────────────────────────
# If you ever add a captcha or a token to this tool, generate it with
# "secrets", never with "random".
#
#   random.random()  -> Mersenne Twister. Given 624 outputs you can predict
#                       every future value. Fine for shuffling a playlist.
#   secrets.token_hex(16) -> a cryptographically secure CSPRNG. Correct choice
#                       for anything an attacker benefits from guessing.
#
# Run this to see it yourself:
def demo_random_vs_secrets() -> None:
    import random
    random.seed(1234)
    leaked = [random.randint(0, 2**32) for _ in range(5)]
    random.seed(1234)
    replayed = [random.randint(0, 2**32) for _ in range(5)]
    print("  random with a known seed is fully predictable:")
    print(f"    first run  : {leaked}")
    print(f"    replayed   : {replayed}")
    print(f"    identical? {leaked == replayed}")
    print(f"  secrets is not seedable, so it cannot be replayed.")


# ── STEP 8: REPORT ─────────────────────────────────────────────────────────
def build_report(email: str) -> dict:
    email = email.strip()
    domain = email.split("@", 1)[1] if "@" in email else ""

    if not is_valid_shape(email):
        return {"email": email, "error": "does not look like an email address"}
    if not domain:
        return {"email": email, "error": "no domain part"}

    mx_info = dns_lookup_mx(domain)
    a, a_status = dns_lookup(domain, "A")

    return {
        "email": email,
        "domain": domain,
        "shape_valid": True,
        "dns": {
            "mx": mx_info,
            "a_status": a_status,
            "a": a,
        },
        "spf": analyse_spf(domain),
        "dmarc": analyse_dmarc(domain),
        "breach": check_breaches(email),
        "scope_note": "public data only; no credentials handled or transmitted",
    }


def print_report(rep: dict) -> None:
    if "error" in rep:
        print(f"ERROR: {rep['error']}")
        return

    print("=" * 66)
    print(f"OSINT EMAIL REPORT  -  {rep['domain']}")
    print("=" * 66)

    dnsr = rep["dns"]
    mx = dnsr["mx"]
    print("\n[1] DNS")
    print(f"    MX status : {mx['status']}"
          f"{'   *** NULL MX ***' if mx['null_mx'] else ''}")
    print(f"    MX records: {', '.join(mx['records'][:4]) or 'none'}")
    print(f"    verdict   : {mx['explanation']}")
    print(f"    can receive mail : {mx['can_receive_mail']}")
    print(f"    A  ({dnsr['a_status']}): {', '.join(dnsr['a'][:4]) or 'none'}")

    print("\n[2] SPF  (who may send as this domain)")
    print(f"    status : {rep['spf']['status']}")
    print(f"    verdict: {rep['spf']['verdict']}")
    if rep["spf"]["record"]:
        print(f"    record : {rep['spf']['record'][:120]}")

    print("\n[3] DMARC  (what to do when SPF fails)")
    print(f"    status : {rep['dmarc']['status']}")
    print(f"    policy : {rep['dmarc']['policy']}")
    print(f"    verdict: {rep['dmarc']['verdict']}")

    b = rep["breach"]
    print("\n[4] BREACH EXPOSURE")
    print(f"    status : {b['status']}")
    print(f"    times seen : {b['count']}")
    print(f"    privacy    : {b['privacy']}")

    print("\n[5] SCOPE")
    print(f"    {rep['scope_note']}")


# ── STEP 9: COMMAND LINE ───────────────────────────────────────────────────
def main() -> int:
    p = argparse.ArgumentParser(description="Public-data OSINT check for an email address.")
    p.add_argument("email", nargs="?", help="the address to assess")
    p.add_argument("--json", metavar="PATH", help="also write the full report as JSON")
    p.add_argument("--demo-secrets", action="store_true",
                   help="demonstrate why secrets beats random")
    args = p.parse_args()

    if args.demo_secrets:
        demo_random_vs_secrets()
        return 0

    if not args.email:
        p.print_help()
        return 1

    rep = build_report(args.email)
    print_report(rep)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(rep, fh, indent=2)
        print(f"\nJSON report written to {args.json}")

    return 0


if __name__ == "__main__":
    sys.exit(main())

"""
osint_domain.py - Public-data OSINT assessment of a domain.

WHAT THIS IS
    Five questions about a domain, asked using only public data:
      1. WHOIS - who registered it, when, until when
      2. DNS   - what records does it publish
      3. Subdomains - which common names resolve (dictionary attack on DNS)
      4. PTR   - what hostname does its IP point back to
      5. AXFR  - will the nameserver hand over its whole zone (misconfig check)

    No credentials, no exploitation. WHOIS and DNS are public registries.

AUTHORIZATION
    Run it against domains you own or are explicitly authorised to assess.
    Querying a WHOIS server and asking for DNS records is passive, but
    subdomain brute force generates real traffic, and the zone-transfer (AXFR)
    check is an access attempt against someone else's nameserver. Both are
    gated behind flags below for that reason.

USAGE
    python osint_domain.py example.com
    python osint_domain.py example.com --subs
    python osint_domain.py example.com --subs --axfr     # authorised targets only
    python osint_domain.py example.com --json out.json

TEACHING NOTES are inline as numbered steps.
"""

import argparse
import json
import re
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

import dns.query
import dns.resolver
import dns.zone

# ── STEP 1: WHOIS WITHOUT A LIBRARY ───────────────────────────────────────
# WHOIS is not HTTP. It is a bare TCP conversation on port 43:
#
#     client connects to whois.server:43
#     client sends "example.com\r\n"
#     server streams text back until it closes the connection
#
# There is no library needed, just a socket. Writing it by hand teaches the
# shape of the protocol and, more importantly, shows WHY you must first ask
# IANA which server is authoritative for a TLD. Querying whois.verisign-grs.com
# for a .com works, but querying it for a .io domain returns nothing useful,
# because .io has its own registry. IANA is the directory of directories.
#
# Port 43 is often firewalled on corporate and university networks. That is a
# network condition, not a finding about the domain, so we report it as such.
IANA_WHOIS = "whois.iana.org"

# Registry responses differ per TLD, so we look for keys whose MEANING is
# stable while ignoring exact labels. Registrars rebrand constantly.
#
# LESSON LEARNED THE HARD WAY: every leading \s* below is load-bearing.
# Real WHOIS output is INDENTED with three spaces:
#
#     "   Registrar: RESERVED-Internet Assigned Numbers Authority"
#     "   Creation Date: 1995-08-14T04:00:00Z"
#
# The first version of this parser used "^Registrar:" with no \s* and matched
# NOTHING on any field, while reporting no error at all. A silent parser that
# extracts nothing is indistinguishable from a domain that has no data, which
# is the worst kind of bug in a reporting tool.
#
# Note "Registrar WHOIS Server:" also begins with "Registrar", so every pattern
# must require the colon IMMEDIATELY after the label or we capture the wrong
# field.
WHOIS_FIELDS = {
    "registrar": [r"^\s*Registrar:\s*(.+)$"],
    "created": [r"^\s*Creation Date:\s*(.+)$", r"^\s*Created(?: on)?:\s*(.+)$",
                r"^\s*Registered on:\s*(.+)$",
                r"^\s*Domain Registration Date:\s*(.+)$"],
    "updated": [r"^\s*Updated Date:\s*(.+)$", r"^\s*Last updated?:\s*(.+)$",
                r"^\s*Last Modified:\s*(.+)$"],
    "expires": [r"^\s*(?:Registry Expiry|Expiration|Expiry) Date:\s*(.+)$",
                r"^\s*Expires(?: on)?:\s*(.+)$"],
    "registrant_country": [r"^\s*Registrant Country:\s*(.+)$"],
    "nameservers": [r"^\s*Name Server:\s*(.+)$", r"^\s*Nserver:\s*(.+)$"],
    "dnssec": [r"^\s*dnssec:\s*(.+)$"],
    "status": [r"^\s*Domain Status:\s*(.+)$"],
}


def whois_raw(server: str, query: str, timeout: int = 12) -> str:
    """Talk the port-43 protocol directly. Returns raw text, or raises."""
    with socket.create_connection((server, 43), timeout=timeout) as sock:
        sock.sendall((query + "\r\n").encode("utf-8", errors="replace"))
        chunks = []
        while True:
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data)
    return b"".join(chunks).decode("utf-8", errors="replace")


def find_authoritative_whois(tld: str) -> str | None:
    """Ask IANA which whois server owns this TLD."""
    try:
        text = whois_raw(IANA_WHOIS, tld, timeout=10)
    except (socket.timeout, OSError):
        return None
    match = re.search(r"^whois:\s*(\S+)", text, re.M | re.I)
    return match.group(1) if match else None


def whois_lookup(domain: str) -> dict:
    """Two-step: IANA referral, then the authoritative server."""
    tld = domain.rsplit(".", 1)[-1].lower()
    out = {"tld": tld, "server": None, "raw_available": False,
           "registrar": None, "created": None, "updated": None,
           "expires": None, "registrant_country": None,
           "nameservers": [], "dnssec": None, "status": [], "note": None}

    server = find_authoritative_whois(tld)
    if not server:
        out["note"] = ("could not reach IANA on port 43. This is a NETWORK "
                       "condition, not a finding about the domain.")
        return out
    out["server"] = server

    try:
        text = whois_raw(server, domain)
    except socket.timeout:
        out["note"] = "authoritative whois server timed out (network condition)"
        return out
    except OSError as exc:
        out["note"] = f"could not connect to {server}: {type(exc).__name__}"
        return out

    out["raw_available"] = True

    for key, patterns in WHOIS_FIELDS.items():
        for pattern in patterns:
            flags = re.M if key != "dnssec" else re.M | re.I
            m = re.search(pattern, text, flags)
            if not m:
                continue
            value = m.group(1).strip()
            if key in ("nameservers", "status"):
                out[key].append(value.lower().rstrip("."))
            else:
                out[key] = value
            break

    # A blank registrant field usually means privacy protection (GDPR, ICANN
    # 2018). That is a FINDING, not missing data.
    if not out["registrant_country"]:
        out["note"] = ("registrant country not published, which usually means "
                       "privacy protection (GDPR / ICANN 2018), not missing data")
    return out


# ── STEP 2: FULL DNS DUMP ─────────────────────────────────────────────────
# Reuses the resolver-fallback idea from osint_email.py, because the same trap
# applies: large TXT answers (SPF, DKIM selectors) time out on ISP resolvers.
RESOLVER_FALLBACK = [None, ["1.1.1.1"], ["8.8.8.8"]]


def resolve_with_fallback(name: str, rtype: str) -> tuple[list[str], str]:
    """Try each resolver in turn. Returns (values, status).

    Key distinction this preserves: "timeout" means WE FAILED TO ASK.
    It must never be reported as "no record exists", because that turns a
    network problem into a false security finding.
    """
    last = "error"
    for nameservers in RESOLVER_FALLBACK:
        r = dns.resolver.Resolver()
        if nameservers:
            r.nameservers = nameservers
        r.timeout = 5
        r.lifetime = 5
        try:
            return [str(a).strip() for a in r.resolve(name, rtype)], "found"
        except dns.resolver.NXDOMAIN:
            return [], "nxdomain"
        except dns.resolver.NoAnswer:
            return [], "no-answer"
        except dns.resolver.Timeout:
            last = "timeout"
        except dns.resolver.DNSException as exc:
            last = f"error:{type(exc).__name__}"
    return [], last


DNS_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]


def dns_dump(domain: str) -> dict:
    dump = {}
    for rtype in DNS_TYPES:
        values, status = resolve_with_fallback(domain, rtype)
        dump[rtype] = {"status": status, "values": values[:8]}
    # Common DKIM selector is a TXT record under a named subdomain.
    for sel in ("default", "google", "selector1", "selector2", "k1", "mail"):
        values, status = resolve_with_fallback(f"{sel}._domainkey.{domain}", "TXT")
        if values:
            dump.setdefault("DKIM", {"status": "found", "values": []})
            dump["DKIM"]["values"].extend(
                f"{sel}: {v[:60]}" for v in values if "v=DKIM1" in v or "p=" in v
            )
    return dump


# ── STEP 3: SUBDOMAIN ENUMERATION ─────────────────────────────────────────
# Idea: try a dictionary of common names, keep the ones that resolve.
#
# This is a DNS dictionary attack. Two engineering concerns make or break it:
#
#   CONCURRENCY - doing 200 lookups serially at ~100ms each is 20 seconds of
#   waiting. A thread pool does them concurrently. DNS lookups are IO-bound,
#   which is exactly the workload threads are good at. (Threads, not async,
#   because dnspython is blocking C-ish code we do not control.)
#
#   HONESTY - a name that fails to resolve might not exist, or the resolver
#   might have timed out. We record WHICH, because "does not exist" and "we
#   did not find out" are different claims and a recon tool must not blur them.
#
# 403 is the most common status by far. Those are NOT counted as found.
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "dev", "staging", "stage", "test", "testing", "qa",
    "api", "app", "admin", "portal", "dashboard", "panel", "cpanel", "whm",
    "webmail", "mail2", "smtp", "imap", "pop", "ns1", "ns2", "ns3", "ns4",
    "vpn", "remote", "ssh", "git", "gitlab", "github", "jenkins", "ci", "cd",
    "db", "database", "mysql", "postgres", "redis", "mongo", "sql",
    "blog", "shop", "store", "cdn", "assets", "static", "media", "img",
    "images", "files", "docs", "wiki", "help", "support", "status",
    "grafana", "kibana", "prometheus", "metrics", "logs", "monitor",
    "backup", "old", "new", "beta", "demo", "internal", "intranet", "corp",
]

NOT_FOUND = "not-found"
AMBIGUOUS = "ambiguous-timeout"


def probe_subdomain(domain: str, name: str) -> tuple[str, str, str]:
    """Return (fqdn, status, detail). status is found / not-found / ambiguous."""
    fqdn = f"{name}.{domain}"
    values, status = resolve_with_fallback(fqdn, "A")
    if status == "found":
        return fqdn, "found", ", ".join(values[:2])

    # No A record, but it may still be a CNAME. Ask that too before giving up.
    cnames, c_status = resolve_with_fallback(fqdn, "CNAME")
    if c_status == "found" and cnames:
        return fqdn, "found", "CNAME " + ", ".join(cnames[:2])

    if status in ("timeout",) or (status.startswith("error") and "Timeout" in status):
        return fqdn, AMBIGUOUS, status
    return fqdn, NOT_FOUND, status


def enumerate_subdomains(domain: str, workers: int = 24) -> dict:
    found, unresolved, ambiguous = [], [], []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(probe_subdomain, domain, name): name
            for name in COMMON_SUBDOMAINS
        }
        for fut in as_completed(futures):
            fqdn, status, detail = fut.result()
            if status == "found":
                found.append({"host": fqdn, "detail": detail})
            elif status == AMBIGUOUS:
                ambiguous.append({"host": fqdn, "detail": detail})
            else:
                unresolved.append(fqdn)

    return {
        "wordlist_size": len(COMMON_SUBDOMAINS),
        "found": sorted(found, key=lambda x: x["host"]),
        "not_found_count": len(unresolved),
        "ambiguous": ambiguous,
        "note": ("ambiguous entries are timeouts, not confirmed absent; a recon "
                 "tool should not report them as missing"),
    }


# ── STEP 4: REVERSE LOOKUP (PTR) ─────────────────────────────────────────
# Asks "given this IP, what hostname points back at it?"
#
# IMPORTANT DISTINCTION, and conflating these is a common rookie error:
#   PTR / reverse DNS  -> ONE hostname for an IP (free, built into DNS)
#   reverse IP lookup  -> EVERY domain hosted on that IP (needs a paid API
#                         like SecurityTrails or ViewDNS)
# We do PTR because it needs no key and no third party. We do NOT fake the
# other one, because a made-up "recon" number is worse than no number.
def ptr_lookup(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return "no PTR record"


# ── STEP 5: ZONE TRANSFER (AXFR) ─────────────────────────────────────────
# A nameserver SHOULD refuse AXFR for the internet. If it answers, it hands
# over every record in the zone, including internal hosts that were never
# meant to be public. This is one of the most classic DNS misconfigurations.
#
# AUTHORIZED USE ONLY. This is a real access attempt against someone else's
# server, so it is opt-in behind --axfr and refuses to run without
# --i-own-this, a deliberate speed bump so it is never fired by accident.
def try_zone_transfer(domain: str, timeout: int = 15) -> dict:
    ns_names, status = resolve_with_fallback(domain, "NS")
    if not ns_names:
        return {"attempted": False, "reason": f"no NS records ({status})"}

    results = []
    for ns in ns_names:
        host = ns.rstrip(".")
        entry = {"nameserver": host, "vulnerable": False, "record_count": 0,
                 "sample": []}
        try:
            zone = dns.zone.from_xfr(
                dns.query.xfr(host, domain, timeout=timeout, lifetime=timeout)
            )
            names = [n.to_text() for n in zone.nodes.keys()]
            entry["vulnerable"] = True
            entry["record_count"] = len(names)
            entry["sample"] = names[:15]
        except dns.query.TransferError:
            entry["reason"] = "refused (this is the correct behaviour)"
        except Exception as exc:                    # noqa: BLE001
            entry["reason"] = f"{type(exc).__name__}: not transferable"
        results.append(entry)
    return {"attempted": True, "nameservers": results}


# ── STEP 6: POSTURE SCORING ──────────────────────────────────────────────
# Turns raw facts into judgement, which is what makes a tool useful rather
# than just a data dump. Every verdict cites the record it came from so a
# reader can disagree with it.
def score_posture(domain: str, whois: dict, dns: dict,
                  subdomains: dict | None) -> dict:
    findings = []

    def add(sev, title, detail):
        findings.append({"severity": sev, "title": title, "detail": detail})

    # SPF: read the TXT values and find the "all" mechanism.
    spf = None
    for t in dns.get("TXT", {}).get("values", []):
        if "v=spf1" in t.replace('"', ""):
            spf = t.replace('"', "")
            break
    if not spf:
        add("HIGH", "No SPF record",
            "Anyone may send email claiming to be this domain.")
    else:
        mech = next((tok for tok in spf.split()
                     if tok in ("-all", "~all", "+all", "?all")), None)
        if mech == "+all":
            add("HIGH", "SPF is +all", "Anyone on the internet may send as this domain.")
        elif mech == "~all":
            add("LOW", "SPF is ~all", "Lenient policy: unknown senders are flagged, not rejected.")
        elif mech == "-all":
            pass
        elif mech == "?all":
            add("MEDIUM", "SPF is ?all", "Neutral policy; effectively no restriction.")

    dm, dm_policy = None, None
    dm_values, dm_status = resolve_with_fallback(f"_dmarc.{domain}", "TXT")
    for t in dm_values:
        joined = t.replace('"', "")
        if "v=DMARC1" in joined:
            dm = joined
            dm_policy = next((s.split("=", 1)[1].strip()
                              for s in joined.split(";")
                              if s.strip().startswith("p=")), None)
            break
    if not dm:
        add("MEDIUM", "No DMARC record", "Receivers are not told what to do with spoofed mail.")
    elif dm_policy == "none":
        add("LOW", "DMARC is p=none", "Monitoring only; failing mail is still delivered.")

    if not dns.get("MX", {}).get("values"):
        add("INFO", "No MX records", "This domain does not receive email.")
    elif all(re.fullmatch(r"0\s+\.?", str(v).strip())
             for v in dns["MX"]["values"]):
        # Same RFC 7505 null MX the email tool found. Easy to miss because the
        # record EXISTS - the naive check "MX present therefore mail works"
        # reports the exact opposite of reality.
        add("INFO", "Null MX (RFC 7505)",
            "MX is '0 .': the domain explicitly REFUSES all inbound mail. "
            "The record exists but mail is not delivered.")

    # DKIM: an empty p= tag means the key is REVOKED (RFC 8301 section 3).
    # This is easy to misread as a parsing bug, so we report it as a fact.
    #
    # DEDUPE, because the first version emitted one MEDIUM finding per selector
    # and example.com produced SIX identical lines. Many domains answer every
    # _domainkey.<selector> query with the same record (wildcard DNS), so the
    # same fact repeated six times is alert fatigue, not signal. One finding
    # naming the selectors is strictly more useful.
    revoked = []
    for entry in dns.get("DKIM", {}).get("values", []):
        if re.search(r"p=\s*[\"']?\s*$", entry.rstrip("\"'")):
            revoked.append(entry.split(":", 1)[0].strip())
    if revoked:
        add("MEDIUM", f"DKIM key revoked ({len(revoked)} selector"
                      f"{'s' if len(revoked) > 1 else ''})",
            "Empty p= tag on " + ", ".join(revoked[:8])
            + ". Per RFC 8301 an empty p= means the signing key is revoked, so "
              "mail signed with it fails validation. If every selector returns "
              "the same record the domain is likely answering via wildcard DNS.")

    if subdomains:
        interesting = [s for s in subdomains["found"]
                       if any(k in s["host"] for k in
                              ("dev", "test", "stage", "admin", "panel", "vpn",
                               "jenkins", "ci", "git", "grafana", "db", "api"))]
        if interesting:
            add("MEDIUM", f"{len(interesting)} interesting subdomain(s)",
               "Names that often expose non-production or admin surfaces: "
               + ", ".join(s["host"] for s in interesting[:8]))

    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
    findings.sort(key=lambda f: order.get(f["severity"], 9))
    return {"findings": findings,
            "counts": {s: sum(1 for f in findings if f["severity"] == s)
                       for s in ("HIGH", "MEDIUM", "LOW", "INFO")}}


# ── STEP 7: REPORT ────────────────────────────────────────────────────────
def assess(domain: str, do_subs: bool, do_axfr: bool) -> dict:
    domain = domain.strip().lower().strip(".")
    rep = {"domain": domain, "whois": whois_lookup(domain), "dns": dns_dump(domain)}

    for rtype, info in rep["dns"].items():
        ips = info["values"] if rtype == "A" else []
        if rtype == "A" and ips:
            rep.setdefault("reverse_dns", {})[ips[0]] = ptr_lookup(ips[0])

    if do_subs:
        rep["subdomains"] = enumerate_subdomains(domain)
    if do_axfr:
        rep["zone_transfer"] = try_zone_transfer(domain)

    rep["posture"] = score_posture(domain, rep["whois"], rep["dns"],
                                   rep.get("subdomains"))
    rep["scope"] = ("public WHOIS and DNS only; no credentials, no exploitation")
    return rep


def print_report(rep: dict) -> None:
    d = rep["domain"]
    print("=" * 68)
    print(f"OSINT DOMAIN REPORT  -  {d}")
    print("=" * 68)

    w = rep["whois"]
    print("\n[1] WHOIS")
    print(f"    tld            : .{w['tld']}")
    print(f"    server         : {w['server']}")
    if not w["raw_available"]:
        print(f"    unavailable    : {w['note']}")
    else:
        print(f"    registrar      : {w['registrar']}")
        print(f"    created        : {w['created']}")
        print(f"    updated        : {w['updated']}")
        print(f"    expires        : {w['expires']}")
        print(f"    registrant     : {w['registrant_country'] or 'withheld'}")
        print(f"    nameservers    : {', '.join(w['nameservers'][:4]) or 'none'}")
        print(f"    DNSSEC         : {w['dnssec'] or 'not stated'}")
        if w["note"]:
            print(f"    note           : {w['note']}")

    print("\n[2] DNS")
    for rtype, info in rep["dns"].items():
        vals = info["values"]
        shown = ", ".join(v[:46] for v in vals[:3]) if vals else "-"
        print(f"    {rtype:<7} [{info['status']:<9}] {shown}")

    if rep.get("reverse_dns"):
        print("\n[3] REVERSE DNS (PTR)")
        for ip, host in rep["reverse_dns"].items():
            print(f"    {ip:<17} -> {host}")

    if rep.get("subdomains"):
        s = rep["subdomains"]
        print(f"\n[4] SUBDOMAINS  (dictionary of {s['wordlist_size']})")
        for item in s["found"]:
            print(f"    FOUND   {item['host']:<38} {item['detail'][:34]}")
        print(f"    not found: {s['not_found_count']}")
        if s["ambiguous"]:
            print(f"    ambiguous (timeouts, NOT confirmed absent): {len(s['ambiguous'])}")

    if rep.get("zone_transfer"):
        z = rep["zone_transfer"]
        print("\n[5] ZONE TRANSFER")
        if not z.get("attempted"):
            print(f"    skipped: {z.get('reason')}")
        for ns in z.get("nameservers", []):
            tag = "VULNERABLE" if ns["vulnerable"] else "refused"
            print(f"    {ns['nameserver']:<34} {tag} {ns.get('reason','')}")

    p = rep["posture"]
    print("\n[6] POSTURE")
    for c, n in p["counts"].items():
        print(f"    {c:<7}: {n}")
    for f in p["findings"]:
        print(f"    [{f['severity']}] {f['title']}")
        print(f"            {f['detail']}")

    print(f"\n[7] SCOPE\n    {rep['scope']}")


def main() -> int:
    p = argparse.ArgumentParser(description="Public-data OSINT check for a domain.")
    p.add_argument("domain")
    p.add_argument("--subs", action="store_true", help="run subdomain dictionary lookup")
    p.add_argument("--axfr", action="store_true",
                   help="attempt a zone transfer (AUTHORIZED TARGETS ONLY)")
    p.add_argument("--i-own-this", action="store_true",
                   help="required acknowledgement for --axfr")
    p.add_argument("--json", metavar="PATH")
    args = p.parse_args()

    if args.axfr and not args.i_own_this:
        print("--axfr is an access attempt against a nameserver. It only runs "
              "against a domain you own or are authorised to test.\n"
              "Re-run with --i-own-this to confirm.")
        return 2

    rep = assess(args.domain, args.subs, args.axfr)
    print_report(rep)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(rep, fh, indent=2, default=str)
        print(f"\nJSON report written to {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

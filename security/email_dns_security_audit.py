#!/usr/bin/env python3
"""
email_dns_security_audit.py - Email spoofing & DNS posture auditor.

Audits a domain's anti-spoofing and DNS security records and reports every
weakness that lets an attacker send mail as that domain (or that leaves its
DNS unprotected):

  SPF      missing / duplicated records, +all and ?all, the RFC 7208
           10-DNS-lookup limit (a real, silent cause of permerror), and
           overly broad mechanisms
  DMARC    missing policy, p=none, pct<100, weak subdomain policy, no rua
  DKIM     probes common selectors, flags revoked keys and RSA moduli
           below 1024/2048 bits
  MTA-STS  missing policy record (no downgrade protection for inbound TLS)
  TLS-RPT  missing reporting endpoint
  CAA      missing issuer restriction (any CA may issue for the domain)
  DNSSEC   no DS record at the parent (zone answers are forgeable)
  MX       no null-MX on a domain that accepts no mail

Everything is checked over raw DNS from the standard library - no dnspython,
no requests, no cloud SDK, no API keys. Read-only: it sends DNS queries only.

Usage:
  python3 email_dns_security_audit.py example.com
  python3 email_dns_security_audit.py example.com acme.io --json
  python3 email_dns_security_audit.py -f domains.txt --min-severity HIGH
  python3 email_dns_security_audit.py example.com --resolver 1.1.1.1
  python3 email_dns_security_audit.py example.com --selectors s1,s2,google
  python3 email_dns_security_audit.py example.com --fail-on-findings   # CI gate

Exit codes:
  0  clean (or findings present without --fail-on-findings)
  1  findings at or above --min-severity, with --fail-on-findings
  2  usage / resolution error

Dependencies: Python 3.7+ standard library only.
Author: https://github.com/ashvinctrl/cloud-security-scripts
"""

import argparse
import base64
import json
import random
import socket
import struct
import sys

# ---------------------------------------------------------------------------
# Minimal DNS client (RFC 1035) - UDP with TCP fallback on truncation.
# ---------------------------------------------------------------------------

QTYPE = {"A": 1, "NS": 2, "CNAME": 5, "MX": 15, "TXT": 16, "DS": 43, "CAA": 257}
RCODE = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
         4: "NOTIMP", 5: "REFUSED"}

DEFAULT_RESOLVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]


class DNSError(Exception):
    pass


def _encode_name(name):
    out = b""
    for label in name.rstrip(".").split("."):
        if not label:
            continue
        raw = label.encode("idna") if any(ord(c) > 127 for c in label) else label.encode()
        if len(raw) > 63:
            raise DNSError("label too long: %s" % label)
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def _parse_name(data, off):
    """Decode a (possibly compressed) name; returns (name, offset_after)."""
    labels = []
    jumped = False
    end = off
    hops = 0
    while True:
        if off >= len(data):
            raise DNSError("truncated name")
        length = data[off]
        if length & 0xC0 == 0xC0:  # compression pointer
            if off + 1 >= len(data):
                raise DNSError("truncated pointer")
            ptr = ((length & 0x3F) << 8) | data[off + 1]
            if not jumped:
                end = off + 2
                jumped = True
            off = ptr
            hops += 1
            if hops > 64:
                raise DNSError("compression loop")
            continue
        off += 1
        if length == 0:
            if not jumped:
                end = off
            break
        labels.append(data[off:off + length].decode("utf-8", "replace"))
        off += length
    return ".".join(labels), end


def _build_query(qname, qtype):
    qid = random.randint(0, 0xFFFF)
    header = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)  # RD set
    body = _encode_name(qname) + struct.pack("!HH", qtype, 1)
    return qid, header + body


def _parse_response(data, qid):
    if len(data) < 12:
        raise DNSError("short response")
    rid, flags, qdcount, ancount, _ns, _ar = struct.unpack("!HHHHHH", data[:12])
    if rid != qid:
        raise DNSError("transaction id mismatch")
    rcode = flags & 0x0F
    truncated = bool(flags & 0x0200)
    off = 12
    for _ in range(qdcount):
        _, off = _parse_name(data, off)
        off += 4
    records = []
    for _ in range(ancount):
        _, off = _parse_name(data, off)
        if off + 10 > len(data):
            break
        rtype, _cls, _ttl, rdlen = struct.unpack("!HHIH", data[off:off + 10])
        off += 10
        records.append((rtype, data[off:off + rdlen], off))
        off += rdlen
    return rcode, truncated, records


def _send(server, payload, timeout, tcp=False):
    if tcp:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect((server, 53))
            sock.sendall(struct.pack("!H", len(payload)) + payload)
            head = sock.recv(2)
            if len(head) < 2:
                raise DNSError("short tcp response")
            want = struct.unpack("!H", head)[0]
            buf = b""
            while len(buf) < want:
                chunk = sock.recv(want - len(buf))
                if not chunk:
                    break
                buf += chunk
            return buf
        finally:
            sock.close()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(payload, (server, 53))
        return sock.recv(4096)
    finally:
        sock.close()


class Resolver:
    """Caching stub resolver. Every lookup in this tool goes through here."""

    def __init__(self, servers, timeout=4.0):
        self.servers = servers
        self.timeout = timeout
        self.cache = {}
        self.queries = 0

    def query(self, qname, qtype):
        """Returns (rcode_name, [decoded_rdata, ...])."""
        key = (qname.lower().rstrip("."), qtype)
        if key in self.cache:
            return self.cache[key]
        last = None
        for server in self.servers:
            try:
                qid, payload = _build_query(qname, QTYPE[qtype])
                self.queries += 1
                raw = _send(server, payload, self.timeout)
                rcode, truncated, records = _parse_response(raw, qid)
                if truncated:
                    raw = _send(server, payload, self.timeout, tcp=True)
                    rcode, _, records = _parse_response(raw, qid)
                decoded = [_decode_rdata(qtype, rdata, raw, off)
                           for rtype, rdata, off in records if rtype == QTYPE[qtype]]
                result = (RCODE.get(rcode, "RCODE%d" % rcode), decoded)
                self.cache[key] = result
                return result
            except (socket.timeout, OSError, DNSError) as exc:
                last = exc
                continue
        raise DNSError("all resolvers failed for %s/%s: %s" % (qname, qtype, last))


def _decode_rdata(qtype, rdata, message, off):
    if qtype == "TXT":
        parts, i = [], 0
        while i < len(rdata):
            n = rdata[i]
            parts.append(rdata[i + 1:i + 1 + n].decode("utf-8", "replace"))
            i += 1 + n
        return "".join(parts)  # RFC 7208: character-strings are concatenated
    if qtype == "MX":
        pref = struct.unpack("!H", rdata[:2])[0]
        name, _ = _parse_name(message, off + 2)
        return "%d %s" % (pref, name or ".")
    if qtype in ("CNAME", "NS"):
        name, _ = _parse_name(message, off)
        return name
    if qtype == "A":
        return socket.inet_ntoa(rdata)
    if qtype == "DS":
        keytag, alg, dtype = struct.unpack("!HBB", rdata[:4])
        return "keytag=%d alg=%d digest=%d" % (keytag, alg, dtype)
    if qtype == "CAA":
        tag_len = rdata[1]
        tag = rdata[2:2 + tag_len].decode("ascii", "replace")
        value = rdata[2 + tag_len:].decode("utf-8", "replace")
        return "%s %s" % (tag, value)
    return rdata.hex()


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

SEVERITIES = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


class Report:
    def __init__(self, domain):
        self.domain = domain
        self.findings = []
        self.records = {}

    def add(self, severity, check, message, remediation):
        self.findings.append({
            "severity": severity,
            "check": check,
            "message": message,
            "remediation": remediation,
        })

    def worst(self):
        if not self.findings:
            return None
        return max(self.findings, key=lambda f: SEVERITIES.index(f["severity"]))["severity"]


# ---------------------------------------------------------------------------
# SPF
# ---------------------------------------------------------------------------

# Mechanisms that each cost a DNS lookup against the RFC 7208 limit of 10.
SPF_LOOKUP_PREFIXES = ("include:", "a:", "mx:", "ptr:", "exists:", "redirect=")
SPF_BARE_LOOKUPS = ("a", "mx", "ptr")


def _spf_records(resolver, domain):
    _rcode, txts = resolver.query(domain, "TXT")
    return [t for t in txts if t.lower().startswith("v=spf1")]


def _count_spf_lookups(resolver, record, depth=0, seen=None, budget=None):
    """Count DNS-querying mechanisms the way RFC 7208 sec 4.6.4 does."""
    if budget is None:
        budget = {"n": 0}
    if seen is None:
        seen = set()
    if depth > 10 or budget["n"] > 20:
        return budget["n"]
    for term in record.split()[1:]:
        bare = term.lstrip("+-~?")
        low = bare.lower()
        if low not in SPF_BARE_LOOKUPS and not low.startswith(SPF_LOOKUP_PREFIXES):
            continue
        budget["n"] += 1
        target = None
        if low.startswith("include:"):
            target = bare[len("include:"):]
        elif low.startswith("redirect="):
            target = bare[len("redirect="):]
        if not target or "%" in target or target.lower() in seen:
            continue
        seen.add(target.lower())
        try:
            nested = _spf_records(resolver, target)
        except DNSError:
            nested = []
        if nested:
            _count_spf_lookups(resolver, nested[0], depth + 1, seen, budget)
    return budget["n"]


def check_spf(resolver, domain, report):
    try:
        records = _spf_records(resolver, domain)
    except DNSError as exc:
        report.add("INFO", "SPF", "lookup failed: %s" % exc, "Retry or use --resolver.")
        return
    report.records["spf"] = records

    if not records:
        report.add("HIGH", "SPF", "No SPF record published.",
                   'Publish a TXT record: "v=spf1 include:<provider> -all".')
        return
    if len(records) > 1:
        report.add("HIGH", "SPF",
                   "%d SPF records published; RFC 7208 requires exactly one, so "
                   "receivers return permerror and ignore SPF entirely." % len(records),
                   "Merge them into a single v=spf1 TXT record.")

    record = records[0]
    terms = record.split()
    all_terms = [t for t in terms if t.lstrip("+-~?").lower() == "all"]
    has_redirect = any(t.lower().startswith("redirect=") for t in terms)

    if not all_terms and not has_redirect:
        report.add("MEDIUM", "SPF",
                   "SPF has no 'all' mechanism and no redirect, so unlisted senders "
                   "get a neutral result.",
                   "Append '-all' (or at minimum '~all') to the record.")
    for term in all_terms:
        qualifier = term[0] if term[0] in "+-~?" else "+"
        if qualifier == "+":
            report.add("CRITICAL", "SPF",
                       "Record ends in '+all' - every host on the internet is an "
                       "authorised sender for this domain.",
                       "Replace '+all' with '-all'.")
        elif qualifier == "?":
            report.add("MEDIUM", "SPF",
                       "Record ends in '?all' (neutral); SPF gives no protection.",
                       "Replace '?all' with '-all'.")
        elif qualifier == "~":
            report.add("LOW", "SPF",
                       "Record ends in '~all' (softfail); mail from unlisted hosts is "
                       "usually still delivered.",
                       "Move to '-all' once every sending source is confirmed.")

    for term in terms:
        bare = term.lstrip("+-~?").lower()
        if bare == "ptr" or bare.startswith("ptr:"):
            report.add("LOW", "SPF",
                       "Uses the deprecated 'ptr' mechanism (RFC 7208 sec 5.5 says do "
                       "not publish it); some receivers skip it entirely.",
                       "Remove 'ptr' and list sources with include/ip4/ip6.")
        for prefix in ("ip4:", "ip6:"):
            if bare.startswith(prefix) and "/" in bare:
                try:
                    mask = int(bare.split("/", 1)[1])
                except ValueError:
                    continue
                if (prefix == "ip4:" and mask < 16) or (prefix == "ip6:" and mask < 32):
                    report.add("MEDIUM", "SPF",
                               "Authorises a very large netblock (%s)." % term,
                               "Narrow it to the hosts that actually send mail.")

    try:
        lookups = _count_spf_lookups(resolver, record)
    except DNSError:
        lookups = None
    if lookups is None:
        return
    report.records["spf_dns_lookups"] = lookups
    if lookups > 10:
        report.add("HIGH", "SPF",
                   "SPF evaluation needs %d DNS lookups; the RFC 7208 limit is 10, so "
                   "receivers return permerror and SPF silently stops working."
                   % lookups,
                   "Flatten or drop include: chains to get under 10 lookups.")
    elif lookups == 10:
        report.add("LOW", "SPF",
                   "SPF uses exactly 10 DNS lookups - the maximum allowed; adding one "
                   "more sender will break it.",
                   "Reduce include: depth to leave headroom.")


# ---------------------------------------------------------------------------
# DMARC
# ---------------------------------------------------------------------------

def _parse_tag_value(record):
    tags = {}
    for part in record.split(";"):
        if "=" in part:
            key, value = part.split("=", 1)
            tags[key.strip().lower()] = value.strip()
    return tags


def check_dmarc(resolver, domain, report):
    name = "_dmarc.%s" % domain
    try:
        _rcode, txts = resolver.query(name, "TXT")
    except DNSError as exc:
        report.add("INFO", "DMARC", "lookup failed: %s" % exc, "Retry or use --resolver.")
        return
    records = [t for t in txts if t.lower().replace(" ", "").startswith("v=dmarc1")]
    report.records["dmarc"] = records

    if not records:
        report.add("HIGH", "DMARC",
                   "No DMARC record at %s; SPF/DKIM failures are not enforced and you "
                   "get no visibility into spoofing." % name,
                   'Publish "v=DMARC1; p=none; rua=mailto:dmarc@%s", then move to '
                   "p=quarantine and p=reject." % domain)
        return
    if len(records) > 1:
        report.add("HIGH", "DMARC",
                   "%d DMARC records found; receivers treat this as no policy at all."
                   % len(records),
                   "Keep exactly one _dmarc TXT record.")

    tags = _parse_tag_value(records[0])
    policy = tags.get("p", "").lower()
    if policy == "none":
        report.add("MEDIUM", "DMARC",
                   "Policy is p=none - failures are reported but still delivered, so "
                   "spoofed mail reaches inboxes.",
                   "Move to p=quarantine, then p=reject once reports are clean.")
    elif policy == "quarantine":
        report.add("LOW", "DMARC", "Policy is p=quarantine, not p=reject.",
                   "Move to p=reject once reports show no legitimate failures.")
    elif policy != "reject":
        report.add("HIGH", "DMARC",
                   "DMARC record has no valid p= tag, so the whole record is ignored.",
                   "Add p=reject (or p=quarantine) to the record.")

    if tags.get("sp", "").lower() == "none" and policy in ("quarantine", "reject"):
        report.add("MEDIUM", "DMARC",
                   "Subdomain policy sp=none overrides the strict domain policy - any "
                   "subdomain can be spoofed freely.",
                   "Set sp=reject, or remove the sp tag to inherit p=.")

    if "pct" in tags:
        try:
            pct = int(tags["pct"])
        except ValueError:
            report.add("LOW", "DMARC", "pct tag is not a number: %r" % tags["pct"],
                       "Set pct to an integer between 0 and 100.")
        else:
            if pct < 100:
                report.add("MEDIUM", "DMARC",
                           "pct=%d - the policy is applied to only %d%% of failing "
                           "mail." % (pct, pct),
                           "Set pct=100 once rollout is complete.")

    if not tags.get("rua"):
        report.add("LOW", "DMARC",
                   "No rua= aggregate report address, so spoofing attempts against the "
                   "domain are invisible to you.",
                   "Add rua=mailto:dmarc@%s." % domain)


# ---------------------------------------------------------------------------
# DKIM
# ---------------------------------------------------------------------------

COMMON_SELECTORS = [
    "default", "selector1", "selector2", "google", "k1", "k2", "s1", "s2",
    "mail", "dkim", "mandrill", "zendesk1", "sig1", "smtp", "protonmail",
]


def _der_tlv(data, i):
    """Read one ASN.1 DER tag-length-value; returns (tag, value, next_index)."""
    tag = data[i]
    i += 1
    length = data[i]
    i += 1
    if length & 0x80:
        count = length & 0x7F
        length = int.from_bytes(data[i:i + count], "big")
        i += count
    return tag, data[i:i + length], i + length


def _rsa_key_bits(der):
    """Modulus size of an RSA SubjectPublicKeyInfo, or None if unparseable."""
    try:
        tag, spki, _ = _der_tlv(der, 0)
        if tag != 0x30:
            return None
        _tag, _alg, i = _der_tlv(spki, 0)
        tag, bitstring, _ = _der_tlv(spki, i)
        if tag != 0x03:
            return None
        _tag, rsa_seq, _ = _der_tlv(bitstring[1:], 0)  # drop the unused-bits byte
        tag, modulus, _ = _der_tlv(rsa_seq, 0)
        if tag != 0x02:
            return None
        return len(modulus.lstrip(b"\x00")) * 8
    except (IndexError, ValueError):
        return None


def _dkim_records(resolver, selector, domain):
    """DKIM key records for one selector, or [] if the name holds none."""
    try:
        _rcode, txts = resolver.query("%s._domainkey.%s" % (selector, domain), "TXT")
    except DNSError:
        return []
    out = []
    for txt in txts:
        tags = _parse_tag_value(txt)
        # A key record must carry a p= tag; v=DKIM1 is recommended but optional.
        if "p" in tags and (tags.get("v", "dkim1").lower() == "dkim1" or "k" in tags):
            out.append((txt, tags))
    return out


def check_dkim(resolver, domain, report, selectors):
    # A wildcard under _domainkey answers for every name, so per-selector probing
    # tells us nothing - detect it once instead of reporting it once per selector.
    if _dkim_records(resolver, "wildcard-probe-4f2a9c", domain):
        report.records["dkim_wildcard"] = True
        report.add("INFO", "DKIM",
                   "A wildcard record answers for every *._domainkey.%s name, so "
                   "selectors cannot be enumerated from DNS." % domain,
                   "None needed if the wildcard is a deliberate 'this domain does not "
                   "sign mail' marker; otherwise remove it so real selectors resolve.")
        report.records["dkim_selectors"] = []
        return

    found = []
    for selector in selectors:
        for _txt, tags in _dkim_records(resolver, selector, domain):
            found.append(selector)
            key = tags.get("p", "")
            if not key:
                report.add("MEDIUM", "DKIM",
                           "Selector '%s' publishes an empty p= tag (revoked key); any "
                           "mail still signed with it fails DKIM." % selector,
                           "Remove the record once the selector is fully retired.")
                continue
            if tags.get("t", "").lower().startswith("y"):
                report.add("LOW", "DKIM",
                           "Selector '%s' is in test mode (t=y); receivers ignore DKIM "
                           "failures for it." % selector,
                           "Remove t=y once the selector is in production.")
            if tags.get("k", "rsa").lower() != "rsa":
                continue
            try:
                der = base64.b64decode(key + "=" * (-len(key) % 4))
            except (ValueError, TypeError):
                continue
            bits = _rsa_key_bits(der)
            if bits is None:
                continue
            report.records.setdefault("dkim_key_bits", {})[selector] = bits
            if bits < 1024:
                report.add("HIGH", "DKIM",
                           "Selector '%s' uses a %d-bit RSA key - factorable on modest "
                           "hardware, so signatures can be forged." % (selector, bits),
                           "Rotate to a 2048-bit key.")
            elif bits < 2048:
                report.add("MEDIUM", "DKIM",
                           "Selector '%s' uses a %d-bit RSA key; RFC 8301 sets 1024 as "
                           "the floor and 2048 as the recommendation." % (selector, bits),
                           "Rotate to a 2048-bit key.")
    report.records["dkim_selectors"] = found
    if not found:
        report.add("MEDIUM", "DKIM",
                   "No DKIM key found for the probed selectors (%s). Selectors are not "
                   "discoverable via DNS, so confirm with --selectors before acting on "
                   "this." % ", ".join(selectors[:6]),
                   "Publish a DKIM key and sign outbound mail - DMARC needs SPF or "
                   "DKIM to align, and DKIM survives forwarding.")


# ---------------------------------------------------------------------------
# Transport security, CAA, DNSSEC, MX
# ---------------------------------------------------------------------------

def check_transport(resolver, domain, report):
    try:
        _rcode, txts = resolver.query("_mta-sts.%s" % domain, "TXT")
        sts = [t for t in txts if t.lower().startswith("v=stsv1")]
    except DNSError:
        sts = []
    report.records["mta_sts"] = sts
    if not sts:
        report.add("LOW", "MTA-STS",
                   "No MTA-STS record; inbound SMTP TLS can be stripped by an on-path "
                   "attacker without anyone noticing.",
                   "Publish an _mta-sts TXT record plus a policy at "
                   "https://mta-sts.%s/.well-known/mta-sts.txt." % domain)

    try:
        _rcode, txts = resolver.query("_smtp._tls.%s" % domain, "TXT")
        rpt = [t for t in txts if t.lower().startswith("v=tlsrptv1")]
    except DNSError:
        rpt = []
    report.records["tls_rpt"] = rpt
    if not rpt:
        report.add("INFO", "TLS-RPT",
                   "No SMTP TLS reporting record, so TLS negotiation failures against "
                   "your MX hosts go unreported.",
                   'Publish _smtp._tls TXT: "v=TLSRPTv1; rua=mailto:tls@%s".' % domain)


def check_caa(resolver, domain, report):
    try:
        _rcode, records = resolver.query(domain, "CAA")
    except DNSError:
        return
    report.records["caa"] = records
    if not records:
        report.add("LOW", "CAA",
                   "No CAA record; any public CA may issue a certificate for this "
                   "domain.",
                   'Publish CAA: 0 issue "<your-ca>" and 0 iodef "mailto:security@%s".'
                   % domain)


def check_dnssec(resolver, domain, report):
    try:
        _rcode, records = resolver.query(domain, "DS")
    except DNSError:
        return
    report.records["ds"] = records
    if not records:
        report.add("LOW", "DNSSEC",
                   "No DS record at the parent zone; this domain's DNS answers are "
                   "unsigned and forgeable by an on-path or cache-poisoning attacker - "
                   "including the SPF, DKIM and DMARC records above.",
                   "Enable DNSSEC at the DNS provider and publish the DS record at the "
                   "registrar.")


def check_mx(resolver, domain, report):
    try:
        _rcode, records = resolver.query(domain, "MX")
    except DNSError:
        return
    report.records["mx"] = records
    if not records:
        report.add("LOW", "MX",
                   "No MX record and no null MX, so senders cannot tell whether this "
                   "domain accepts mail.",
                   'Publish a null MX ("0 .") per RFC 7505 if the domain never '
                   "receives mail.")


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------

def audit(resolver, domain, selectors):
    report = Report(domain)
    check_spf(resolver, domain, report)
    check_dmarc(resolver, domain, report)
    check_dkim(resolver, domain, report, selectors)
    check_transport(resolver, domain, report)
    check_caa(resolver, domain, report)
    check_dnssec(resolver, domain, report)
    check_mx(resolver, domain, report)
    report.findings.sort(key=lambda f: -SEVERITIES.index(f["severity"]))
    return report


def print_report(report, min_index):
    print("")
    print(report.domain)
    print("-" * max(len(report.domain), 60))
    spf = report.records.get("spf") or []
    if spf:
        lookups = report.records.get("spf_dns_lookups")
        suffix = "   [%s DNS lookups]" % lookups if lookups is not None else ""
        print("  SPF     %s%s" % (spf[0][:110], suffix))
    dmarc = report.records.get("dmarc") or []
    if dmarc:
        print("  DMARC   %s" % dmarc[0][:110])
    dkim = report.records.get("dkim_selectors") or []
    if dkim:
        print("  DKIM    selectors found: %s" % ", ".join(dkim))
    mx = report.records.get("mx") or []
    if mx:
        print("  MX      %s" % ", ".join(mx[:3]))

    shown = [f for f in report.findings if SEVERITIES.index(f["severity"]) >= min_index]
    if not shown:
        print("")
        print("  No findings at or above the selected severity.")
        return 0
    print("")
    for finding in shown:
        print("  [%-8s] %-7s %s" % (finding["severity"], finding["check"],
                                    finding["message"]))
        print("                     fix: %s" % finding["remediation"])
    return len(shown)


def main():
    parser = argparse.ArgumentParser(
        description="Audit a domain's email anti-spoofing and DNS security posture.")
    parser.add_argument("domains", nargs="*", help="domains to audit")
    parser.add_argument("-f", "--file", help="file with one domain per line")
    parser.add_argument("--resolver", action="append",
                        help="DNS resolver IP (repeatable; default 1.1.1.1, 8.8.8.8, "
                             "9.9.9.9)")
    parser.add_argument("--selectors",
                        help="comma-separated DKIM selectors to probe (default: %d "
                             "common ones)" % len(COMMON_SELECTORS))
    parser.add_argument("--timeout", type=float, default=4.0,
                        help="per-query DNS timeout in seconds (default 4)")
    parser.add_argument("--min-severity", default="INFO", choices=SEVERITIES,
                        help="hide findings below this severity (default INFO)")
    parser.add_argument("--json", action="store_true", help="emit JSON instead of text")
    parser.add_argument("--fail-on-findings", action="store_true",
                        help="exit 1 if any finding is at or above --min-severity")
    args = parser.parse_args()

    domains = list(args.domains)
    if args.file:
        try:
            with open(args.file) as handle:
                domains += [line.strip() for line in handle
                            if line.strip() and not line.startswith("#")]
        except OSError as exc:
            print("error: %s" % exc, file=sys.stderr)
            return 2
    domains = [d.strip().rstrip(".").lower() for d in domains if d.strip()]
    if not domains:
        parser.print_usage(sys.stderr)
        print("error: give at least one domain, or -f FILE", file=sys.stderr)
        return 2

    resolvers = args.resolver or list(DEFAULT_RESOLVERS)
    selectors = ([s.strip() for s in args.selectors.split(",") if s.strip()]
                 if args.selectors else COMMON_SELECTORS)
    min_index = SEVERITIES.index(args.min_severity)

    reports, shown_total = [], 0
    for domain in domains:
        resolver = Resolver(resolvers, timeout=args.timeout)
        try:
            report = audit(resolver, domain, selectors)
        except DNSError as exc:
            print("error: %s: %s" % (domain, exc), file=sys.stderr)
            reports.append({"domain": domain, "error": str(exc)})
            continue
        kept = [f for f in report.findings
                if SEVERITIES.index(f["severity"]) >= min_index]
        reports.append({
            "domain": domain,
            "records": report.records,
            "worst_severity": report.worst(),
            "findings": kept,
        })
        if args.json:
            shown_total += len(kept)
        else:
            shown_total += print_report(report, min_index)

    if args.json:
        print(json.dumps({"domains": reports, "finding_count": shown_total}, indent=2))
    else:
        print("")
        print("%d finding(s) across %d domain(s)." % (shown_total, len(domains)))

    if args.fail_on_findings and shown_total:
        return 1
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)

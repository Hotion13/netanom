#!/usr/bin/env python3
"""
sanitize_netconfig.py — Network configuration sanitizer
========================================================

Targets : Cisco (IOS / IOS-XE / NX-OS) and Arista EOS.
Purpose : strip or pseudonymize sensitive information from a configuration
          file BEFORE sending it to an AI (or any third party), without
          breaking the internal consistency required for a useful analysis.

Two families of treatment
-------------------------
1. SECRETS  -> DESTRUCTION. The real value is replaced by a marker
   (e.g. <SANITIZED-SECRET>) and is never stored anywhere. The algorithm
   hint (type 7, type 9, sha512, RO/RW, ACL...) is kept, as it is useful
   security information and NOT confidential.

2. IDENTIFIERS -> CONSISTENT PSEUDONYMIZATION. A given original value is
   always replaced by the same alias (device-1, 198.51.100.x,
   example-1.net...) so that the relationships within the file remain
   usable by the AI. The mapping table can be written to a .map.json file
   to be KEPT LOCALLY: it lets you re-apply the AI's recommendations to
   the real configuration afterwards. That file must NEVER be sent to the
   AI or to any third party.

What gets neutralized
---------------------
DESTROYED SECRETS:
  - enable secret / enable password (all types: 0,5,7,8,9, sha512)
  - username ... secret/password (incl. EOS "secret sha512")
  - user SSH public keys (username ... sshkey ...): identifying material
  - line passwords (line con/vty/aux: password ...)
  - SNMP communities (snmp-server community) and the community embedded in
    snmp-server host (incl. vrf / use-vrf / traps / informs / version 1|2c|3)
  - SNMPv3 keys (auth md5/sha[-]..., priv des/aes[-128...], NX-OS 0x... forms)
  - TACACS+ / RADIUS keys (tacacs-server key, radius-server ... key, and
    "radius server X" / "tacacs server X" blocks with an indented "key",
    key 7 ...)
  - password-encryption master key (key config-key password-encrypt)
  - VPN pre-shared keys (crypto isakmp key [0|6|encrypted], pre-shared-key)
  - neighbor / routing-protocol authentication (neighbor ... password, OSPF
    message-digest-key md5, authentication-key, authentication text,
    IS-IS isis password / area-password / domain-password)
  - plaintext FHRP authentication (standby / vrrp ... authentication)
  - key-string (key chains)
  - PPP CHAP/PAP, ip ftp password, ip http client password,
    NTP authentication keys
  - PKI certificates (IOS hex blobs) and PEM blocks
    (-----BEGIN...-----END-----)
  - banners (banner motd/login/exec ...), which often carry
    organizational/legal information
  - e-mail addresses

PSEUDONYMIZED IDENTIFIERS (consistent):
  - hostname / switchname / sysname  -> device-N (replaced everywhere,
    case-insensitive, including inside "host.domain" FQDNs)
  - domain (ip domain-name / domain list / dns domain / DHCP domain-name)
    -> example-N.net (replaced everywhere, including as an FQDN suffix)
  - public IPv4 addresses -> RFC 5737 documentation ranges, then
    198.18.0.0/15 (RFC 2544) beyond ~760 distinct addresses
  - public IPv6 addresses -> 2001:db8::/32 (RFC 3849)
  - MAC addresses -> fictitious locally-administered MACs (format preserved,
    consistent across the aabb.ccdd.eeff and aa:bb:cc:dd:ee:ff notations);
    multicast/broadcast MACs and well-known virtual MACs (HSRP, VRRP, GLBP)
    are kept, as they carry protocol meaning and are not identifying
  - interface descriptions -> consistent token (--keep-descriptions to keep)
  - snmp-server location / contact -> marker (address, phone, name are
    sensitive)

Limitations (IMPORTANT)
-----------------------
Best-effort, pattern-based tool. It does NOT replace a human review. In
particular, manually check: VRF / route-map / ACL / trustpoint names,
serial and license numbers, circuit IDs inside descriptions, EOS agent
tokens (daemon TerminAttr...), WLAN PSKs, snmp engineID, purely numeric
values after "key" (ambiguous with a key-chain key number), and any secret
with an exotic syntax. Masks/prefixes are not recomputed: a replaced
network address may become a host address (subnet consistency is not
guaranteed). At the end of processing the script prints the residual lines
that still look like secrets: review them.

Usage
-----
  netanom config.txt -o config.san.txt -m config.map.json      (installed CLI)
  python3 sanitize_netconfig.py config.txt -o config.san.txt -m config.map.json
  cat config.txt | python3 sanitize_netconfig.py - > config.san.txt
  python3 sanitize_netconfig.py config.txt --anonymize-all-ips --keep-descriptions
  python3 sanitize_netconfig.py config.txt --strict   # exit code 2 on residue
"""

import argparse
import ipaddress
import json
import re
import sys
from itertools import count

__version__ = "0.3.0"

# ---------------------------------------------------------------------------
# Markers
# ---------------------------------------------------------------------------
def ph(category: str) -> str:
    """Return a homogeneous redaction marker for a given category."""
    return f"<SANITIZED-{category}>"

S_SECRET = ph("SECRET")
S_COMMUNITY = ph("SNMP-COMMUNITY")
S_EMAIL = ph("EMAIL")
S_LOCATION = ph("LOCATION")
S_CONTACT = ph("CONTACT")
S_BANNER = ph("BANNER")
S_CERT = ph("CERTIFICATE-OR-KEY")
S_SSHKEY = ph("SSH-KEY")

# ---------------------------------------------------------------------------
# Secret DESTRUCTION rules
# Each rule = (compiled regex, replacement string).
# Convention: keep the "directive" plus the algorithm hint through capturing
# groups, destroy only the sensitive value.
# ORDER MATTERS: from most specific to most generic. The inline
# "key <type> <value>" rule is deliberately LAST and never matches inside a
# hyphenated -key directive (message-digest-key, etc.), otherwise it would
# destroy the algorithm token and let the actual secret leak.
# ---------------------------------------------------------------------------
_F = re.IGNORECASE
SECRET_RULES = [
    # enable secret/password [level N] [0|5|7|8|9|sha512...] <value>
    (re.compile(r'^(\s*enable\s+(?:secret|password)(?:\s+level\s+\d+)?'
                r'(?:\s+(?:0|5|7|8|9|sha512|sha256|md5))?\s+)\S+.*$', _F),
     r'\1' + S_SECRET),

    # username X [privilege N] [role ...] secret|password [algo] <hash> [rest]
    (re.compile(r'^(\s*username\s+\S+\s+.*?\b(?:secret|password)'
                r'(?:\s+(?:sha512|sha256|md5|0|5|7|8|9))?\s+)(\S+)(.*)$', _F),
     r'\1' + S_SECRET + r'\3'),
    # account SSH public key (EOS "username X sshkey ssh-rsa ..."):
    # not a secret, but identifying (comment field, correlation potential)
    (re.compile(r'^(\s*username\s+\S+\s+ssh-?key\s+).*$', _F),
     r'\1' + S_SSHKEY),

    # line password or generic: password [type] <value>
    (re.compile(r'^(\s*password\s+(?:\d\s+)?)\S+.*$', _F),
     r'\1' + S_SECRET),
    # bare secret (rare outside username): secret [algo] <value>
    (re.compile(r'^(\s*secret\s+(?:sha512\s+|sha256\s+|\d\s+)?)\S+.*$', _F),
     r'\1' + S_SECRET),

    # SNMP: community (keep RO/RW and the optional ACL)
    (re.compile(r'^(\s*snmp-server\s+community\s+)\S+(.*)$', _F),
     r'\1' + S_COMMUNITY + r'\2'),
    # SNMP host: every IOS/NX-OS/EOS form. Skip the known keywords (vrf X,
    # use-vrf X, traps, informs, version X, auth/noauth/priv) then destroy
    # the next token = community (or v3 user, an identifier).
    (re.compile(r'^(\s*snmp-server\s+host\s+\S+'
                r'(?:\s+(?:(?:vrf|use-vrf|filter-vrf|version)\s+\S+'
                r'|traps|informs|auth|noauth|priv))*'
                r'\s+)(?!(?:vrf|use-vrf|filter-vrf|version|traps|informs'
                r'|auth|noauth|priv|udp-port)\b)(\S+)(.*)$', _F),
     r'\1' + S_COMMUNITY + r'\3'),
    # SNMPv3: auth md5|sha|sha-256... <key>  /  priv des|3des|aes[- ]128... <key>
    (re.compile(r'(\bauth\s+(?:md5|sha-?(?:512|384|256|224)?)\s+)(\S+)', _F),
     r'\1' + S_SECRET),
    (re.compile(r'(\bpriv\s+(?:des|3des|aes(?:[\s-]+(?:128|192|256))?)\s+)(\S+)', _F),
     r'\1' + S_SECRET),
    # NX-OS localized form: priv 0x<hex> (no algorithm keyword)
    (re.compile(r'(\bpriv\s+)(0x[0-9A-Fa-f]+)', _F),
     r'\1' + S_SECRET),

    # TACACS+ / RADIUS: global line, whatever precedes "key"
    # (host, auth-port, acct-port, timeout...)
    (re.compile(r'^(\s*(?:tacacs|radius)-server\s+.*?\bkey\s+(?:\d\s+)?)\S.*$', _F),
     r'\1' + S_SECRET),
    # password-encryption master key (AES password encryption)
    (re.compile(r'^(\s*key\s+config-key\s+password-encrypt\s+)\S.*$', _F),
     r'\1' + S_SECRET),
    # "key [type] <value>" at the start of a line ("radius server X" /
    # "tacacs server X" blocks). Leaves "key chain X", key-chain key numbers
    # ("key 1") and "key config-key ..." (dedicated rule above) untouched.
    (re.compile(r'^(\s*key\s+(?:\d\s+)?)(?!chain\b|config-key\b|\d+\s*$)\S.*$', _F),
     r'\1' + S_SECRET),

    # VPN / IPsec
    (re.compile(r'^(\s*crypto\s+isakmp\s+key\s+(?:[06]\s+)?)(\S+)(.*)$', _F),
     r'\1' + S_SECRET + r'\3'),
    (re.compile(r'(\bpre-shared-key\s+(?:(?:local|remote|encrypted)\s+)?(?:\d\s+)?)'
                r'(?!address\b|hostname\b)(\S+)', _F),
     r'\1' + S_SECRET),

    # Routing: BGP / OSPF / misc
    (re.compile(r'(\bneighbor\s+\S+\s+password\s+(?:\d\s+)?)(\S+)', _F),
     r'\1' + S_SECRET),
    (re.compile(r'(\bmessage-digest-key\s+\d+\s+md5\s+(?:\d\s+)?)(\S+)', _F),
     r'\1' + S_SECRET),
    (re.compile(r'(\bauthentication-key\s+(?:\d\s+)?)(\S+)\s*$', _F),
     r'\1' + S_SECRET),
    (re.compile(r'(\bauthentication\s+text\s+)(\S+)', _F),
     r'\1' + S_SECRET),
    # IS-IS: isis password / area-password / domain-password [hmac-md5] <pw>
    (re.compile(r'^(\s*(?:isis\s+password|(?:area|domain)-password)\s+'
                r'(?:hmac-md5\s+)?)(\S+)(.*)$', _F),
     r'\1' + S_SECRET + r'\3'),
    # FHRP: standby/vrrp ... authentication <plaintext-pw>
    # (md5/text/key-string/key-chain forms are handled by other rules)
    (re.compile(r'^(\s*(?:standby|vrrp)\s+(?:\d+\s+)?authentication\s+)'
                r'(?!md5\b|text\b|key-string\b|key-chain\b)(\S+)(.*)$', _F),
     r'\1' + S_SECRET + r'\3'),

    # Key chains
    (re.compile(r'(\bkey-string\s+(?:\d\s+)?)(\S+)', _F),
     r'\1' + S_SECRET),

    # PPP / FTP / HTTP / NTP
    (re.compile(r'(\bppp\s+chap\s+(?:hostname\s+\S+\s+)?password\s+(?:\d\s+)?)(\S+)', _F),
     r'\1' + S_SECRET),
    (re.compile(r'(\bsent-username\s+\S+\s+password\s+(?:\d\s+)?)(\S+)', _F),
     r'\1' + S_SECRET),
    (re.compile(r'(\bip\s+(?:ftp|http\s+client)\s+password\s+(?:\d\s+)?)(\S+)', _F),
     r'\1' + S_SECRET),
    (re.compile(r'(\bntp\s+authentication-key\s+\d+\s+'
                r'(?:md5|sha\d*|hmac-sha[0-9-]*|cmac-aes-\d+)\s+(?:\d\s+)?)(\S+)', _F),
     r'\1' + S_SECRET),

    # Generic inline "... key <type> <value>" — LAST. The lookbehind forbids
    # matching inside "message-digest-key", "authentication-key",
    # "pre-shared-key", etc. (directives already handled above).
    (re.compile(r'((?<![\w-])key\s+(?:0|5|7|8|9)\s+)(\S+)', _F),
     r'\1' + S_SECRET),
]

# "Free text value" rules -> marker (no pseudonymization, destroy)
LOCATION_RX = re.compile(r'^(\s*snmp-server\s+location\s+).*$', _F)
CONTACT_RX = re.compile(r'^(\s*snmp-server\s+contact\s+).*$', _F)
DESCRIPTION_RX = re.compile(r'^(\s*description\s+)(.*)$', _F)

# Identifier captures (collection pass)
HOSTNAME_RX = re.compile(r'^\s*(?:hostname|switchname|sysname)\s+(\S+)\s*$', _F)
DOMAIN_RX = re.compile(r'^\s*(?:ip\s+)?(?:domain[\s-](?:name|list)|dns\s+domain)\s+'
                       r'(?:vrf\s+\S+\s+)?(\S+)\s*$', _F)

# PEM block / banner / hex blob
PEM_BEGIN_RX = re.compile(r'-----BEGIN [^-]+-----')
PEM_END_RX = re.compile(r'-----END [^-]+-----')
BANNER_RX = re.compile(r'^(\s*banner\s+\S+)\s?(.*)$', _F)

EMAIL_RX = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')

# Addresses
IPV4_RX = re.compile(r'(?<![\w.])((?:\d{1,3}\.){3}\d{1,3})(/\d{1,2})?(?![\w.])')
IPV6_RX = re.compile(
    r'(?<![:\w.])('
    r'(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}'
    r'|(?:[A-Fa-f0-9]{1,4}:){1,7}:'
    r'|(?:[A-Fa-f0-9]{1,4}:){1,6}:[A-Fa-f0-9]{1,4}'
    r'|(?:[A-Fa-f0-9]{1,4}:){1,5}(?::[A-Fa-f0-9]{1,4}){1,2}'
    r'|(?:[A-Fa-f0-9]{1,4}:){1,4}(?::[A-Fa-f0-9]{1,4}){1,3}'
    r'|(?:[A-Fa-f0-9]{1,4}:){1,3}(?::[A-Fa-f0-9]{1,4}){1,4}'
    r'|(?:[A-Fa-f0-9]{1,4}:){1,2}(?::[A-Fa-f0-9]{1,4}){1,5}'
    r'|[A-Fa-f0-9]{1,4}:(?::[A-Fa-f0-9]{1,4}){1,6}'
    r'|:(?::[A-Fa-f0-9]{1,4}){1,7}'
    r'|::'
    r')(/\d{1,3})?(?![:\w.])'
)
MAC_DOT_RX = re.compile(r'(?<![\w.])([0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4})(?![\w.])')
MAC_COLON_RX = re.compile(r'(?<![\w:.])((?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})(?![\w:.])')

NET0_8 = ipaddress.ip_network("0.0.0.0/8")

# Well-known virtual MACs, kept (hex prefixes without separators):
# HSRP 0000.0c07.acXX / HSRPv2 0000.0c9f.fXXX / VRRP 0000.5e00.01XX /
# GLBP 0007.b40X.XXXX
KEEP_MAC_PREFIXES = ("00000c07ac", "00000c9ff", "00005e0001", "0007b4")

# Residual-secret detection (output safety net)
RESIDUAL_RX = re.compile(
    r'\b(password|passwd|secret|community|key-string|pre-shared|passphrase|'
    r'private-key|psk)\b', _F)
# Values that look like a hash/key, even on an already-marked line
# (crypt/type5/8/9 hashes: $1$..., $6$..., $8$..., $9$... ; hex blobs 0x...)
RESIDUAL_VALUE_RX = re.compile(r'\$(?:1|2[aby]?|5|6|8|9)\$\S{6,}|\b0x[0-9A-Fa-f]{16,}\b')


# ---------------------------------------------------------------------------
class Anonymizer:
    def __init__(self, anon_all_ips=False, keep_descriptions=False, keep_macs=False):
        self.anon_all_ips = anon_all_ips
        self.keep_descriptions = keep_descriptions
        self.keep_macs = keep_macs

        # Mapping tables (identifiers only)
        self.hosts = {}
        self.domains = {}
        self.ipv4 = {}
        self.ipv6 = {}
        self.macs = {}
        self.descriptions = {}

        # Counters / pools
        self._host_c = count(1)
        self._domain_c = count(1)
        self._desc_c = count(1)
        self._ipv4_pool = self._hosts_of(
            "198.51.100.0/24", "203.0.113.0/24", "192.0.2.0/24",
            "198.18.0.0/15")                     # RFC 2544 overflow (>760 IPs)
        self._ipv6_pool = (ipaddress.ip_address("2001:db8::") + i for i in count(1))
        self._mac_c = count(1)

        # Normalized keys -> alias (the same address written in several ways
        # always receives the same alias)
        self._ipv4_norm = {}
        self._ipv6_norm = {}
        self._mac_norm = {}

        # Word-for-word replacement (filled during the collection pass)
        self._word_map = {}          # alias <- original term (lowercase key)
        self._word_rx = None         # terms with letters: '.' allowed at edges (FQDN)
        self._word_rx_strict = None  # letterless terms: strict boundaries

        # Stats
        self.stats = {"secrets": 0, "banners": 0, "certs": 0,
                      "emails": 0, "locations": 0, "contacts": 0}

    # --- pools / allocations ------------------------------------------------
    @staticmethod
    def _hosts_of(*nets):
        for net in nets:
            for host in ipaddress.ip_network(net).hosts():
                yield host

    def _alloc_ipv4(self, original, ip):
        key = str(ip)
        if key not in self._ipv4_norm:
            try:
                self._ipv4_norm[key] = str(next(self._ipv4_pool))
            except StopIteration:                # pool exhausted (>130,000 IPs!)
                self._ipv4_norm[key] = "198.19.255.254"
        alias = self._ipv4_norm[key]
        self.ipv4[original] = alias
        return alias

    def _alloc_ipv6(self, original, ip):
        key = ip.compressed.lower()
        if key not in self._ipv6_norm:
            self._ipv6_norm[key] = str(next(self._ipv6_pool))
        alias = self._ipv6_norm[key]
        self.ipv6[original] = alias
        return alias

    def _alloc_mac(self, original, sep_dot):
        digits = "".join(ch for ch in original if ch not in ".:").lower()
        # Multicast/broadcast, all-zero or well-known virtual MAC: keep
        # (they carry protocol meaning and are not identifying)
        if int(digits[:2], 16) & 1 or digits == "000000000000" \
                or digits.startswith(KEEP_MAC_PREFIXES):
            return original
        if digits not in self._mac_norm:
            # locally-administered OUI (U/L bit set) -> matches no real hardware
            self._mac_norm[digits] = "02%010x" % next(self._mac_c)
        raw = self._mac_norm[digits]
        if sep_dot:
            fake = f"{raw[0:4]}.{raw[4:8]}.{raw[8:12]}"
        else:
            fake = ":".join(raw[i:i + 2] for i in range(0, 12, 2))
        self.macs[original] = fake
        return fake

    # --- should an IP be kept as-is? -----------------------------------------
    def _keep_ip(self, ip):
        if ip.version == 4 and ip in NET0_8:
            return True
        if (ip.is_multicast or ip.is_loopback or ip.is_link_local
                or ip.is_unspecified or ip.is_reserved):
            return True
        if self.anon_all_ips:
            return False
        return not ip.is_global

    # --- pass 1: collect hostnames / domains ---------------------------------
    def collect(self, lines):
        seen_hosts, seen_domains = set(), set()
        for ln in lines:
            m = HOSTNAME_RX.match(ln)
            if m and m.group(1).lower() not in seen_hosts:
                seen_hosts.add(m.group(1).lower())
                self.hosts[m.group(1)] = f"device-{next(self._host_c)}"
            m = DOMAIN_RX.match(ln)
            if m and m.group(1).lower() not in seen_domains:
                seen_domains.add(m.group(1).lower())
                self.domains[m.group(1)] = f"example-{next(self._domain_c)}.net"

        for original, alias in {**self.hosts, **self.domains}.items():
            self._word_map[original.lower()] = alias

        # Two regexes: terms containing letters accept a '.' at their edges
        # (to catch "host.domain.tld" FQDNs), purely numeric terms keep
        # strict boundaries (must not match inside an IP address). Longest
        # terms first (substrings).
        relaxed = [t for t in self._word_map if re.search(r'[a-z]', t)]
        strict = [t for t in self._word_map if t not in relaxed]

        def build(terms, before, after):
            if not terms:
                return None
            alts = "|".join(re.escape(t)
                            for t in sorted(terms, key=len, reverse=True))
            return re.compile(before + "(" + alts + ")" + after, _F)

        self._word_rx = build(relaxed, r'(?<![\w-])', r'(?![\w-])')
        self._word_rx_strict = build(strict, r'(?<![\w.-])', r'(?![\w.-])')

    # --- unit replacements ----------------------------------------------------
    def _sub_words(self, line):
        for rx in (self._word_rx, self._word_rx_strict):
            if rx:
                line = rx.sub(lambda m: self._word_map[m.group(1).lower()], line)
        return line

    def _sub_ipv4(self, line):
        def repl(m):
            addr, prefix = m.group(1), m.group(2) or ""
            try:
                ip = ipaddress.ip_address(addr)
            except ValueError:
                return m.group(0)
            if self._keep_ip(ip):
                return m.group(0)
            return self._alloc_ipv4(addr, ip) + prefix
        return IPV4_RX.sub(repl, line)

    def _sub_ipv6(self, line):
        def repl(m):
            addr, prefix = m.group(1), m.group(2) or ""
            try:
                ip = ipaddress.ip_address(addr)
            except ValueError:
                return m.group(0)
            if ip.version != 6 or self._keep_ip(ip):
                return m.group(0)
            return self._alloc_ipv6(addr, ip) + prefix
        return IPV6_RX.sub(repl, line)

    def _sub_macs(self, line):
        line = MAC_DOT_RX.sub(lambda m: self._alloc_mac(m.group(1), True), line)
        line = MAC_COLON_RX.sub(lambda m: self._alloc_mac(m.group(1), False), line)
        return line

    def _sub_description(self, line):
        m = DESCRIPTION_RX.match(line)
        if not m:
            return line
        text = m.group(2)
        if text not in self.descriptions:
            self.descriptions[text] = ph(f"DESCRIPTION-{next(self._desc_c)}")
        return m.group(1) + self.descriptions[text]

    # --- transformation of a "normal" line ------------------------------------
    def transform_line(self, line):
        # 1) destroy secrets
        for rx, repl in SECRET_RULES:
            new = rx.sub(repl, line)
            if new != line:
                self.stats["secrets"] += 1
                line = new
        # 2) location / contact -> marker
        if LOCATION_RX.match(line):
            self.stats["locations"] += 1
            return LOCATION_RX.sub(r'\1' + S_LOCATION, line)
        if CONTACT_RX.match(line):
            self.stats["contacts"] += 1
            return CONTACT_RX.sub(r'\1' + S_CONTACT, line)
        # 3) descriptions
        if not self.keep_descriptions:
            line = self._sub_description(line)
        # 4) e-mails
        if EMAIL_RX.search(line):
            self.stats["emails"] += len(EMAIL_RX.findall(line))
            line = EMAIL_RX.sub(S_EMAIL, line)
        # 5) hostnames / domains (word-for-word, consistent)
        line = self._sub_words(line)
        # 6) addresses
        line = self._sub_ipv4(line)
        line = self._sub_ipv6(line)
        if not self.keep_macs:
            line = self._sub_macs(line)
        return line

    # --- pass 2: processing with multi-line block handling --------------------
    def process(self, lines):
        out = []
        i, n = 0, len(lines)
        while i < n:
            line = lines[i]
            stripped = line.strip()

            # PEM block
            if PEM_BEGIN_RX.search(line):
                out.append(self._indent(line) + S_CERT)
                self.stats["certs"] += 1
                i += 1
                while i < n and not PEM_END_RX.search(lines[i]):
                    i += 1
                i += 1                              # skip the END line
                continue

            # banner
            mb = BANNER_RX.match(line)
            if mb:
                head, rest = mb.group(1), mb.group(2)
                self.stats["banners"] += 1
                rest_s = rest.strip()
                if rest_s:
                    # delimiter: a single char, or a "^X" sequence (e.g. ^C)
                    if rest_s.startswith("^") and len(rest_s) >= 2 and rest_s[1].isalpha():
                        delim = rest_s[:2]
                    else:
                        delim = rest_s[0]
                    # single-line banner: delimiter present twice
                    if rest_s.count(delim) >= 2:
                        out.append(f"{head} {delim}{S_BANNER}{delim}")
                        i += 1
                        continue
                    out.append(f"{head} {delim}{S_BANNER}{delim}")
                    i += 1
                    while i < n and delim not in lines[i]:
                        i += 1
                    i += 1                          # skip the closing line
                    continue
                else:
                    # EOS style: terminated by an "EOF" line
                    out.append(f"{head} ^C{S_BANNER}^C")
                    i += 1
                    while i < n and lines[i].strip() != "EOF":
                        i += 1
                    i += 1
                    continue

            # hex blob (IOS certificate / key)
            if self._is_hexblob(stripped):
                out.append(self._indent(line) + S_CERT)
                self.stats["certs"] += 1
                i += 1
                while i < n:
                    s = lines[i].strip()
                    if self._is_hexblob(s):
                        i += 1
                        continue
                    if s == "quit":
                        i += 1
                    break
                continue

            # normal line
            out.append(self.transform_line(line))
            i += 1
        return out

    # --- helpers --------------------------------------------------------------
    @staticmethod
    def _indent(line):
        return line[:len(line) - len(line.lstrip())]

    @staticmethod
    def _is_hexblob(stripped):
        if len(stripped) < 16:
            return False
        compact = stripped.replace(" ", "")
        return bool(compact) and re.fullmatch(r'[0-9A-Fa-f]+', compact) is not None

    def mapping(self):
        return {
            "_warning": ("Mapping table used to DE-anonymize the AI's answers. "
                         "KEEP THIS FILE LOCAL. Never send it to the AI or to "
                         "any third party."),
            "hosts": self.hosts,
            "domains": self.domains,
            "ipv4": self.ipv4,
            "ipv6": self.ipv6,
            "macs": self.macs if not self.keep_macs else {},
            "descriptions": self.descriptions if not self.keep_descriptions else {},
        }


# ---------------------------------------------------------------------------
def residual_warnings(lines, limit=20):
    """Spot output lines that still look like a secret (to be reviewed)."""
    flagged = []
    for idx, ln in enumerate(lines, 1):
        # suspicious keywords on an unprocessed line, OR a value that looks
        # like a hash/key even on an already-marked line
        suspicious = RESIDUAL_VALUE_RX.search(ln) or (
            "<SANITIZED" not in ln and RESIDUAL_RX.search(ln))
        if suspicious:
            flagged.append((idx, ln.rstrip()))
            if len(flagged) >= limit:
                break
    return flagged


def main():
    p = argparse.ArgumentParser(
        prog="netanom",
        description="Sanitize a Cisco/Arista configuration before sharing it "
                    "with an AI (or any third party).")
    p.add_argument("input", nargs="?", default="-",
                   help="Configuration file ('-' or empty for stdin).")
    p.add_argument("-o", "--output", default="-",
                   help="Output file (default: stdout).")
    p.add_argument("-m", "--map", dest="mapfile", default=None,
                   help="Write the JSON mapping table (keep it local, never share it).")
    p.add_argument("--anonymize-all-ips", action="store_true",
                   help="Also anonymize private (RFC 1918) addresses, not only public ones.")
    p.add_argument("--keep-descriptions", action="store_true",
                   help="Keep interface descriptions as-is (e-mails/IPs/hostnames "
                        "inside them are still processed).")
    p.add_argument("--keep-macs", action="store_true",
                   help="Keep MAC addresses as-is.")
    p.add_argument("--no-summary", action="store_true",
                   help="Do not print the summary on stderr.")
    p.add_argument("--strict", action="store_true",
                   help="Exit with status 2 if suspicious residual lines remain "
                        "(useful in CI pipelines).")
    p.add_argument("--version", action="version",
                   version=f"%(prog)s {__version__}")
    args = p.parse_args()

    # read
    if args.input == "-":
        data = sys.stdin.read()
    else:
        try:
            with open(args.input, "r", encoding="utf-8", errors="replace") as f:
                data = f.read()
        except OSError as e:
            sys.exit(f"netanom: cannot read input: {e}")
    lines = data.splitlines()

    anon = Anonymizer(anon_all_ips=args.anonymize_all_ips,
                      keep_descriptions=args.keep_descriptions,
                      keep_macs=args.keep_macs)
    anon.collect(lines)
    result = anon.process(lines)

    # write
    body = "\n".join(result) + ("\n" if data.endswith("\n") else "")
    if args.output == "-":
        sys.stdout.write(body)
    else:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(body)
        except OSError as e:
            sys.exit(f"netanom: cannot write output: {e}")

    if args.mapfile:
        try:
            with open(args.mapfile, "w", encoding="utf-8") as f:
                json.dump(anon.mapping(), f, ensure_ascii=False, indent=2)
        except OSError as e:
            sys.exit(f"netanom: cannot write mapping file: {e}")

    flagged = residual_warnings(result)

    # summary + residual alert (on stderr, keeping stdout clean)
    if not args.no_summary:
        s = anon.stats
        print("--- Sanitization summary ---", file=sys.stderr)
        print(f"  Secrets destroyed        : {s['secrets']}", file=sys.stderr)
        print(f"  Banners                  : {s['banners']}", file=sys.stderr)
        print(f"  Certificates / keys      : {s['certs']}", file=sys.stderr)
        print(f"  E-mail addresses         : {s['emails']}", file=sys.stderr)
        print(f"  Locations / contacts     : {s['locations']} / {s['contacts']}", file=sys.stderr)
        print(f"  Hostnames pseudonymized  : {len(anon.hosts)}", file=sys.stderr)
        print(f"  Domains                  : {len(anon.domains)}", file=sys.stderr)
        print(f"  IPv4 / IPv6              : {len(anon.ipv4)} / {len(anon.ipv6)}", file=sys.stderr)
        print(f"  MAC addresses            : {len(anon.macs)}", file=sys.stderr)
        print(f"  Descriptions             : {len(anon.descriptions)}", file=sys.stderr)

        if flagged:
            print("\n  /!\\ Lines to REVIEW (potential secret not neutralized):",
                  file=sys.stderr)
            for idx, ln in flagged:
                print(f"     L{idx}: {ln}", file=sys.stderr)
        else:
            print("\n  No residual secret detected by the heuristic.",
                  file=sys.stderr)

    if args.strict and flagged:
        sys.exit(2)


if __name__ == "__main__":
    main()

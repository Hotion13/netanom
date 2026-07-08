#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sanitize_netconfig.py — Anonymiseur de configurations reseau
============================================================

Cible : Cisco (IOS / IOS-XE / NX-OS) et Arista EOS.
But    : retirer ou pseudonymiser les informations sensibles d'un fichier de
         configuration AVANT de le transmettre a une IA (ou tout tiers), sans
         casser la coherence interne necessaire a une analyse.

Deux familles de traitement
---------------------------
1. SECRETS  -> DESTRUCTION. La vraie valeur est remplacee par un marqueur
   (ex. <SANITIZED-SECRET>) et n'est jamais conservee nulle part. On garde
   quand meme l'indice d'algorithme (type 7, type 9, sha512, RO/RW, ACL...)
   car c'est une info de securite utile et NON confidentielle.

2. IDENTIFIANTS -> PSEUDONYMISATION COHERENTE. Une meme valeur d'origine est
   toujours remplacee par le meme alias (host-1, 198.51.100.x, example-1.net...)
   afin que les relations du fichier restent exploitables par l'IA. La table de
   correspondance peut etre ecrite dans un fichier .map.json a CONSERVER EN
   LOCAL : elle permet de re-appliquer ensuite les recommandations de l'IA a la
   vraie configuration. Ce fichier ne doit JAMAIS etre transmis a l'IA.

Ce qui est neutralise
---------------------
SECRETS DETRUITS :
  - enable secret / enable password (tous types : 0,5,7,8,9, sha512)
  - username ... secret/password (incl. EOS "secret sha512")
  - cles publiques SSH des comptes (username ... sshkey ...) : identifiantes
  - mots de passe de lignes (line con/vty/aux : password ...)
  - communautes SNMP (snmp-server community) + communaute dans snmp-server
    host (y compris formes vrf / use-vrf / traps / informs / version 1|2c|3)
  - cles SNMPv3 (auth md5/sha[-]..., priv des/aes[-128...], formes NX-OS 0x...)
  - cles TACACS+ / RADIUS (tacacs-server key, radius-server ... key, blocs
    "radius server X" / "tacacs server X" avec "key" indente, key 7 ...)
  - cle maitre de chiffrement (key config-key password-encrypt)
  - cles pre-partagees VPN (crypto isakmp key [0|6|encrypted], pre-shared-key)
  - authentification de voisinage / routage (neighbor ... password, OSPF
    message-digest-key md5, authentication-key, authentication text,
    IS-IS isis password / area-password / domain-password)
  - authentification FHRP en clair (standby / vrrp ... authentication)
  - key-string (key chains)
  - PPP CHAP/PAP, ip ftp password, ip http client password,
    cle d'authentification NTP
  - certificats PKI (blocs hex IOS) et blocs PEM (-----BEGIN...-----END-----)
  - bannieres (banner motd/login/exec ...) souvent porteuses d'infos org/legales
  - adresses e-mail

IDENTIFIANTS PSEUDONYMISES (coherents) :
  - hostname / switchname / sysname  -> device-N (remplace partout, insensible
    a la casse, y compris au sein d'un FQDN "hote.domaine")
  - domaine (ip domain-name / domain list / dns domain / domain-name DHCP)
    -> example-N.net (remplace partout, y compris en suffixe de FQDN)
  - adresses IPv4 publiques -> plages de documentation RFC 5737, puis
    198.18.0.0/15 (RFC 2544) si plus de ~760 adresses distinctes
  - adresses IPv6 publiques -> 2001:db8::/32 (RFC 3849)
  - adresses MAC -> MAC d'administration locale fictive (format conserve,
    coherent entre notations aabb.ccdd.eeff et aa:bb:cc:dd:ee:ff) ; les MAC
    multicast/broadcast et les MAC virtuelles bien connues (HSRP, VRRP,
    GLBP) sont conservees car porteuses de sens et non identifiantes
  - descriptions d'interface -> jeton coherent (option --keep-descriptions)
  - snmp-server location / contact -> marqueur (adresse, tel, nom => sensibles)

Limites (IMPORTANT)
-------------------
Outil "best effort" base sur des motifs. Il ne remplace PAS une relecture
humaine. Pensez en particulier a verifier manuellement : noms de VRF, de
route-map, d'ACL, de trustpoint, numeros de serie/licence, identifiants de
circuit dans les descriptions, jetons d'agents EOS (daemon TerminAttr...),
cles PSK WLAN, snmp engineID, valeurs numeriques pures apres "key" (ambigues
avec un numero de cle de key chain), et tout secret a syntaxe exotique.
Les masques/prefixes ne sont pas recalcules : une adresse reseau remplacee
peut devenir une adresse hote (la coherence de sous-reseau n'est pas
garantie). Le script affiche en fin de traitement les lignes residuelles qui
ressemblent encore a un secret : relisez-les.

Usage
-----
  python3 sanitize_netconfig.py config.txt -o config.san.txt -m config.map.json
  cat config.txt | python3 sanitize_netconfig.py - > config.san.txt
  python3 sanitize_netconfig.py config.txt --anonymize-all-ips --keep-descriptions
  python3 sanitize_netconfig.py config.txt --strict   # code retour 2 si residu
"""

import argparse
import ipaddress
import json
import re
import sys
from itertools import count

__version__ = "0.2.0"

# ---------------------------------------------------------------------------
# Marqueurs
# ---------------------------------------------------------------------------
def ph(category: str) -> str:
    """Retourne un marqueur de censure homogene pour une categorie donnee."""
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
# Regles de DESTRUCTION des secrets
# Chaque regle = (regex compilee, chaine de remplacement).
# Convention : on conserve la "directive" + l'indice d'algorithme via des
# groupes capturants, on detruit uniquement la valeur sensible.
# ORDRE IMPORTANT : du plus specifique au plus generique. La regle inline
# "key <type> <valeur>" est volontairement en DERNIER et ne matche jamais a
# l'interieur d'une directive suffixee en -key (message-digest-key, etc.),
# sinon elle detruirait le jeton d'algorithme et laisserait fuir le secret.
# ---------------------------------------------------------------------------
_F = re.IGNORECASE
SECRET_RULES = [
    # enable secret/password [level N] [0|5|7|8|9|sha512...] <valeur>
    (re.compile(r'^(\s*enable\s+(?:secret|password)(?:\s+level\s+\d+)?'
                r'(?:\s+(?:0|5|7|8|9|sha512|sha256|md5))?\s+)\S+.*$', _F),
     r'\1' + S_SECRET),

    # username X [privilege N] [role ...] secret|password [algo] <hash> [reste]
    (re.compile(r'^(\s*username\s+\S+\s+.*?\b(?:secret|password)'
                r'(?:\s+(?:sha512|sha256|md5|0|5|7|8|9))?\s+)(\S+)(.*)$', _F),
     r'\1' + S_SECRET + r'\3'),
    # cle publique SSH d'un compte (EOS "username X sshkey ssh-rsa ...") :
    # pas un secret, mais identifiante (commentaire, correlation possible)
    (re.compile(r'^(\s*username\s+\S+\s+ssh-?key\s+).*$', _F),
     r'\1' + S_SSHKEY),

    # mot de passe de ligne ou generique : password [type] <valeur>
    (re.compile(r'^(\s*password\s+(?:\d\s+)?)\S+.*$', _F),
     r'\1' + S_SECRET),
    # secret nu (rare hors username) : secret [algo] <valeur>
    (re.compile(r'^(\s*secret\s+(?:sha512\s+|sha256\s+|\d\s+)?)\S+.*$', _F),
     r'\1' + S_SECRET),

    # SNMP : communaute  (on garde RO/RW + ACL eventuelle)
    (re.compile(r'^(\s*snmp-server\s+community\s+)\S+(.*)$', _F),
     r'\1' + S_COMMUNITY + r'\2'),
    # SNMP host : toutes formes IOS/NX-OS/EOS. On saute les mots-cles connus
    # (vrf X, use-vrf X, traps, informs, version X, auth/noauth/priv) puis on
    # detruit le jeton suivant = communaute (ou utilisateur v3, identifiant).
    (re.compile(r'^(\s*snmp-server\s+host\s+\S+'
                r'(?:\s+(?:(?:vrf|use-vrf|filter-vrf|version)\s+\S+'
                r'|traps|informs|auth|noauth|priv))*'
                r'\s+)(?!(?:vrf|use-vrf|filter-vrf|version|traps|informs'
                r'|auth|noauth|priv|udp-port)\b)(\S+)(.*)$', _F),
     r'\1' + S_COMMUNITY + r'\3'),
    # SNMPv3 : auth md5|sha|sha-256... <cle>  /  priv des|3des|aes[- ]128... <cle>
    (re.compile(r'(\bauth\s+(?:md5|sha-?(?:512|384|256|224)?)\s+)(\S+)', _F),
     r'\1' + S_SECRET),
    (re.compile(r'(\bpriv\s+(?:des|3des|aes(?:[\s-]+(?:128|192|256))?)\s+)(\S+)', _F),
     r'\1' + S_SECRET),
    # forme NX-OS localisee : priv 0x<hex> (sans mot-cle d'algo)
    (re.compile(r'(\bpriv\s+)(0x[0-9A-Fa-f]+)', _F),
     r'\1' + S_SECRET),

    # TACACS+ / RADIUS : ligne globale, quel que soit ce qui precede "key"
    # (host, auth-port, acct-port, timeout...)
    (re.compile(r'^(\s*(?:tacacs|radius)-server\s+.*?\bkey\s+(?:\d\s+)?)\S.*$', _F),
     r'\1' + S_SECRET),
    # cle maitre de chiffrement des mots de passe (AES password encryption)
    (re.compile(r'^(\s*key\s+config-key\s+password-encrypt\s+)\S.*$', _F),
     r'\1' + S_SECRET),
    # "key [type] <valeur>" en debut de ligne (blocs "radius server X" /
    # "tacacs server X"). Ne touche ni "key chain X", ni un numero de cle
    # de key chain ("key 1"), ni "key config-key ..." (regle dediee ci-dessus).
    (re.compile(r'^(\s*key\s+(?:\d\s+)?)(?!chain\b|config-key\b|\d+\s*$)\S.*$', _F),
     r'\1' + S_SECRET),

    # VPN / IPsec
    (re.compile(r'^(\s*crypto\s+isakmp\s+key\s+(?:[06]\s+)?)(\S+)(.*)$', _F),
     r'\1' + S_SECRET + r'\3'),
    (re.compile(r'(\bpre-shared-key\s+(?:(?:local|remote|encrypted)\s+)?(?:\d\s+)?)'
                r'(?!address\b|hostname\b)(\S+)', _F),
     r'\1' + S_SECRET),

    # Routage : BGP / OSPF / divers
    (re.compile(r'(\bneighbor\s+\S+\s+password\s+(?:\d\s+)?)(\S+)', _F),
     r'\1' + S_SECRET),
    (re.compile(r'(\bmessage-digest-key\s+\d+\s+md5\s+(?:\d\s+)?)(\S+)', _F),
     r'\1' + S_SECRET),
    (re.compile(r'(\bauthentication-key\s+(?:\d\s+)?)(\S+)\s*$', _F),
     r'\1' + S_SECRET),
    (re.compile(r'(\bauthentication\s+text\s+)(\S+)', _F),
     r'\1' + S_SECRET),
    # IS-IS : isis password / area-password / domain-password [hmac-md5] <pw>
    (re.compile(r'^(\s*(?:isis\s+password|(?:area|domain)-password)\s+'
                r'(?:hmac-md5\s+)?)(\S+)(.*)$', _F),
     r'\1' + S_SECRET + r'\3'),
    # FHRP : standby/vrrp ... authentication <pw-en-clair>
    # (les formes md5/text/key-string/key-chain sont gerees par d'autres regles)
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

    # Generique inline "... key <type> <valeur>" — EN DERNIER. Le lookbehind
    # interdit le match au sein de "message-digest-key", "authentication-key",
    # "pre-shared-key", etc. (directives deja traitees plus haut).
    (re.compile(r'((?<![\w-])key\s+(?:0|5|7|8|9)\s+)(\S+)', _F),
     r'\1' + S_SECRET),
]

# Regles "valeur libre" -> marqueur (pas de pseudonymisation, on detruit)
LOCATION_RX = re.compile(r'^(\s*snmp-server\s+location\s+).*$', _F)
CONTACT_RX = re.compile(r'^(\s*snmp-server\s+contact\s+).*$', _F)
DESCRIPTION_RX = re.compile(r'^(\s*description\s+)(.*)$', _F)

# Captures d'identifiants (passe de collecte)
HOSTNAME_RX = re.compile(r'^\s*(?:hostname|switchname|sysname)\s+(\S+)\s*$', _F)
DOMAIN_RX = re.compile(r'^\s*(?:ip\s+)?(?:domain[\s-](?:name|list)|dns\s+domain)\s+'
                       r'(?:vrf\s+\S+\s+)?(\S+)\s*$', _F)

# Bloc PEM / banniere / blob hex
PEM_BEGIN_RX = re.compile(r'-----BEGIN [^-]+-----')
PEM_END_RX = re.compile(r'-----END [^-]+-----')
BANNER_RX = re.compile(r'^(\s*banner\s+\S+)\s?(.*)$', _F)

EMAIL_RX = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')

# Adresses
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

# MAC virtuelles bien connues, conservees (prefixes hex sans separateur) :
# HSRP 0000.0c07.acXX / HSRPv2 0000.0c9f.fXXX / VRRP 0000.5e00.01XX /
# GLBP 0007.b40X.XXXX
KEEP_MAC_PREFIXES = ("00000c07ac", "00000c9ff", "00005e0001", "0007b4")

# Detection de secrets residuels (filet de securite en sortie)
RESIDUAL_RX = re.compile(
    r'\b(password|passwd|secret|community|key-string|pre-shared|passphrase|'
    r'private-key|psk)\b', _F)
# Valeurs qui ressemblent a un hash/une cle, meme sur une ligne deja marquee
# (hash crypt/type5/8/9 : $1$..., $6$..., $8$..., $9$... ; blobs hex 0x...)
RESIDUAL_VALUE_RX = re.compile(r'\$(?:1|2[aby]?|5|6|8|9)\$\S{6,}|\b0x[0-9A-Fa-f]{16,}\b')


# ---------------------------------------------------------------------------
class Anonymizer:
    def __init__(self, anon_all_ips=False, keep_descriptions=False, keep_macs=False):
        self.anon_all_ips = anon_all_ips
        self.keep_descriptions = keep_descriptions
        self.keep_macs = keep_macs

        # Tables de correspondance (identifiants uniquement)
        self.hosts = {}
        self.domains = {}
        self.ipv4 = {}
        self.ipv6 = {}
        self.macs = {}
        self.descriptions = {}

        # Compteurs / pools
        self._host_c = count(1)
        self._domain_c = count(1)
        self._desc_c = count(1)
        self._ipv4_pool = self._hosts_of(
            "198.51.100.0/24", "203.0.113.0/24", "192.0.2.0/24",
            "198.18.0.0/15")                      # extension RFC 2544 si >760 IP
        self._ipv6_pool = (ipaddress.ip_address("2001:db8::") + i for i in count(1))
        self._mac_c = count(1)

        # Cles normalisees -> alias (une meme adresse sous plusieurs ecritures
        # recoit toujours le meme alias)
        self._ipv4_norm = {}
        self._ipv6_norm = {}
        self._mac_norm = {}

        # Remplacement mot-pour-mot (rempli en passe de collecte)
        self._word_map = {}          # alias <- terme original (cle en minuscules)
        self._word_rx = None         # termes avec lettres : bordure '.' toleree (FQDN)
        self._word_rx_strict = None  # termes sans lettre : bordures strictes

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
            except StopIteration:                   # pool epuise (>130 000 IP !)
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
        # MAC multicast/broadcast, nulle ou virtuelle bien connue : on conserve
        # (porteuses de sens protocolaire, non identifiantes)
        if int(digits[:2], 16) & 1 or digits == "000000000000" \
                or digits.startswith(KEEP_MAC_PREFIXES):
            return original
        if digits not in self._mac_norm:
            # OUI d'administration locale (bit U/L a 1) -> aucun vrai materiel
            self._mac_norm[digits] = "02%010x" % next(self._mac_c)
        raw = self._mac_norm[digits]
        if sep_dot:
            fake = f"{raw[0:4]}.{raw[4:8]}.{raw[8:12]}"
        else:
            fake = ":".join(raw[i:i + 2] for i in range(0, 12, 2))
        self.macs[original] = fake
        return fake

    # --- decision de conservation d'une IP ----------------------------------
    def _keep_ip(self, ip):
        if ip.version == 4 and ip in NET0_8:
            return True
        if (ip.is_multicast or ip.is_loopback or ip.is_link_local
                or ip.is_unspecified or ip.is_reserved):
            return True
        if self.anon_all_ips:
            return False
        return not ip.is_global

    # --- passe 1 : collecte hostnames / domaines ----------------------------
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

        # Deux regex : les termes contenant des lettres acceptent un '.' en
        # bordure (pour attraper les FQDN "hote.domaine.tld"), les termes
        # purement numeriques gardent des bordures strictes (ne pas matcher
        # dans une adresse IP). Termes les plus longs d'abord (sous-chaines).
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

    # --- remplacements unitaires --------------------------------------------
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

    # --- transformation d'une ligne "normale" -------------------------------
    def transform_line(self, line):
        # 1) destruction des secrets
        for rx, repl in SECRET_RULES:
            new = rx.sub(repl, line)
            if new != line:
                self.stats["secrets"] += 1
                line = new
        # 2) location / contact -> marqueur
        if LOCATION_RX.match(line):
            self.stats["locations"] += 1
            return LOCATION_RX.sub(r'\1' + S_LOCATION, line)
        if CONTACT_RX.match(line):
            self.stats["contacts"] += 1
            return CONTACT_RX.sub(r'\1' + S_CONTACT, line)
        # 3) descriptions
        if not self.keep_descriptions:
            line = self._sub_description(line)
        # 4) emails
        if EMAIL_RX.search(line):
            self.stats["emails"] += len(EMAIL_RX.findall(line))
            line = EMAIL_RX.sub(S_EMAIL, line)
        # 5) hostnames / domaines (mot-pour-mot, coherent)
        line = self._sub_words(line)
        # 6) adresses
        line = self._sub_ipv4(line)
        line = self._sub_ipv6(line)
        if not self.keep_macs:
            line = self._sub_macs(line)
        return line

    # --- passe 2 : traitement avec gestion des blocs multi-lignes -----------
    def process(self, lines):
        out = []
        i, n = 0, len(lines)
        while i < n:
            line = lines[i]
            stripped = line.strip()

            # bloc PEM
            if PEM_BEGIN_RX.search(line):
                out.append(self._indent(line) + S_CERT)
                self.stats["certs"] += 1
                i += 1
                while i < n and not PEM_END_RX.search(lines[i]):
                    i += 1
                i += 1                              # saute la ligne END
                continue

            # banniere
            mb = BANNER_RX.match(line)
            if mb:
                head, rest = mb.group(1), mb.group(2)
                self.stats["banners"] += 1
                rest_s = rest.strip()
                if rest_s:
                    # delimiteur : un seul char, ou sequence "^X" (ex. ^C)
                    if rest_s.startswith("^") and len(rest_s) >= 2 and rest_s[1].isalpha():
                        delim = rest_s[:2]
                    else:
                        delim = rest_s[0]
                    # banniere mono-ligne : delimiteur present 2 fois
                    if rest_s.count(delim) >= 2:
                        out.append(f"{head} {delim}{S_BANNER}{delim}")
                        i += 1
                        continue
                    out.append(f"{head} {delim}{S_BANNER}{delim}")
                    i += 1
                    while i < n and delim not in lines[i]:
                        i += 1
                    i += 1                          # saute la ligne de fin
                    continue
                else:
                    # style EOS : termine par une ligne "EOF"
                    out.append(f"{head} ^C{S_BANNER}^C")
                    i += 1
                    while i < n and lines[i].strip() != "EOF":
                        i += 1
                    i += 1
                    continue

            # blob hexa (certificat / cle IOS)
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

            # ligne normale
            out.append(self.transform_line(line))
            i += 1
        return out

    # --- utilitaires --------------------------------------------------------
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
            "_avertissement": ("Fichier de correspondance pour DE-anonymiser les "
                               "reponses de l'IA. A CONSERVER EN LOCAL. Ne jamais "
                               "transmettre a l'IA ou a un tiers."),
            "hosts": self.hosts,
            "domains": self.domains,
            "ipv4": self.ipv4,
            "ipv6": self.ipv6,
            "macs": self.macs if not self.keep_macs else {},
            "descriptions": self.descriptions if not self.keep_descriptions else {},
        }


# ---------------------------------------------------------------------------
def residual_warnings(lines, limit=20):
    """Repere les lignes qui ressemblent encore a un secret (a relire)."""
    flagged = []
    for idx, ln in enumerate(lines, 1):
        # mots-cles suspects sur une ligne non traitee, OU valeur qui
        # ressemble a un hash/une cle meme sur une ligne deja marquee
        suspicious = RESIDUAL_VALUE_RX.search(ln) or (
            "<SANITIZED" not in ln and RESIDUAL_RX.search(ln))
        if suspicious:
            flagged.append((idx, ln.rstrip()))
            if len(flagged) >= limit:
                break
    return flagged


def main():
    p = argparse.ArgumentParser(
        description="Anonymise une configuration Cisco/Arista pour ingestion par une IA.")
    p.add_argument("input", nargs="?", default="-",
                   help="Fichier de config (ou '-' / vide pour stdin).")
    p.add_argument("-o", "--output", default="-",
                   help="Fichier de sortie (defaut : stdout).")
    p.add_argument("-m", "--map", dest="mapfile", default=None,
                   help="Ecrit la table de correspondance JSON (a garder en local).")
    p.add_argument("--anonymize-all-ips", action="store_true",
                   help="Anonymise aussi les IP privees (RFC1918), pas seulement publiques.")
    p.add_argument("--keep-descriptions", action="store_true",
                   help="Conserve les descriptions d'interface telles quelles.")
    p.add_argument("--keep-macs", action="store_true",
                   help="Conserve les adresses MAC telles quelles.")
    p.add_argument("--no-summary", action="store_true",
                   help="N'affiche pas le recapitulatif sur stderr.")
    p.add_argument("--strict", action="store_true",
                   help="Termine avec le code retour 2 si des lignes residuelles "
                        "suspectes subsistent (utilisable en CI / pipeline).")
    p.add_argument("--version", action="version",
                   version=f"%(prog)s {__version__}")
    args = p.parse_args()

    # lecture
    if args.input == "-":
        data = sys.stdin.read()
    else:
        try:
            with open(args.input, "r", encoding="utf-8", errors="replace") as f:
                data = f.read()
        except OSError as e:
            sys.exit(f"sanitize_netconfig: lecture impossible : {e}")
    lines = data.splitlines()

    anon = Anonymizer(anon_all_ips=args.anonymize_all_ips,
                      keep_descriptions=args.keep_descriptions,
                      keep_macs=args.keep_macs)
    anon.collect(lines)
    result = anon.process(lines)

    # ecriture
    body = "\n".join(result) + ("\n" if data.endswith("\n") else "")
    if args.output == "-":
        sys.stdout.write(body)
    else:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(body)
        except OSError as e:
            sys.exit(f"sanitize_netconfig: ecriture impossible : {e}")

    if args.mapfile:
        try:
            with open(args.mapfile, "w", encoding="utf-8") as f:
                json.dump(anon.mapping(), f, ensure_ascii=False, indent=2)
        except OSError as e:
            sys.exit(f"sanitize_netconfig: ecriture de la table impossible : {e}")

    flagged = residual_warnings(result)

    # recapitulatif + alerte residuelle (sur stderr pour ne pas polluer stdout)
    if not args.no_summary:
        s = anon.stats
        print("--- Recapitulatif d'anonymisation ---", file=sys.stderr)
        print(f"  Secrets detruits        : {s['secrets']}", file=sys.stderr)
        print(f"  Bannieres               : {s['banners']}", file=sys.stderr)
        print(f"  Certificats / cles      : {s['certs']}", file=sys.stderr)
        print(f"  E-mails                 : {s['emails']}", file=sys.stderr)
        print(f"  Locations / contacts    : {s['locations']} / {s['contacts']}", file=sys.stderr)
        print(f"  Hostnames pseudonymises : {len(anon.hosts)}", file=sys.stderr)
        print(f"  Domaines                : {len(anon.domains)}", file=sys.stderr)
        print(f"  IPv4 / IPv6             : {len(anon.ipv4)} / {len(anon.ipv6)}", file=sys.stderr)
        print(f"  MAC                     : {len(anon.macs)}", file=sys.stderr)
        print(f"  Descriptions            : {len(anon.descriptions)}", file=sys.stderr)

        if flagged:
            print("\n  /!\\ Lignes a RELIRE (secret potentiel non neutralise) :",
                  file=sys.stderr)
            for idx, ln in flagged:
                print(f"     L{idx}: {ln}", file=sys.stderr)
        else:
            print("\n  Aucun secret residuel detecte par l'heuristique.",
                  file=sys.stderr)

    if args.strict and flagged:
        sys.exit(2)


if __name__ == "__main__":
    main()

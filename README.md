# netanom

[![CI](https://github.com/Hotion13/netanom/actions/workflows/ci.yml/badge.svg)](https://github.com/Hotion13/netanom/actions/workflows/ci.yml)

**netanom** sanitizes **Cisco (IOS / IOS-XE / NX-OS)** and **Arista EOS**
configurations so you can share them with an AI assistant — or any third
party — without disclosing secrets or identifying information, while keeping
the file **internally consistent and fully usable for analysis**.

It is a single, dependency-free Python module (`sanitize_netconfig.py`,
Python ≥ 3.9) that also installs as a proper CLI (`netanom`).

## Why

Pasting a running configuration into an AI assistant is one of the fastest
ways to get help with network design, troubleshooting or auditing — and one
of the fastest ways to leak enable secrets, SNMP communities, TACACS+ keys,
BGP passwords, public addressing plans and organizational details. Redacting
by hand is error-prone, and naive find-and-replace breaks the very
relationships (which peer talks to which address, which host owns which
name) that make the analysis useful.

## How it works

netanom applies two distinct treatments:

1. **Secrets → destruction.** The real value is replaced by a marker
   (`<SANITIZED-SECRET>`, `<SANITIZED-SNMP-COMMUNITY>`, …) and is never
   stored anywhere. The algorithm hint (type 7, type 9, sha512, RO/RW,
   ACL name…) is preserved: it is useful security information and is not
   confidential.

2. **Identifiers → consistent pseudonymization.** A given original value is
   always replaced by the same alias (`device-1`, `198.51.100.x`,
   `example-1.net`, …) so cross-references inside the file remain
   analyzable. The mapping table can be written to a `.map.json` file —
   **to be kept local** — so you can translate the AI's recommendations
   back to your real configuration.

A **residual-secret heuristic** then scans the output and lists any line
that still looks suspicious (unknown password syntaxes, leftover
hash-looking values), so you know exactly what to review before sharing.

## Example

Input:

```text
hostname PARIS-CORE-01
ip domain name prod.acme.example
!
enable secret 5 $1$mERr$hx5rVt7rPNoS4wqbXKX7m0
!
snmp-server community acme-RO-2024 RO 99
snmp-server location Paris DC, rack B12
!
interface GigabitEthernet0/0
 description WAN to provider - circuit CT-889123
 ip address 82.121.34.5 255.255.255.252
!
router bgp 65001
 neighbor 82.121.34.6 remote-as 3215
 neighbor 82.121.34.6 password 7 121A0C041104
!
ntp server ntp1.prod.acme.example
```

Output (`netanom config.txt`):

```text
hostname device-1
ip domain name example-1.net
!
enable secret 5 <SANITIZED-SECRET>
!
snmp-server community <SANITIZED-SNMP-COMMUNITY> RO 99
snmp-server location <SANITIZED-LOCATION>
!
interface GigabitEthernet0/0
 description <SANITIZED-DESCRIPTION-1>
 ip address 198.51.100.1 255.255.255.252
!
router bgp 65001
 neighbor 198.51.100.2 remote-as 3215
 neighbor 198.51.100.2 password 7 <SANITIZED-SECRET>
!
ntp server ntp1.example-1.net
```

Note how the BGP peer keeps a single consistent alias (`198.51.100.2`) on
both lines, the FQDN `ntp1.prod.acme.example` follows the domain's alias,
private addressing and the `RO 99` community attributes are untouched, and
the secret type hints (`5`, `7`) are preserved.

## Installation

With [uv](https://docs.astral.sh/uv/) (recommended):

```console
# install the netanom command globally
uv tool install git+https://github.com/Hotion13/netanom

# or run it once, without installing
uvx --from git+https://github.com/Hotion13/netanom netanom config.txt
```

With pip:

```console
pip install git+https://github.com/Hotion13/netanom
```

Zero-install: `sanitize_netconfig.py` is self-contained (standard library
only). Copy that single file to a jump host and run it with any
Python ≥ 3.9:

```console
python3 sanitize_netconfig.py config.txt
```

## Usage

```console
# file -> file, with a local mapping table
netanom config.txt -o config.san.txt -m config.map.json

# as a filter (stdin -> stdout)
show_run_output | netanom - > config.san.txt

# also anonymize private IPs, keep interface descriptions
netanom config.txt --anonymize-all-ips --keep-descriptions

# CI / pipeline gate: fail if anything suspicious remains
netanom config.txt -o config.san.txt --strict
```

A summary is printed on stderr (stdout stays clean for piping), including
the list of residual lines that still look like secrets — **always review
them** before sharing the output.

### Options

| Option | Effect |
|---|---|
| `-o, --output FILE` | Output file (default: stdout) |
| `-m, --map FILE` | Write the JSON mapping table (keep it local, **never** share it) |
| `--anonymize-all-ips` | Also anonymize private (RFC 1918) addresses, not only public ones |
| `--keep-descriptions` | Keep interface descriptions as-is (e-mails/IPs/hostnames inside them are still processed) |
| `--keep-macs` | Keep MAC addresses as-is |
| `--no-summary` | Do not print the summary on stderr |
| `--strict` | Exit with status 2 if suspicious residual lines remain (CI-friendly) |
| `--version` | Show version |

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | I/O error (unreadable input, unwritable output) |
| 2 | Residual suspicious lines found while `--strict` is set (also used by argparse for invalid arguments) |

## What gets destroyed (secrets)

**Authentication & AAA**
- `enable secret` / `enable password` (types 0/5/7/8/9, EOS `sha512`)
- `username … secret/password` (all types, trailing options preserved)
- account SSH public keys (`username … sshkey …`) — identifying material
- line passwords (`line con/vty/aux` → `password …`)
- TACACS+ / RADIUS keys: `tacacs-server`/`radius-server … key` (including
  after `auth-port`/`acct-port` options) and indented `key …` inside
  `radius server X` / `tacacs server X` blocks
- password-encryption master key (`key config-key password-encrypt`)
- `ip ftp password`, `ip http client password`

**SNMP**
- `snmp-server community` (RO/RW and ACL kept)
- community/v3 user embedded in every `snmp-server host` form
  (`vrf`/`use-vrf`, `traps`/`informs`, `version 1|2c|3 auth|noauth|priv`)
- SNMPv3 keys: `auth md5|sha|sha-256…`, `priv des|3des|aes [128|192|256]`,
  hyphenated `aes-128` and NX-OS localized `0x…` forms
- `snmp-server location` / `contact` (free text → marker)

**Routing, FHRP & neighbors**
- BGP/EOS `neighbor … password`
- OSPF `message-digest-key N md5` and `authentication-key`
- `authentication text`, key-chain `key-string`
- IS-IS `isis password`, `area-password`, `domain-password`
- HSRP/VRRP plaintext `authentication` (md5/key-chain forms handled via
  their own rules, key-chain structure preserved)
- NTP authentication keys (md5/sha/hmac-sha2/cmac-aes, either
  encryption-type position)
- PPP CHAP/PAP (`ppp chap password`, `sent-username … password`)

**VPN & PKI**
- `crypto isakmp key [0|6] …`, `pre-shared-key [local|remote] …`
- inline `key 0|5|7|8|9 <value>` occurrences (keyrings, server blocks…)
- PEM blocks (`-----BEGIN … END-----`) and IOS hex certificate blobs
  (collapsed to one `<SANITIZED-CERTIFICATE-OR-KEY>` marker)

**Free text**
- banners (`banner motd/login/exec …`, IOS delimiters and EOS `EOF` style)
- e-mail addresses (everywhere, including inside kept descriptions)
- interface descriptions → consistent `<SANITIZED-DESCRIPTION-N>` tokens

## What gets pseudonymized (consistent aliases)

| Identifier | Alias | Notes |
|---|---|---|
| `hostname` / `switchname` / `sysname` | `device-N` | replaced everywhere, case-insensitive, including inside `host.domain` FQDNs |
| domains (`ip domain-name`, `ip domain list`, `dns domain`, DHCP `domain-name`, `vrf` forms) | `example-N.net` | replaced everywhere, including as FQDN suffix |
| public IPv4 | RFC 5737 documentation ranges, then 198.18.0.0/15 (RFC 2544) | > 130,000 distinct addresses supported without alias collision |
| public IPv6 | `2001:db8::/32` (RFC 3849) | equivalent notations of one address share one alias |
| MAC addresses | locally-administered `02:…` | format preserved; `aabb.ccdd.eeff` and `aa:bb:cc:dd:ee:ff` notations of the same MAC share one alias |

## What is deliberately preserved

- private (RFC 1918) IPv4 addresses — unless `--anonymize-all-ips`
- documentation, multicast, loopback, link-local, unspecified and reserved
  addresses; netmasks and wildcard masks; `0.0.0.0/8`
- multicast/broadcast MACs and well-known virtual MACs (HSRP, VRRP, GLBP)
- AS numbers, VLAN IDs, interface names, ACL/route-map/VRF names
- algorithm/type hints (`5`, `7`, `9`, `sha512`, `md5`…) and SNMP RO/RW +
  ACL attributes
- key-chain structure (`key chain NAME`, key numbers)

## The mapping file (`-m`)

The table written by `-m` maps `real value → alias`:

```json
{
  "_warning": "Mapping table used to DE-anonymize the AI's answers. KEEP THIS FILE LOCAL. Never send it to the AI or to any third party.",
  "hosts":   { "PARIS-CORE-01": "device-1" },
  "domains": { "prod.acme.example": "example-1.net" },
  "ipv4":    { "82.121.34.5": "198.51.100.1", "82.121.34.6": "198.51.100.2" },
  "ipv6":    {},
  "macs":    {},
  "descriptions": { "WAN to provider - circuit CT-889123": "<SANITIZED-DESCRIPTION-1>" }
}
```

It exists so you can apply the AI's answer back to the real network
(e.g. replace `device-1` / `198.51.100.2` with the actual values). **Treat
it as a secret: never send it to the AI or to any third party.** Destroyed
secrets are never written to it.

## Limitations (important)

This is a best-effort, pattern-based tool — it does **not** replace a human
review. In particular, check manually:

- VRF, route-map, ACL, prefix-list and trustpoint **names** (kept as-is; they
  sometimes encode customer or site names)
- serial numbers, license tokens, circuit IDs inside kept descriptions
- EOS agent tokens (`daemon TerminAttr` ingest keys), WLC/WLAN PSKs,
  `snmp-server engineID`
- purely numeric values after `key` (ambiguous with a key-chain key number)
- any secret with an exotic or vendor-specific syntax

Masks and prefixes are not recomputed: a replaced network address may become
a host address (subnet-level consistency is not guaranteed). The residual
heuristic reports suspicious leftovers; `--strict` turns that report into a
non-zero exit code for pipelines.

## Development

The project uses [uv](https://docs.astral.sh/uv/); tests are standard
`unittest` (no test dependencies).

```console
git clone https://github.com/Hotion13/netanom
cd netanom

uv run python -m unittest discover -s tests -v   # run the test suite
uv run netanom --version                         # run the CLI from source
uv build                                         # build sdist + wheel
```

Without uv, `python3 -m unittest discover -s tests -v` works too.

The test suite includes one regression test per previously fixed leak
(OSPF/NTP keys whose key number is 0/5/7/8/9, `snmp-server host … vrf`,
NX-OS `priv 0x…`/`aes-128`, `crypto isakmp key 6 …`,
`radius-server … auth-port … key`, server-block `key`, plaintext HSRP/VRRP,
`host.domain` FQDNs, …).

## License

[MIT](LICENSE)

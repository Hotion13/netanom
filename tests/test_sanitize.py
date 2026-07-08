"""Tests for sanitize_netconfig.py — stdlib only (unittest).

Run with:  python3 -m unittest discover -s tests -v
"""

import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import sanitize_netconfig as sn  # noqa: E402

SCRIPT = ROOT / "sanitize_netconfig.py"


def sanitize(text, **kwargs):
    """Full collect + process pipeline; returns (output, anonymizer)."""
    anon = sn.Anonymizer(**kwargs)
    lines = text.splitlines()
    anon.collect(lines)
    return "\n".join(anon.process(lines)), anon


class TestSecrets(unittest.TestCase):
    def test_enable_secret(self):
        out, _ = sanitize("enable secret 9 $9$abc.def/ghi123")
        self.assertEqual(out, "enable secret 9 " + sn.S_SECRET)

    def test_enable_password_sha512_eos(self):
        out, _ = sanitize("enable password sha512 $6$saltsalt$hashhashhash")
        self.assertNotIn("$6$", out)
        self.assertIn("sha512", out)

    def test_line_password(self):
        out, _ = sanitize("line vty 0 4\n password s3cretpw\n login")
        self.assertNotIn("s3cretpw", out)
        self.assertIn(" password " + sn.S_SECRET, out)

    def test_username_keeps_trailing_options(self):
        out, _ = sanitize("username admin password 5 $5$abc$defgh role network-admin")
        self.assertNotIn("$5$abc$defgh", out)
        self.assertIn("role network-admin", out)

    def test_username_nopassword_untouched(self):
        line = "username admin privilege 15 nopassword"
        out, _ = sanitize(line)
        self.assertEqual(out, line)

    def test_username_sshkey_destroyed(self):
        out, _ = sanitize(
            "username admin sshkey ssh-rsa AAAAB3NzaC1yc2EAAAADAQAB admin@corp.com")
        self.assertNotIn("AAAAB3", out)
        self.assertNotIn("admin@corp.com", out)
        self.assertIn(sn.S_SSHKEY, out)

    # --- regressions: fixed leaks --------------------------------------------
    def test_ospf_message_digest_key_number_in_type_set(self):
        # Key number 5 used to trigger the inline "key 5 ..." rule, which
        # destroyed "md5" and let the actual secret leak.
        out, _ = sanitize("ip ospf message-digest-key 5 md5 OspfS3cret")
        self.assertNotIn("OspfS3cret", out)
        self.assertIn("md5", out)

    def test_ntp_key_number_in_type_set(self):
        out, _ = sanitize("ntp authentication-key 5 md5 NtpS3cret")
        self.assertNotIn("NtpS3cret", out)
        self.assertIn("md5", out)

    def test_ntp_trailing_encryption_type(self):
        out, _ = sanitize("ntp authentication-key 10 md5 141B1309 7")
        self.assertNotIn("141B1309", out)

    def test_isakmp_key_with_encryption_type(self):
        # "crypto isakmp key 6 SECRET address x": the 6 used to be destroyed
        # instead of the secret.
        out, _ = sanitize("crypto isakmp key 6 IsakmpS3cret address 198.51.100.99")
        self.assertNotIn("IsakmpS3cret", out)
        self.assertIn("address", out)

    def test_isakmp_key_plain(self):
        out, _ = sanitize("crypto isakmp key MyPSK address 0.0.0.0 0.0.0.0")
        self.assertNotIn("MyPSK", out)

    def test_radius_server_with_ports_key(self):
        out, _ = sanitize(
            "radius-server host 10.1.1.2 auth-port 1812 acct-port 1813 key RadiusS3cret")
        self.assertNotIn("RadiusS3cret", out)

    def test_tacacs_server_key_type7(self):
        out, _ = sanitize("tacacs-server host 10.1.1.3 key 7 06120A3258F4A1")
        self.assertNotIn("06120A3258F4A1", out)

    def test_radius_block_indented_bare_key(self):
        cfg = ("radius server ISE\n"
               " address ipv4 10.5.5.5 auth-port 1812 acct-port 1813\n"
               " key BlockS3cret!\n")
        out, _ = sanitize(cfg)
        self.assertNotIn("BlockS3cret!", out)
        self.assertIn("radius server ISE", out)

    def test_key_chain_structure_preserved(self):
        cfg = ("key chain LANKEYS\n"
               " key 1\n"
               "  key-string 7 141B1309000E\n")
        out, _ = sanitize(cfg)
        self.assertIn("key chain LANKEYS", out)
        self.assertIn("\n key 1\n", out)
        self.assertNotIn("141B1309000E", out)

    def test_key_config_key(self):
        out, _ = sanitize("key config-key password-encrypt MyMasterKey")
        self.assertNotIn("MyMasterKey", out)
        self.assertIn("key config-key password-encrypt", out)

    def test_hsrp_plaintext_authentication(self):
        out, _ = sanitize("standby 1 authentication HsrpS3cret")
        self.assertNotIn("HsrpS3cret", out)

    def test_hsrp_md5_keystring(self):
        out, _ = sanitize("standby 1 authentication md5 key-string 7 09441B1B13")
        self.assertNotIn("09441B1B13", out)
        self.assertIn("authentication md5 key-string 7", out)

    def test_vrrp_plaintext_authentication(self):
        out, _ = sanitize("vrrp 10 authentication VrrpPass")
        self.assertNotIn("VrrpPass", out)

    def test_isis_passwords(self):
        out, _ = sanitize("domain-password IsisS3cret\n"
                          "area-password AreaS3cret\n"
                          "isis password IfS3cret level-2")
        for secret in ("IsisS3cret", "AreaS3cret", "IfS3cret"):
            self.assertNotIn(secret, out)
        self.assertIn("level-2", out)

    def test_pre_shared_key_keyring_address_form(self):
        out, _ = sanitize("  pre-shared-key address 192.0.2.99 key 0 SuperPSK")
        self.assertNotIn("SuperPSK", out)
        self.assertIn("address", out)

    def test_pre_shared_key_local(self):
        out, _ = sanitize("  pre-shared-key local Sup3rS3cret")
        self.assertNotIn("Sup3rS3cret", out)

    def test_neighbor_password(self):
        out, _ = sanitize("neighbor 203.0.113.5 password 7 0822455D0A16")
        self.assertNotIn("0822455D0A16", out)

    def test_http_client_password(self):
        out, _ = sanitize("ip http client password 7 05080F1C2243")
        self.assertNotIn("05080F1C2243", out)


class TestSnmp(unittest.TestCase):
    def test_community(self):
        out, _ = sanitize("snmp-server community S3cretC0mm RO 99")
        self.assertNotIn("S3cretC0mm", out)
        self.assertIn("RO 99", out)

    def test_host_legacy_v2c(self):
        out, _ = sanitize("snmp-server host 10.1.1.1 public")
        self.assertNotIn("public", out)

    def test_host_with_vrf(self):
        # The vrf form used to leak the community (over-strict lookahead).
        out, _ = sanitize("snmp-server host 10.1.1.1 vrf MGMT version 2c C0mmun1ty")
        self.assertNotIn("C0mmun1ty", out)
        self.assertIn("vrf MGMT", out)

    def test_host_v3_priv_user(self):
        out, _ = sanitize("snmp-server host 192.0.2.50 version 3 priv NetOpsUser")
        self.assertNotIn("NetOpsUser", out)
        self.assertIn("version 3 priv", out)

    def test_host_nxos_use_vrf_line_untouched(self):
        line = "snmp-server host 10.1.1.1 use-vrf management"
        out, _ = sanitize(line)
        self.assertEqual(out, line)

    def test_nxos_user_priv_hex(self):
        # NX-OS "priv 0x..." (no algorithm keyword) used to leak silently.
        out, _ = sanitize("snmp-server user admin network-admin "
                          "auth md5 0x1a2b3c4d5e priv 0x5e4d3c2b1a localizedkey")
        self.assertNotIn("0x1a2b3c4d5e", out)
        self.assertNotIn("0x5e4d3c2b1a", out)
        self.assertIn("localizedkey", out)

    def test_priv_aes_dash_form(self):
        # "priv aes-128 KEY" (hyphenated) used to leak silently.
        out, _ = sanitize("snmp-server user ops grp v3 auth sha AuthPass priv aes-128 PrivPass")
        self.assertNotIn("AuthPass", out)
        self.assertNotIn("PrivPass", out)

    def test_auth_sha_dash_form(self):
        out, _ = sanitize("snmp-server user x g v3 auth sha-256 S3cretAuth")
        self.assertNotIn("S3cretAuth", out)

    def test_location_contact(self):
        out, _ = sanitize("snmp-server location Building 7, Paris DC, rack B12\n"
                          "snmp-server contact John Smith +1 555 0100")
        self.assertNotIn("Paris", out)
        self.assertNotIn("Smith", out)
        self.assertIn(sn.S_LOCATION, out)
        self.assertIn(sn.S_CONTACT, out)


class TestIdentifiers(unittest.TestCase):
    def test_hostname_and_fqdn(self):
        # A "host.domain" FQDN used to leak entirely (boundaries rejected '.').
        cfg = ("hostname SW-CORE\n"
               "ip domain-name corp.example\n"
               "ntp server sw-core.corp.example\n")
        out, _ = sanitize(cfg)
        self.assertNotIn("SW-CORE", out)
        self.assertNotIn("sw-core", out)
        self.assertNotIn("corp.example", out)
        self.assertIn("hostname device-1", out)
        self.assertIn("ntp server device-1.example-1.net", out)

    def test_domain_with_vrf_and_dhcp_pool(self):
        cfg = ("ip domain name vrf MGMT corp.example\n"
               "ip dhcp pool LAN\n"
               " domain-name corp.example\n")
        out, _ = sanitize(cfg)
        self.assertNotIn("corp.example", out)

    def test_public_ip_coherent(self):
        cfg = "ip route 8.8.8.8 255.255.255.255 11.22.33.44\nlogging host 8.8.8.8\n"
        out, anon = sanitize(cfg)
        self.assertNotIn("8.8.8.8", out)
        self.assertNotIn("11.22.33.44", out)
        # same original -> same alias on both lines
        alias = anon.ipv4["8.8.8.8"]
        self.assertEqual(out.count(alias), 2)

    def test_private_ip_kept_by_default(self):
        line = "ip route 10.0.0.0 255.0.0.0 192.168.1.1"
        out, _ = sanitize(line)
        self.assertEqual(out, line)

    def test_anonymize_all_ips(self):
        out, _ = sanitize("interface Vlan10\n ip address 192.168.1.1 255.255.255.0",
                          anon_all_ips=True)
        self.assertNotIn("192.168.1.1", out)
        self.assertIn("255.255.255.0", out)   # netmask preserved

    def test_keep_ips_public_v4_kept(self):
        line = "ip route 8.8.8.8 255.255.255.255 11.22.33.44"
        out, anon = sanitize(line, keep_ips=True)
        self.assertEqual(out, line)
        self.assertEqual(anon.mapping()["ipv4"], {})
        self.assertEqual(anon.kept_public_ips, {"8.8.8.8", "11.22.33.44"})

    def test_keep_ips_public_v6_kept(self):
        line = "ipv6 route 2400:cb00::/32 Null0"
        out, anon = sanitize(line, keep_ips=True)
        self.assertEqual(out, line)
        self.assertEqual(anon.mapping()["ipv6"], {})
        self.assertEqual(anon.kept_public_ips, {"2400:cb00::"})

    def test_keep_ips_counts_distinct_addresses(self):
        cfg = "logging host 8.8.8.8\nntp server 8.8.8.8\nntp server 9.9.9.9\n"
        _, anon = sanitize(cfg, keep_ips=True)
        self.assertEqual(len(anon.kept_public_ips), 2)

    def test_keep_ips_secrets_still_destroyed(self):
        out, _ = sanitize("neighbor 203.0.113.5 password 7 0822455D0A16",
                          keep_ips=True)
        self.assertIn("neighbor 203.0.113.5", out)
        self.assertNotIn("0822455D0A16", out)

    def test_keep_ips_other_identifiers_still_processed(self):
        cfg = ("hostname SW-CORE\n"
               "logging host 8.8.8.8\n"
               "arp 10.0.0.5 aa:bb:cc:dd:ee:ff arpa\n")
        out, _ = sanitize(cfg, keep_ips=True)
        self.assertNotIn("SW-CORE", out)
        self.assertNotIn("aa:bb:cc:dd:ee:ff", out)
        self.assertIn("8.8.8.8", out)

    def test_keep_ips_conflicts_with_anonymize_all_ips(self):
        with self.assertRaises(ValueError):
            sn.Anonymizer(anon_all_ips=True, keep_ips=True)

    def test_ipv4_pool_no_duplicate_after_doc_ranges(self):
        # >762 distinct public IPs: the old code fell back to a single
        # duplicated address, breaking the mapping table consistency.
        lines = [f"ip route 11.{i // 200}.{i % 200}.1 255.255.255.255 Null0"
                 for i in range(800)]
        _, anon = sanitize("\n".join(lines))
        self.assertEqual(len(anon.ipv4), 800)
        self.assertEqual(len(set(anon.ipv4.values())), 800)

    def test_ipv6_global_replaced_coherent(self):
        cfg = "ipv6 route 2400:cb00::/32 Null0\nntp server 2400:cb00::\n"
        out, anon = sanitize(cfg)
        self.assertNotIn("2400:cb00", out)
        self.assertEqual(len(set(anon.ipv6.values())), 1)

    def test_ipv6_doc_range_kept(self):
        line = "ipv6 route 2001:db8:1::/48 Null0"
        out, _ = sanitize(line)
        self.assertEqual(out, line)

    def test_mac_unicast_replaced_coherently_across_formats(self):
        cfg = ("mac address-table static aabb.ccdd.eeff vlan 10 interface Gi1/0/1\n"
               "arp 10.0.0.5 aa:bb:cc:dd:ee:ff arpa\n")
        out, anon = sanitize(cfg)
        self.assertNotIn("aabb.ccdd.eeff", out)
        self.assertNotIn("aa:bb:cc:dd:ee:ff", out)
        digits = {v.replace(".", "").replace(":", "") for v in anon.macs.values()}
        self.assertEqual(len(digits), 1)      # same MAC -> same alias

    def test_mac_multicast_and_virtual_kept(self):
        for line in ("mac address-table static 0100.5e00.0001 vlan 1 interface Gi1/0/1",
                     "arp 10.0.0.9 0000.0c07.ac0a arpa",
                     "arp 10.0.0.8 0000.5e00.0105 arpa"):
            out, _ = sanitize(line)
            self.assertEqual(out, line)

    def test_email_destroyed(self):
        out, _ = sanitize("alias exec support mail noc@corp.example")
        self.assertNotIn("noc@corp.example", out)
        self.assertIn(sn.S_EMAIL, out)

    def test_descriptions_tokenized_coherently(self):
        cfg = ("interface Gi1/0/1\n description WAN link Orange CT-12345\n"
               "interface Gi1/0/2\n description WAN link Orange CT-12345\n"
               "interface Gi1/0/3\n description Some other link\n")
        out, anon = sanitize(cfg)
        self.assertNotIn("CT-12345", out)
        self.assertEqual(len(anon.descriptions), 2)

    def test_keep_descriptions(self):
        out, _ = sanitize("interface Gi1\n description WAN link CT-12345",
                          keep_descriptions=True)
        self.assertIn("WAN link CT-12345", out)


class TestBlocks(unittest.TestCase):
    def test_banner_multiline(self):
        cfg = ("banner motd ^C\n"
               "Property of ACME Corp - authorized access only\n"
               "^C\n"
               "line vty 0 4\n")
        out, _ = sanitize(cfg)
        self.assertNotIn("ACME", out)
        self.assertIn(sn.S_BANNER, out)
        self.assertIn("line vty 0 4", out)

    def test_banner_singleline(self):
        out, _ = sanitize("banner login #Restricted - ACME#")
        self.assertNotIn("ACME", out)
        self.assertIn(sn.S_BANNER, out)

    def test_banner_eos_eof(self):
        cfg = ("banner login\n"
               "Welcome to ACME network\n"
               "EOF\n"
               "interface Ethernet1\n")
        out, _ = sanitize(cfg)
        self.assertNotIn("ACME", out)
        self.assertIn("interface Ethernet1", out)

    def test_pem_block(self):
        cfg = ("ssl certificate mycert\n"
               "-----BEGIN CERTIFICATE-----\n"
               "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7x8Z\n"
               "-----END CERTIFICATE-----\n"
               "end\n")
        out, _ = sanitize(cfg)
        self.assertNotIn("MIIBIjAN", out)
        self.assertIn(sn.S_CERT, out)
        self.assertIn("end", out)

    def test_hexblob_with_quit(self):
        cfg = ("crypto pki certificate chain TP-self-signed-1\n"
               " certificate self-signed 01\n"
               "  30820330 308202B9 A0030201 02020101\n"
               "  300D0609 2A864886 F70D0101 04050030\n"
               "  quit\n"
               "!\n")
        out, _ = sanitize(cfg)
        self.assertNotIn("30820330", out)
        self.assertEqual(out.count(sn.S_CERT), 1)
        self.assertIn(" certificate self-signed 01", out)
        self.assertIn("!", out)


class TestResidual(unittest.TestCase):
    def test_keyword_line_flagged(self):
        flagged = sn.residual_warnings(["foo passphrase bar"])
        self.assertEqual(len(flagged), 1)

    def test_sanitized_line_not_flagged(self):
        flagged = sn.residual_warnings(["username x secret " + sn.S_SECRET])
        self.assertEqual(flagged, [])

    def test_hash_value_flagged_even_with_marker(self):
        # A hash-looking value left on a partially processed line must still
        # be reported.
        flagged = sn.residual_warnings(
            ["something " + sn.S_SECRET + " leftover $6$roundsalt$abcdef012345"])
        self.assertEqual(len(flagged), 1)


class TestCli(unittest.TestCase):
    def run_cli(self, args, stdin):
        return subprocess.run(
            [sys.executable, str(SCRIPT)] + args,
            input=stdin, capture_output=True, text=True)

    def test_stdin_stdout(self):
        r = self.run_cli(["-"], "enable secret 5 $1$abc$def\n")
        self.assertEqual(r.returncode, 0)
        self.assertIn(sn.S_SECRET, r.stdout)
        self.assertNotIn("$1$abc$def", r.stdout)
        self.assertIn("Sanitization summary", r.stderr)

    def test_no_summary(self):
        r = self.run_cli(["-", "--no-summary"], "hostname R1\n")
        self.assertEqual(r.stderr, "")

    def test_strict_exit_code_on_residual(self):
        r = self.run_cli(["-", "--strict", "--no-summary"],
                         "some unknown passphrase thing\n")
        self.assertEqual(r.returncode, 2)

    def test_keep_ips_flag_and_warning(self):
        r = self.run_cli(["-", "--keep-ips"], "logging host 8.8.8.8\n")
        self.assertEqual(r.returncode, 0)
        self.assertIn("8.8.8.8", r.stdout)
        self.assertIn("--keep-ips: 1 public IP", r.stderr)

    def test_keep_ips_and_anonymize_all_ips_rejected(self):
        r = self.run_cli(["-", "--keep-ips", "--anonymize-all-ips"], "")
        self.assertEqual(r.returncode, 2)
        self.assertIn("not allowed with", r.stderr)

    def test_missing_input_file_friendly_error(self):
        r = self.run_cli(["/nonexistent/file.txt"], "")
        self.assertEqual(r.returncode, 1)
        self.assertIn("cannot read", r.stderr)

    def test_map_file_written(self):
        with tempfile.TemporaryDirectory() as tmp:
            mapfile = pathlib.Path(tmp) / "out.map.json"
            r = self.run_cli(["-", "--no-summary", "-m", str(mapfile)],
                             "hostname R1\nip route 8.8.8.8 255.255.255.255 Null0\n")
            self.assertEqual(r.returncode, 0)
            data = json.loads(mapfile.read_text(encoding="utf-8"))
            self.assertIn("_warning", data)
            self.assertEqual(data["hosts"], {"R1": "device-1"})
            self.assertIn("8.8.8.8", data["ipv4"])


if __name__ == "__main__":
    unittest.main()

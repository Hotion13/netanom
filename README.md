# netanom

Anonymiseur de configurations réseau **Cisco (IOS / IOS-XE / NX-OS)** et
**Arista EOS**, pensé pour pouvoir soumettre une configuration à une IA (ou à
tout tiers) sans divulguer de secrets ni d'informations identifiantes — tout
en gardant le fichier **cohérent et exploitable** pour l'analyse.

Un seul fichier, aucune dépendance : `sanitize_netconfig.py` (Python ≥ 3.8).

## Principe

Deux familles de traitement :

1. **Secrets → destruction.** La vraie valeur est remplacée par un marqueur
   (`<SANITIZED-SECRET>`, `<SANITIZED-SNMP-COMMUNITY>`…) et n'est conservée
   nulle part. L'indice d'algorithme (type 7, type 9, sha512, RO/RW, ACL…)
   est gardé : c'est une information de sécurité utile et non confidentielle.

2. **Identifiants → pseudonymisation cohérente.** Une même valeur d'origine
   est toujours remplacée par le même alias (`device-1`, `198.51.100.x`,
   `example-1.net`…) afin que les relations internes du fichier restent
   analysables. La table de correspondance peut être écrite dans un fichier
   `.map.json` **à conserver en local** : elle permet de ré-appliquer les
   recommandations de l'IA à la vraie configuration.

## Usage

```console
# fichier -> fichier, avec table de correspondance locale
python3 sanitize_netconfig.py config.txt -o config.san.txt -m config.map.json

# en filtre (stdin -> stdout)
cat config.txt | python3 sanitize_netconfig.py - > config.san.txt

# anonymiser aussi les IP privées, garder les descriptions d'interface
python3 sanitize_netconfig.py config.txt --anonymize-all-ips --keep-descriptions
```

Un récapitulatif est affiché sur stderr, avec la liste des lignes résiduelles
qui ressemblent encore à un secret : **relisez-les toujours** avant envoi.

### Options

| Option | Effet |
|---|---|
| `-o, --output FICHIER` | Fichier de sortie (défaut : stdout) |
| `-m, --map FICHIER` | Écrit la table de correspondance JSON (à garder en local, ne **jamais** transmettre) |
| `--anonymize-all-ips` | Anonymise aussi les IP privées (RFC 1918), pas seulement les publiques |
| `--keep-descriptions` | Conserve les descriptions d'interface (les e-mails/IP/hostnames qu'elles contiennent restent traités) |
| `--keep-macs` | Conserve les adresses MAC |
| `--no-summary` | Pas de récapitulatif sur stderr |
| `--strict` | Code retour 2 si des lignes résiduelles suspectes subsistent (pratique en CI/pipeline) |
| `--version` | Affiche la version |

## Ce qui est neutralisé

**Secrets détruits** : enable secret/password, username secret/password
(y compris EOS `sha512`), clés publiques SSH des comptes, mots de passe de
lignes (con/vty/aux), communautés SNMP (`community` et toutes les formes de
`snmp-server host`, y compris `vrf`/`use-vrf`), clés SNMPv3 (`auth md5/sha…`,
`priv des/aes/aes-128…`, formes NX-OS `0x…`), clés TACACS+/RADIUS (lignes
globales et blocs `radius server X` / `tacacs server X`), clé maîtresse
`key config-key password-encrypt`, clés pré-partagées VPN (`crypto isakmp
key`, `pre-shared-key`), authentification de routage (BGP `neighbor …
password`, OSPF `message-digest-key`/`authentication-key`, IS-IS
`isis password`/`area-password`/`domain-password`), authentification HSRP/VRRP
en clair, `key-string` des key chains, PPP CHAP/PAP, `ip ftp password`,
`ip http client password`, clés NTP, certificats PKI (blocs hexadécimaux IOS),
blocs PEM, bannières et adresses e-mail.

**Identifiants pseudonymisés (cohérents)** :

- hostname / switchname / sysname → `device-N` (partout, insensible à la
  casse, y compris dans un FQDN `hote.domaine`) ;
- domaine (`ip domain-name`, `domain list`, `dns domain`, `domain-name` des
  pools DHCP) → `example-N.net` (partout, y compris en suffixe de FQDN) ;
- IPv4 publiques → plages de documentation RFC 5737, puis 198.18.0.0/15
  (RFC 2544) au-delà de ~760 adresses distinctes ;
- IPv6 publiques → `2001:db8::/32` (RFC 3849) ;
- MAC → adresses fictives d'administration locale (`02:…`), format conservé
  et alias identique entre notations `aabb.ccdd.eeff` et `aa:bb:cc:dd:ee:ff`.
  Les MAC multicast/broadcast et les MAC virtuelles bien connues (HSRP, VRRP,
  GLBP) sont conservées : porteuses de sens protocolaire, non identifiantes ;
- descriptions d'interface → jeton cohérent `<SANITIZED-DESCRIPTION-N>` ;
- `snmp-server location` / `contact` → marqueur.

Sont volontairement **conservés** : IP privées (par défaut), plages de
documentation, multicast, loopback, link-local, masques et wildcards, numéros
d'AS, VLAN, indices de type de chiffrement (7, 9, sha512…).

## Le fichier `.map.json`

La table écrite par `-m` contient la correspondance
`valeur réelle → alias`. Elle sert à dé-anonymiser les réponses de l'IA pour
les ré-appliquer à la vraie configuration. **Elle ne doit jamais être
transmise à l'IA ni à un tiers** — traitez-la comme un secret.

## Limites (important)

Outil « best effort » à base de motifs : il ne remplace **pas** une relecture
humaine. Vérifiez notamment : noms de VRF / route-map / ACL / trustpoint,
numéros de série et licences, identifiants de circuit dans les descriptions,
jetons d'agents EOS (`daemon TerminAttr`…), clés PSK WLAN, `snmp engineID`,
valeurs purement numériques après `key` (ambiguës avec un numéro de clé de
key chain) et tout secret à syntaxe exotique. Les masques/préfixes ne sont
pas recalculés : la cohérence de sous-réseau des adresses remplacées n'est
pas garantie. Le récapitulatif signale les lignes résiduelles suspectes ;
l'option `--strict` transforme cette alerte en code d'erreur.

## Tests

```console
python3 -m unittest discover -s tests -v
```

La suite couvre chaque famille de règles ainsi que des cas de régression
(fuites corrigées) : `message-digest-key`/clé NTP dont le numéro vaut
0/5/7/8/9, `snmp-server host … vrf`, formes NX-OS `priv 0x…`/`aes-128`,
`crypto isakmp key 6 …`, `radius-server … auth-port … key`, `key` en bloc
serveur, HSRP/VRRP en clair, FQDN `hote.domaine`, etc.

## Licence

[MIT](LICENSE)

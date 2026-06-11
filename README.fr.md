# antivirus.sh

<div align="center">

**Antivirus et scanner de malwares Linux dans un seul script Bash.**

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](antivirus.sh)
[![Shell](https://img.shields.io/badge/Shell-Bash-blue.svg)](antivirus.sh)
[![Platform](https://img.shields.io/badge/Platform-Linux-orange.svg)](antivirus.sh)
[![Ubuntu](https://img.shields.io/badge/Ubuntu-supported-E95420.svg)](antivirus.sh)
[![Debian](https://img.shields.io/badge/Debian-best--effort-A81D33.svg)](antivirus.sh)
[![RHEL/CentOS](https://img.shields.io/badge/RHEL%2FCentOS-best--effort-EE0000.svg)](antivirus.sh)
[![Fedora](https://img.shields.io/badge/Fedora-best--effort-51A2DA.svg)](antivirus.sh)
[![Arch](https://img.shields.io/badge/Arch-best--effort-1793D1.svg)](antivirus.sh)
[![openSUSE](https://img.shields.io/badge/openSUSE-best--effort-73BA25.svg)](antivirus.sh)
[![No agent](https://img.shields.io/badge/No%20agent-no%20daemon-lightgrey.svg)](antivirus.sh)

[English](README.md) | [Русский](README.ru.md) | [Español](README.es.md) | [中文](README.zh.md) | [日本語](README.ja.md) | [한국어](README.ko.md) | [Deutsch](README.ge.md) | [العربية](README.ar.md) | Français | [Italiano](README.it.md)

</div>

---

`antivirus.sh` est un scanner Bash autonome pour serveurs Linux. Il couvre la detection de malwares, les points de persistance, l'inspection des processus, l'integrite des paquets, quelques indicateurs reseau et une quarantaine prudente. Ce depot contient uniquement la partie antivirus extraite de la suite de securite plus large `antivirus.sh`.

La structure de ce README reprend l'esprit du projet de reference : <https://github.com/ultra-x-coder/antivirus.sh/>

## Demarrage rapide

```bash
chmod +x antivirus.sh
sudo bash antivirus.sh
sudo bash antivirus.sh --audit
sudo bash antivirus.sh --fix
sudo bash antivirus.sh --scan /var/www
sudo bash antivirus.sh --full
```

## Verifications effectuees

- Reverse shells, droppers, mineurs et motifs classiques de backdoor
- Executables caches dans `/tmp`, `/var/tmp` et `/dev/shm`
- Noms de processus malveillants connus, processus `memfd`, binaires lances depuis des repertoires temporaires
- Persistance via cron, systemd, `rc.local`, profils shell, udev et `authorized_keys`
- Connexions sortantes vers des ports typiques de pools de minage ou de botnets IRC
- Verification d'integrite des binaires systeme critiques avec `dpkg -V` ou `rpm -V`
- Scans approfondis optionnels avec ClamAV, rkhunter et chkrootkit

## Modes

| Commande | Description |
| --- | --- |
| `sudo bash antivirus.sh` | Mode interactif. Chaque correction est confirmee. |
| `sudo bash antivirus.sh --audit` | Rapport en lecture seule. Aucun changement. |
| `sudo bash antivirus.sh --fix` | Applique automatiquement les corrections jugees sures. |
| `sudo bash antivirus.sh --install-tools` | Installe ClamAV, rkhunter et chkrootkit. |

## Options

`--scan PATH`, `--exclude PATH`, `--quick`, `--full`, `--yes`, `--no-external`, `--report FILE`, `--no-color`, `--version`, `--help`

## Securite

- Les fichiers suspects sont mis en quarantaine, pas supprimes.
- `--audit` est le bon point d'entree pour un serveur en production.
- L'execution en `root` donne la couverture complete.

## Sortie

- Codes de retour : `0` propre, `1` avertissements, `2` resultats critiques
- Rapports root : `/var/log/antivirus-whole/`
- Quarantaine root : `/var/lib/antivirus-whole/quarantine/`
- Sans root : `~/.antivirus-whole/log/` et `~/.antivirus-whole/quarantine/`

## Licence

MIT, selon l'en-tete du script.

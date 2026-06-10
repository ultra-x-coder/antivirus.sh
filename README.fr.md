<div align="center">

# 🛡️ antivirus.sh

**Un seul script. Toute la sécurité Linux : analyse de malwares, audit réseau, durcissement du système.**

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Shell](https://img.shields.io/badge/100%25-Bash-blue.svg)](antivirus.sh)
[![Platform](https://img.shields.io/badge/Platform-Linux-orange.svg)](https://antivirus.sh)
[![Ubuntu](https://img.shields.io/badge/Ubuntu-any%20version-E95420.svg)](https://antivirus.sh)

🌐 **Site web et documentation complète : [antivirus.sh](https://antivirus.sh/fr/)**

[English](README.md) | [Русский](README.ru.md) | [中文](README.zh.md) | [한국어](README.ko.md) | [日本語](README.ja.md) | [Italiano](README.it.md) | [Español](README.es.md) | [Deutsch](README.de.md) | [العربية](README.ar.md) | [Français](README.fr.md)

</div>

---

`antivirus.sh` est un script Bash unique et autonome qui analyse un serveur Linux à la recherche de malwares, audite sa sécurité réseau et système et — si vous le souhaitez — corrige ce qu'il trouve. Il est conçu pour amener une **VM fraîchement installée à un état durci en une seule exécution**, et pour auditer des machines existantes sans rien y modifier.

Aucune dépendance. Aucun agent. Aucun démon. Juste du Bash — garanti de fonctionner sur **toutes les versions d'Ubuntu**, et en mode best-effort sur Debian, RHEL/CentOS/Alma/Rocky, Fedora, Arch, openSUSE et d'autres.

## ⚡ Démarrage rapide

```bash
# download
curl -fsSL https://raw.githubusercontent.com/TARGET_PLEVEHOLDER/antivirus.sh/main/antivirus.sh -o antivirus.sh

# read-only audit (changes nothing, safe everywhere)
sudo bash antivirus.sh --audit

# interactive mode: shows each problem and asks before fixing
sudo bash antivirus.sh

# harden a brand-new VM end-to-end
sudo bash antivirus.sh --harden
```

Fonctionne en **root** (couverture complète) comme en **utilisateur normal** (couverture réduite, clairement signalée).

## 🔍 Ce qu'il vérifie — plus de 70 contrôles

**Malwares et rootkits**
- noms de processus et lignes de commande de malwares / crypto-mineurs connus (xmrig, kinsing, kdevtmpfsi, …)
- processus s'exécutant depuis `/tmp`, `/dev/shm`, binaires supprimés, exécutables fileless `memfd`
- processus cachés (test de rootkit noyau par masquage readdir), modules noyau suspects
- vecteurs de rootkits userland `/etc/ld.so.preload` et `LD_PRELOAD`
- reverse shells, droppers et signatures de mineurs dans les scripts, tâches cron, unités systemd, profils shell, règles udev, scripts MOTD
- exécutables cachés dans `/tmp`, `/var/tmp`, `/dev/shm`, `/dev`
- vérification d'intégrité des binaires système essentiels contre les sommes de contrôle des paquets (`dpkg -V` / `rpm -V`)
- analyses approfondies optionnelles avec **ClamAV**, **rkhunter**, **chkrootkit** (détection automatique, installation en un seul flag)

**Réseau**
- chaque port en écoute avec son processus, analyse d'exposition (loopback vs monde entier)
- services exposés dangereux : Telnet, Redis/Mongo/Elasticsearch sans authentification, API Docker :2375, SMB, RDP, VNC, r-services…
- connexions établies vers des ports connus de pools de minage / botnets IRC
- état du pare-feu : UFW, firewalld, nftables, iptables brut — couverture IPv6 incluse
- interfaces en mode promiscuité, indicateurs d'ARP spoofing, résolveurs DNS, détournements de `/etc/hosts`

**Système**
- audit du démon SSH : connexion root, authentification par mot de passe, mots de passe vides, X11, délais d'expiration, nombre de tentatives
- comptes : utilisateurs UID 0 surnuméraires, mots de passe vides, UID dupliqués, comptes système dotés d'un shell, sudo NOPASSWD, traces de brute force
- mises à jour de sécurité en attente, unattended-upgrades, détection des versions en fin de vie (EOL), redémarrage requis
- durcissement du noyau via sysctl : ASLR, syncookies, redirections, routage par la source, portée de ptrace, restrictions dmesg/kptr…
- permissions de fichiers : `/etc/shadow`, sudoers, clés d'hôte SSH, crontab, GRUB ; audit SUID/SGID contre une liste blanche ; fichiers et répertoires modifiables par tous ; fichiers sans propriétaire ; verrous posés par des malwares via l'attribut immuable
- balayage de persistance : cron, unités systemd, `rc.local`, `at`, fichiers de démarrage du shell, `authorized_keys` de chaque utilisateur (comptes système inclus), dépôts APT tiers
- AppArmor/SELinux, auditd, synchronisation NTP, journalisation persistante, core dumps, options de montage de `/dev/shm` et `/tmp`, mitigations des vulnérabilités CPU, sécurité Docker (permissions du socket, conteneurs privilégiés, groupe docker)

## 🧰 Modes

| Commande | Ce qu'elle fait |
|---|---|
| `sudo bash antivirus.sh` | interactif : chaque correctif est affiché puis confirmé |
| `--audit` | rapport seul — zéro modification, garanti |
| `--fix` | applique automatiquement tous les correctifs sûrs |
| `--harden` | durcissement complet d'une VM neuve : pare-feu, SSH, fail2ban, sysctl, mises à jour automatiques, auditd, politiques + propose de créer un utilisateur administrateur |
| `--create-user` | création guidée d'un utilisateur sudo avec clé SSH |
| `--scan /path` | analyse antimalware d'un répertoire donné |
| `--network` / `--system` / `--malware` | n'exécute qu'un seul domaine |
| `--rollback` | annule toutes les modifications de la dernière exécution |
| `--quick` / `--full` | analyse plus rapide / la plus approfondie |
| `--report file.txt` | enregistre le rapport |

## 🛟 Garde-fous intégrés

Les correctifs susceptibles de couper l'accès distant ne sont **jamais appliqués en silence** :

- l'activation du pare-feu **pré-autorise d'abord vos ports SSH** (détectés via sshd, les sockets actives et `$SSH_CONNECTION`) ;
- `PasswordAuthentication no` est **refusé** tant qu'aucun utilisateur sudo ne possède réellement de clé SSH ;
- chaque nouvelle configuration sshd est validée avec `sshd -t` **avant** rechargement — les configurations invalides sont automatiquement restaurées, et les sessions existantes ne sont jamais coupées ;
- chaque fichier modifié est sauvegardé ; `--rollback` restaure tout ;
- les fichiers suspects sont **mis en quarantaine** (déplacés + `chmod 000`), jamais supprimés.

Codes de sortie : `0` sain · `1` avertissements · `2` problèmes critiques — pratique pour cron/CI.

## 📊 Exemple de sortie

```
==> Firewall
  [CRIT] NO active firewall detected — every listening service is fully exposed
  ?  RISKY fix: enable a firewall (UFW) with SSH port(s) pre-allowed [y/N] y
  [FIX ] enable a firewall (UFW/firewalld) with SSH port(s) pre-allowed

==> Processes & memory
  [ OK ] no known malware/miner process signatures
  [ OK ] no hidden processes (readdir-hiding rootkit test passed)

  security score: 86/100  grade: B — good
```

## 📚 Documentation complète

Catalogue détaillé des contrôles, FAQ, guide de durcissement et exemples : **[https://antivirus.sh/fr/](https://antivirus.sh/fr/)**

## ⚠️ Avertissement

`antivirus.sh` est un outil défensif d'audit et de durcissement. Il réduit la surface d'attaque et détecte les schémas de compromission les plus courants ; il ne constitue pas une garantie contre toutes les menaces. Pour une machine dont la compromission au niveau du noyau est avérée, la seule réponse sûre est la reconstruction à partir d'une image saine.

## 📄 Licence

[MIT](LICENSE) — libre pour un usage personnel comme commercial.

**Si cet outil vous a été utile, pensez à lui mettre une ⭐ sur le dépôt et à partager [antivirus.sh](https://antivirus.sh).**

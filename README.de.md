<div align="center">

# 🛡️ antivirus.sh

**Ein Skript. Volle Linux-Sicherheit: Malware-Scan, Netzwerk-Audit, Systemhärtung.**

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Shell](https://img.shields.io/badge/100%25-Bash-blue.svg)](antivirus.sh)
[![Platform](https://img.shields.io/badge/Platform-Linux-orange.svg)](https://antivirus.sh)
[![Ubuntu](https://img.shields.io/badge/Ubuntu-any%20version-E95420.svg)](https://antivirus.sh)

🌐 **Website & vollständige Dokumentation: [antivirus.sh](https://antivirus.sh/de/)**

[English](README.md) | [Русский](README.ru.md) | [中文](README.zh.md) | [한국어](README.ko.md) | [日本語](README.ja.md) | [Italiano](README.it.md) | [Español](README.es.md) | [Deutsch](README.de.md) | [العربية](README.ar.md) | [Français](README.fr.md)

</div>

---

`antivirus.sh` ist ein einzelnes, in sich geschlossenes Bash-Skript, das einen Linux-Server auf Malware scannt, seine Netzwerk- und Systemsicherheit auditiert und – auf Wunsch – die gefundenen Probleme behebt. Es ist darauf ausgelegt, eine **frische VM in einem einzigen Durchlauf in einen gehärteten Zustand** zu bringen – und bestehende Maschinen zu prüfen, ohne irgendetwas zu verändern.

Keine Abhängigkeiten. Keine Agents. Keine Daemons. Nur Bash – garantiert lauffähig auf **jeder Ubuntu-Version** und im Best-Effort-Modus auf Debian, RHEL/CentOS/Alma/Rocky, Fedora, Arch, openSUSE und anderen.

## ⚡ Schnellstart

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

Läuft als **root** (volle Abdeckung) und als **normaler Benutzer** (reduzierte Abdeckung, klar ausgewiesen).

## 🔍 Was geprüft wird – über 70 Checks

**Malware & Rootkits**
- bekannte Malware-/Krypto-Miner-Prozessnamen und Kommandozeilen (xmrig, kinsing, kdevtmpfsi, …)
- Prozesse, die aus `/tmp` oder `/dev/shm` laufen, gelöschte Binärdateien, dateilose `memfd`-Executables
- versteckte Prozesse (readdir-Hiding-Test auf Kernel-Rootkits), verdächtige Kernel-Module
- `/etc/ld.so.preload` und `LD_PRELOAD` als Userland-Rootkit-Vektoren
- Reverse Shells, Dropper und Miner-Muster in Skripten, Cron-Jobs, systemd-Units, Shell-Profilen, udev-Regeln, MOTD-Skripten
- versteckte ausführbare Dateien in `/tmp`, `/var/tmp`, `/dev/shm`, `/dev`
- Integritätsprüfung zentraler Systembinärdateien gegen Paket-Prüfsummen (`dpkg -V` / `rpm -V`)
- optionale Tiefenscans mit **ClamAV**, **rkhunter**, **chkrootkit** (automatisch erkannt, Installation mit einem einzigen Flag)

**Netzwerk**
- jeder lauschende Port samt Prozess, Expositionsanalyse (Loopback vs. weltweit erreichbar)
- gefährlich exponierte Dienste: Telnet, Redis/Mongo/Elasticsearch ohne Authentifizierung, Docker-API auf :2375, SMB, RDP, VNC, r-Dienste …
- bestehende Verbindungen zu bekannten Mining-Pool- / IRC-Botnetz-Ports
- Firewall-Status: UFW, firewalld, nftables, rohe iptables-Regeln – inklusive IPv6-Abdeckung
- Interfaces im Promiscuous-Modus, ARP-Spoofing-Indikatoren, DNS-Resolver, Hijacks in `/etc/hosts`

**System**
- SSH-Daemon-Audit: Root-Login, Passwort-Authentifizierung, leere Passwörter, X11, Timeouts, Wiederholungsversuche
- Konten: zusätzliche UID-0-Benutzer, leere Passwörter, doppelte UIDs, Systemkonten mit Login-Shell, NOPASSWD-sudo, Spuren von Brute-Force-Angriffen
- ausstehende Sicherheitsupdates, unattended-upgrades, Erkennung von EOL-Releases, ausstehender Neustart
- Kernel-Härtung via sysctl: ASLR, Syncookies, Redirects, Source Routing, ptrace-Scope, dmesg-/kptr-Restriktionen …
- Dateiberechtigungen: `/etc/shadow`, sudoers, SSH-Host-Keys, crontab, GRUB; SUID/SGID-Audit gegen eine Whitelist; weltweit beschreibbare Dateien und Verzeichnisse; Dateien ohne Eigentümer; Immutable-Flag-Sperren durch Malware
- Persistenz-Sweep: Cron, systemd-Units, `rc.local`, `at`, Shell-Startdateien, `authorized_keys` jedes Benutzers (inkl. Systemkonten), APT-Repositories von Drittanbietern
- AppArmor/SELinux, auditd, NTP-Synchronisation, persistentes Logging, Core Dumps, Mount-Optionen für `/dev/shm` & `/tmp`, CPU-Schwachstellen-Mitigationen, Docker-Sicherheit (Socket-Rechte, privilegierte Container, docker-Gruppe)

## 🧰 Modi

| Befehl | Wirkung |
|---|---|
| `sudo bash antivirus.sh` | interaktiv: jeder Fix wird angezeigt und bestätigt |
| `--audit` | nur Bericht – garantiert keine Änderungen |
| `--fix` | alle sicheren Fixes automatisch anwenden |
| `--harden` | vollständige Härtung einer frischen VM: Firewall, SSH, fail2ban, sysctl, Auto-Updates, auditd, Richtlinien + Angebot, einen Admin-Benutzer anzulegen |
| `--create-user` | geführte Anlage eines sudo-Benutzers mit SSH-Key |
| `--scan /path` | Malware-Scan eines bestimmten Verzeichnisses |
| `--network` / `--system` / `--malware` | nur einen Bereich ausführen |
| `--rollback` | alle Änderungen des letzten Laufs rückgängig machen |
| `--quick` / `--full` | schnellerer / gründlichster Scan |
| `--report file.txt` | Bericht speichern |

## 🛟 Sicherheitskonzept

Fixes, die den Fernzugriff kappen könnten, werden **niemals stillschweigend angewendet**:

- vor dem Aktivieren der Firewall werden **die SSH-Ports vorab freigegeben** (ermittelt aus der sshd-Konfiguration, aktiven Sockets und `$SSH_CONNECTION`);
- `PasswordAuthentication no` wird **verweigert**, solange kein sudo-fähiger Benutzer tatsächlich einen SSH-Key besitzt;
- jede neue sshd-Konfiguration wird **vor** dem Reload mit `sshd -t` validiert – ungültige Konfigurationen werden automatisch zurückgesetzt, bestehende Sessions werden nie getrennt;
- jede geänderte Datei wird gesichert; `--rollback` stellt alles wieder her;
- verdächtige Dateien kommen **in Quarantäne** (verschoben + `chmod 000`) und werden niemals gelöscht.

Exit-Codes: `0` sauber · `1` Warnungen · `2` kritische Funde – ideal für Cron und CI.

## 📊 Beispielausgabe

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

## 📚 Vollständige Dokumentation

Detaillierter Check-Katalog, FAQ, Härtungsleitfaden und Beispiele: **[https://antivirus.sh/de/](https://antivirus.sh/de/)**

## ⚠️ Haftungsausschluss

`antivirus.sh` ist ein defensives Audit- und Härtungswerkzeug. Es reduziert die Angriffsfläche und erkennt verbreitete Kompromittierungsmuster – eine Garantie gegen jede Bedrohung ist es nicht. Bei einer Maschine mit bestätigter Kompromittierung auf Kernel-Ebene ist der einzig sichere Weg der Neuaufbau aus einem sauberen Image.

## 📄 Lizenz

[MIT](LICENSE) – frei für private und kommerzielle Nutzung.

**Wenn dieses Tool geholfen hat: bitte das Repo mit einem ⭐ Stern versehen und [antivirus.sh](https://antivirus.sh) weiterempfehlen.**

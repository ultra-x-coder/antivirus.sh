# antivirus_whole

<div align="center">

**Eigenstaendiger Linux-Antivirus- und Malware-Scanner in einem Bash-Skript.**

[English](README.md) | [Русский](README.ru.md) | [Español](README.es.md) | [中文](README.zh.md) | [日本語](README.ja.md) | [한국어](README.ko.md) | Deutsch | [العربية](README.ar.md) | [Français](README.fr.md) | [Italiano](README.it.md)

</div>

---

`antivirus.sh` ist ein selbststaendiger Bash-Scanner fuer Linux-Server. Er prueft auf Malware, Persistenzmechanismen, verdaechtige Prozesse, Paketintegritaet, grundlegende Netzwerkindikatoren und quarantisiert auffaellige Dateien sicher. Dieses Repository enthaelt nur den Antivirus-Teil, der aus der groesseren `antivirus.sh`-Suite herausgeloest wurde.

Die README-Struktur orientiert sich am Stil des Referenzprojekts: <https://github.com/ultra-x-coder/antivirus.sh/>

## Schnellstart

```bash
chmod +x antivirus.sh
sudo bash antivirus.sh
sudo bash antivirus.sh --audit
sudo bash antivirus.sh --fix
sudo bash antivirus.sh --scan /var/www
sudo bash antivirus.sh --full
```

## Was geprueft wird

- Reverse Shells, Dropper, Miner und typische Backdoor-Muster
- Versteckte oder ausfuehrbare Dateien in `/tmp`, `/var/tmp` und `/dev/shm`
- Bekannte Malware-Prozessnamen, `memfd`-Prozesse und Binaries aus Temp-Pfaden
- Persistenz ueber cron, systemd, `rc.local`, Shell-Startdateien, udev und `authorized_keys`
- Ausgehende Verbindungen zu typischen Mining-Pool- oder IRC-Botnet-Ports
- Integritaetspruefung kritischer Systembinaries mit `dpkg -V` oder `rpm -V`
- Optionale Tiefenscans mit ClamAV, rkhunter und chkrootkit

## Modi

| Befehl | Beschreibung |
| --- | --- |
| `sudo bash antivirus.sh` | Interaktiver Modus. Jede Korrektur wird bestaetigt. |
| `sudo bash antivirus.sh --audit` | Nur Bericht. Keine Aenderungen. |
| `sudo bash antivirus.sh --fix` | Wendet sichere Korrekturen automatisch an. |
| `sudo bash antivirus.sh --install-tools` | Installiert ClamAV, rkhunter und chkrootkit. |

## Optionen

`--scan PATH`, `--exclude PATH`, `--quick`, `--full`, `--yes`, `--no-external`, `--report FILE`, `--no-color`, `--version`, `--help`

## Sicherheit

- Verdaechtige Dateien werden quarantisiert, nicht geloescht.
- Fuer Produktionssysteme ist `--audit` der sichere Einstieg.
- Fuer volle Abdeckung sollte das Skript als `root` laufen.

## Ausgabe

- Exit-Codes: `0` sauber, `1` Warnungen, `2` kritische Funde
- Root-Berichte: `/var/log/antivirus-whole/`
- Root-Quarantaene: `/var/lib/antivirus-whole/quarantine/`
- Ohne root: `~/.antivirus-whole/log/` und `~/.antivirus-whole/quarantine/`

## Lizenz

MIT gemaess Script-Header.

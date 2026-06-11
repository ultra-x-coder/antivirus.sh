# antivirus.sh

<div align="center">

**Antivirus e scanner malware per Linux in un unico script Bash.**

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

[English](README.md) | [Русский](README.ru.md) | [Español](README.es.md) | [中文](README.zh.md) | [日本語](README.ja.md) | [한국어](README.ko.md) | [Deutsch](README.ge.md) | [العربية](README.ar.md) | [Français](README.fr.md) | Italiano

</div>

---

`antivirus.sh` e uno scanner Bash autonomo per server Linux. Si concentra su rilevamento malware, controlli di persistenza, ispezione dei processi, integrita dei pacchetti, indicatori di rete di base e quarantena sicura. Questo repository contiene solo la parte antivirus estratta dalla suite di sicurezza piu ampia `antivirus.sh`.

## Avvio rapido

```bash
chmod +x antivirus.sh
sudo bash antivirus.sh
sudo bash antivirus.sh --audit
sudo bash antivirus.sh --fix
sudo bash antivirus.sh --scan /var/www
sudo bash antivirus.sh --full
```

## Controlli eseguiti

- Reverse shell, droppers, miner e pattern comuni di backdoor
- File eseguibili nascosti in `/tmp`, `/var/tmp` e `/dev/shm`
- Nomi di processi malevoli noti, processi `memfd` e binari avviati da directory temporanee
- Persistenza tramite cron, systemd, `rc.local`, file di avvio shell, udev e `authorized_keys`
- Connessioni in uscita verso porte tipiche di mining pool o botnet IRC
- Verifica di integrita dei binari critici con `dpkg -V` o `rpm -V`
- Scansioni opzionali con ClamAV, rkhunter e chkrootkit

## Modalita

| Comando | Descrizione |
| --- | --- |
| `sudo bash antivirus.sh` | Modalita interattiva. Ogni correzione viene confermata. |
| `sudo bash antivirus.sh --audit` | Solo report. Nessuna modifica. |
| `sudo bash antivirus.sh --fix` | Applica automaticamente le correzioni sicure. |
| `sudo bash antivirus.sh --install-tools` | Installa ClamAV, rkhunter e chkrootkit. |

## Opzioni

`--scan PATH`, `--exclude PATH`, `--quick`, `--full`, `--yes`, `--no-external`, `--report FILE`, `--no-color`, `--version`, `--help`

## Sicurezza

- I file sospetti vengono messi in quarantena, non eliminati.
- `--audit` e la scelta corretta per sistemi di produzione.
- Per la copertura completa e consigliato eseguire come `root`.

## Output

- Codici di uscita: `0` pulito, `1` avvisi, `2` rilevamenti critici
- Report root: `/var/log/antivirus-whole/`
- Quarantena root: `/var/lib/antivirus-whole/quarantine/`
- Senza root: `~/.antivirus-whole/log/` e `~/.antivirus-whole/quarantine/`

## Licenza

MIT, come dichiarato nell'intestazione dello script.

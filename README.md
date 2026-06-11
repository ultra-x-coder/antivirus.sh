# antivirus.sh

<div align="center">

**Standalone Linux antivirus and malware scanner in one Bash script.**

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

English | [Русский](README.ru.md) | [Español](README.es.md) | [中文](README.zh.md) | [日本語](README.ja.md) | [한국어](README.ko.md) | [Deutsch](README.ge.md) | [العربية](README.ar.md) | [Français](README.fr.md) | [Italiano](README.it.md)

</div>

---

`antivirus.sh` is a self-contained Bash scanner for Linux servers. It focuses on malware detection, persistence checks, process inspection, package integrity, basic network indicators, and safe quarantine. This repository contains the antivirus-only part extracted from the broader `antivirus.sh` security suite.

The README structure is inspired by the presentation style used in the reference project: <https://github.com/ultra-x-coder/antivirus.sh/>

## Quick start

```bash
chmod +x antivirus.sh

# interactive scan: show findings and confirm fixes
sudo bash antivirus.sh

# read-only audit: report only, change nothing
sudo bash antivirus.sh --audit

# automatic safe fixes
sudo bash antivirus.sh --fix

# scan a specific path
sudo bash antivirus.sh --scan /var/www

# deepest scan
sudo bash antivirus.sh --full
```

Works best as `root`. It can run as a regular user with reduced coverage and user-writable report/quarantine paths.

## What it checks

### Malware and suspicious files

- Reverse shells, droppers, crypto-miners, and common backdoor patterns in scripts and text files
- Hidden or executable payloads in `/tmp`, `/var/tmp`, and `/dev/shm`
- Suspicious files under custom scan paths passed with `--scan`
- Optional deep scans through ClamAV when installed

### Processes and runtime indicators

- Known malware and miner process names
- Suspicious command lines such as `xmrig`, `minerd`, `kdevtmpfsi`, `kinsing`, and similar families
- Binaries started from temporary directories
- Fileless `memfd` processes
- Hidden-process/rootkit indicators
- Suspicious kernel modules associated with common Linux rootkits

### Persistence and backdoors

- `/etc/ld.so.preload`
- Cron jobs and scheduled persistence
- Systemd unit files
- `rc.local`
- Shell startup files
- Udev rules
- Suspicious `authorized_keys` entries
- Third-party package repository entries

### Network and integrity checks

- Outbound connections to ports commonly used by mining pools or IRC botnets
- Integrity verification of security-critical system binaries through `dpkg -V` or `rpm -V`
- Optional `rkhunter` and `chkrootkit` runs when installed

## Modes

| Command | What it does |
| --- | --- |
| `sudo bash antivirus.sh` | Interactive scan. Each fix is confirmed. |
| `sudo bash antivirus.sh --audit` | Read-only report. No changes are made. |
| `sudo bash antivirus.sh --fix` | Applies safe fixes automatically. Risky fixes may still ask. |
| `sudo bash antivirus.sh --install-tools` | Installs ClamAV, rkhunter, and chkrootkit through the system package manager. |

## Options

| Option | Description |
| --- | --- |
| `--scan PATH` | Scan a specific directory. Repeatable. |
| `--exclude PATH` | Exclude a path from scans. Repeatable. |
| `--quick` | Skip slower checks such as ClamAV, rkhunter, and hidden-process tests. |
| `--full` | Run the deepest scan, including broader filesystem coverage. |
| `--yes`, `-y` | Assume yes for every prompt, including risky actions. |
| `--no-external` | Do not run or suggest third-party scanners. |
| `--report FILE` | Write the report to a custom file. |
| `--no-color` | Disable colored output. |
| `--version` | Print the current version. |
| `--help` | Show built-in help. |

## Safety model

- Malicious files are quarantined, not deleted.
- Audit mode is safe for inspection on production hosts.
- Interactive mode is the default.
- Automatic fixes are limited to what the script considers safe.
- Risky actions are called out before execution unless `--yes` is used.

## Output

- Exit codes: `0` clean, `1` warnings, `2` critical findings
- Root reports: `/var/log/antivirus-whole/`
- Root quarantine: `/var/lib/antivirus-whole/quarantine/`
- Non-root reports: `~/.antivirus-whole/log/`
- Non-root quarantine: `~/.antivirus-whole/quarantine/`

Quarantine actions are logged in `quarantine.log`. Restoring a file is a manual move-back operation after review.

## Requirements

- Bash on Linux
- `root` recommended for full coverage
- No mandatory external dependencies
- Optional tools: ClamAV, rkhunter, chkrootkit

## Scope and limitations

- Designed primarily for Linux servers
- Best effort outside Ubuntu/Debian-style environments
- This is a heuristic scanner, not a replacement for kernel hardening, EDR, or continuous monitoring
- Signature-free checks can produce false positives and should be reviewed before restoring or whitelisting files

## Files

```text
antivirus.sh   main standalone scanner
README.md      English documentation
README.*.md    localized documentation
```

## License

MIT, as declared in the script header.

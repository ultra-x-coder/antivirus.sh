<div align="center">

# 🛡️ antivirus.sh

**One script. Full Linux security: malware scan, network audit, system hardening.**

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Shell](https://img.shields.io/badge/100%25-Bash-blue.svg)](antivirus.sh)
[![Platform](https://img.shields.io/badge/Platform-Linux-orange.svg)](https://antivirus.sh)
[![Ubuntu](https://img.shields.io/badge/Ubuntu-any%20version-E95420.svg)](https://antivirus.sh)

🌐 **Website & full documentation: [antivirus.sh](https://antivirus.sh)**

[English](README.md) | [Русский](README.ru.md) | [中文](README.zh.md) | [한국어](README.ko.md) | [日本語](README.ja.md) | [Italiano](README.it.md) | [Español](README.es.md) | [Deutsch](README.de.md) | [العربية](README.ar.md) | [Français](README.fr.md)

</div>

---

`antivirus.sh` is a single self-contained Bash script that scans a Linux server for malware, audits its network and system security, and — if you want — fixes what it finds. It is built to take a **fresh VM to a hardened state in one run**, and to audit existing machines without changing anything.

No dependencies. No agents. No daemons. Just Bash — guaranteed to work on **every Ubuntu version**, and in best-effort mode on Debian, RHEL/CentOS/Alma/Rocky, Fedora, Arch, openSUSE and others.

## ⚡ Quick start

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

Works as **root** (full coverage) and as a **regular user** (reduced coverage, clearly reported).

## 🔍 What it checks — 70+ checks

**Malware & rootkits**
- known malware / crypto-miner process names and command lines (xmrig, kinsing, kdevtmpfsi, …)
- processes running from `/tmp`, `/dev/shm`, deleted binaries, fileless `memfd` executables
- hidden processes (readdir-hiding kernel-rootkit test), suspicious kernel modules
- `/etc/ld.so.preload` and `LD_PRELOAD` userland-rootkit vectors
- reverse shells, droppers and miner patterns inside scripts, cron jobs, systemd units, shell profiles, udev rules, MOTD scripts
- hidden executables in `/tmp`, `/var/tmp`, `/dev/shm`, `/dev`
- integrity verification of core system binaries against package checksums (`dpkg -V` / `rpm -V`)
- optional deep scans with **ClamAV**, **rkhunter**, **chkrootkit** (auto-detected, one-flag install)

**Network**
- every listening port with process, exposure analysis (loopback vs world)
- dangerous exposed services: Telnet, unauthenticated Redis/Mongo/Elasticsearch, Docker API :2375, SMB, RDP, VNC, r-services …
- established connections to known mining-pool / IRC-botnet ports
- firewall state: UFW, firewalld, nftables, raw iptables — including IPv6 coverage
- promiscuous interfaces, ARP-spoofing indicators, DNS resolvers, `/etc/hosts` hijacks

**System**
- SSH daemon audit: root login, password auth, empty passwords, X11, timeouts, retries
- accounts: extra UID-0 users, empty passwords, duplicate UIDs, system accounts with shells, NOPASSWD sudo, brute-force evidence
- pending security updates, unattended-upgrades, EOL release detection, reboot-required
- kernel hardening via sysctl: ASLR, syncookies, redirects, source routing, ptrace scope, dmesg/kptr restrictions …
- file permissions: `/etc/shadow`, sudoers, SSH host keys, crontab, GRUB; SUID/SGID audit against a whitelist; world-writable files & dirs; unowned files; immutable-flag malware locks
- persistence sweep: cron, systemd units, `rc.local`, `at`, shell startup files, `authorized_keys` of every user (incl. system accounts), third-party APT repos
- AppArmor/SELinux, auditd, NTP sync, persistent logging, core dumps, `/dev/shm` & `/tmp` mount options, CPU vulnerability mitigations, Docker security (socket perms, privileged containers, docker group)

## 🧰 Modes

| Command | What it does |
|---|---|
| `sudo bash antivirus.sh` | interactive: every fix is shown and confirmed |
| `--audit` | report only — guaranteed zero changes |
| `--fix` | apply all safe fixes automatically |
| `--harden` | full hardening of a fresh VM: firewall, SSH, fail2ban, sysctl, auto-updates, auditd, policies + offers to create an admin user |
| `--create-user` | guided creation of a sudo user with SSH key |
| `--scan /path` | malware-scan a specific directory |
| `--network` / `--system` / `--malware` | run one area only |
| `--rollback` | undo every change from the last run |
| `--quick` / `--full` | faster / deepest scan |
| `--report file.txt` | save the report |

## 🛟 Safety design

Fixes that could cut off remote access are **never applied silently**:

- enabling the firewall **pre-allows your SSH port(s)** first (parsed from sshd, live sockets and `$SSH_CONNECTION`);
- `PasswordAuthentication no` is **refused** unless a sudo-capable user actually has an SSH key;
- every new sshd config is validated with `sshd -t` **before** reload — invalid configs are auto-reverted, and existing sessions are never dropped;
- every modified file is backed up; `--rollback` restores everything;
- suspicious files are **quarantined** (moved + `chmod 000`), never deleted.

Exit codes: `0` clean · `1` warnings · `2` critical findings — cron/CI friendly.

## 📊 Example output

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

## 📚 Full documentation

Detailed check catalog, FAQ, hardening guide and examples: **[https://antivirus.sh](https://antivirus.sh)**

## ⚠️ Disclaimer

`antivirus.sh` is a defensive audit & hardening tool. It reduces attack surface and detects common compromise patterns; it is not a guarantee against every threat. For a machine with a confirmed kernel-level compromise, the only safe fix is rebuilding from a clean image.

## 📄 License

[MIT](LICENSE) — free for personal and commercial use.

**If this tool helped you, please ⭐ star the repo and share [antivirus.sh](https://antivirus.sh).**

<div align="center">

# 🛡️ antivirus.sh

**Uno script. Sicurezza Linux completa: scansione malware, audit di rete, hardening del sistema.**

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Shell](https://img.shields.io/badge/100%25-Bash-blue.svg)](antivirus.sh)
[![Platform](https://img.shields.io/badge/Platform-Linux-orange.svg)](https://antivirus.sh)
[![Ubuntu](https://img.shields.io/badge/Ubuntu-any%20version-E95420.svg)](https://antivirus.sh)

🌐 **Sito web e documentazione completa: [antivirus.sh](https://antivirus.sh/it/)**

[English](README.md) | [Русский](README.ru.md) | [中文](README.zh.md) | [한국어](README.ko.md) | [日本語](README.ja.md) | [Italiano](README.it.md) | [Español](README.es.md) | [Deutsch](README.de.md) | [العربية](README.ar.md) | [Français](README.fr.md)

</div>

---

`antivirus.sh` è un singolo script Bash autonomo che scansiona un server Linux alla ricerca di malware, ne verifica la sicurezza di rete e di sistema e — se vuoi — corregge ciò che trova. È progettato per portare una **VM appena creata a uno stato hardened in un'unica esecuzione**, e per fare l'audit di macchine esistenti senza modificare nulla.

Nessuna dipendenza. Nessun agent. Nessun demone. Solo Bash — funzionamento garantito su **ogni versione di Ubuntu**, e in modalità best-effort su Debian, RHEL/CentOS/Alma/Rocky, Fedora, Arch, openSUSE e altre.

## ⚡ Avvio rapido

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

Funziona sia come **root** (copertura completa) sia come **utente normale** (copertura ridotta, segnalata con chiarezza).

## 🔍 Cosa controlla — oltre 70 controlli

**Malware e rootkit**
- nomi di processo e righe di comando di malware e crypto-miner noti (xmrig, kinsing, kdevtmpfsi, …)
- processi in esecuzione da `/tmp`, `/dev/shm`, binari eliminati, eseguibili fileless `memfd`
- processi nascosti (test anti kernel-rootkit basato sull'occultamento in readdir), moduli kernel sospetti
- vettori di rootkit userland `/etc/ld.so.preload` e `LD_PRELOAD`
- reverse shell, dropper e pattern da miner dentro script, cron job, unit systemd, profili di shell, regole udev, script MOTD
- eseguibili nascosti in `/tmp`, `/var/tmp`, `/dev/shm`, `/dev`
- verifica dell'integrità dei binari di sistema fondamentali rispetto ai checksum dei pacchetti (`dpkg -V` / `rpm -V`)
- scansioni approfondite opzionali con **ClamAV**, **rkhunter**, **chkrootkit** (rilevati automaticamente, installazione con un solo flag)

**Rete**
- ogni porta in ascolto con il relativo processo, analisi dell'esposizione (loopback vs mondo esterno)
- servizi esposti pericolosi: Telnet, Redis/Mongo/Elasticsearch senza autenticazione, Docker API :2375, SMB, RDP, VNC, r-services …
- connessioni stabilite verso porte note di mining pool / botnet IRC
- stato del firewall: UFW, firewalld, nftables, iptables puro — copertura IPv6 inclusa
- interfacce in modalità promiscua, indicatori di ARP spoofing, resolver DNS, hijack di `/etc/hosts`

**Sistema**
- audit del demone SSH: login root, autenticazione con password, password vuote, X11, timeout, tentativi
- account: utenti UID-0 aggiuntivi, password vuote, UID duplicati, account di sistema con shell, sudo NOPASSWD, tracce di brute force
- aggiornamenti di sicurezza in sospeso, unattended-upgrades, rilevamento di release EOL, riavvio richiesto
- hardening del kernel via sysctl: ASLR, syncookies, redirect, source routing, ptrace scope, restrizioni dmesg/kptr …
- permessi dei file: `/etc/shadow`, sudoers, chiavi host SSH, crontab, GRUB; audit SUID/SGID rispetto a una whitelist; file e directory scrivibili da chiunque; file senza proprietario; lock da malware con flag immutable
- ricognizione della persistenza: cron, unit systemd, `rc.local`, `at`, file di avvio della shell, `authorized_keys` di ogni utente (inclusi gli account di sistema), repository APT di terze parti
- AppArmor/SELinux, auditd, sincronizzazione NTP, logging persistente, core dump, opzioni di mount di `/dev/shm` e `/tmp`, mitigazioni delle vulnerabilità della CPU, sicurezza Docker (permessi del socket, container privilegiati, gruppo docker)

## 🧰 Modalità

| Comando | Cosa fa |
|---|---|
| `sudo bash antivirus.sh` | interattiva: ogni fix viene mostrato e confermato |
| `--audit` | solo report — zero modifiche garantite |
| `--fix` | applica automaticamente tutti i fix sicuri |
| `--harden` | hardening completo di una VM appena creata: firewall, SSH, fail2ban, sysctl, aggiornamenti automatici, auditd, policy + propone la creazione di un utente amministratore |
| `--create-user` | creazione guidata di un utente sudo con chiave SSH |
| `--scan /path` | scansione malware di una directory specifica |
| `--network` / `--system` / `--malware` | esegue una sola area |
| `--rollback` | annulla ogni modifica dell'ultima esecuzione |
| `--quick` / `--full` | scansione più rapida / più approfondita |
| `--report file.txt` | salva il report |

## 🛟 Sicurezza by design

I fix che potrebbero tagliarti fuori dall'accesso remoto **non vengono mai applicati in silenzio**:

- l'attivazione del firewall **autorizza prima le tue porte SSH** (rilevate dalla configurazione di sshd, dai socket attivi e da `$SSH_CONNECTION`);
- `PasswordAuthentication no` viene **rifiutato** a meno che un utente con privilegi sudo non possieda davvero una chiave SSH;
- ogni nuova configurazione di sshd viene validata con `sshd -t` **prima** del reload — le configurazioni non valide vengono ripristinate automaticamente e le sessioni esistenti non vengono mai interrotte;
- ogni file modificato viene salvato in backup; `--rollback` ripristina tutto;
- i file sospetti vengono **messi in quarantena** (spostati + `chmod 000`), mai eliminati.

Codici di uscita: `0` pulito · `1` warning · `2` problemi critici — perfetti per cron/CI.

## 📊 Esempio di output

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

## 📚 Documentazione completa

Catalogo dettagliato dei controlli, FAQ, guida all'hardening ed esempi: **[https://antivirus.sh/it/](https://antivirus.sh/it/)**

## ⚠️ Avvertenze

`antivirus.sh` è uno strumento difensivo di audit e hardening. Riduce la superficie d'attacco e rileva i pattern di compromissione più comuni; non è una garanzia contro ogni minaccia. Per una macchina con una compromissione confermata a livello kernel, l'unica soluzione sicura è ricostruirla da un'immagine pulita.

## 📄 Licenza

[MIT](LICENSE) — libero per uso personale e commerciale.

**Se questo strumento ti è stato utile, metti una ⭐ al repo e condividi [antivirus.sh](https://antivirus.sh).**

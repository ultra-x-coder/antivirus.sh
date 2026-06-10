<div align="center">

# 🛡️ antivirus.sh

**Un solo script. Seguridad Linux completa: escaneo de malware, auditoría de red, hardening del sistema.**

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Shell](https://img.shields.io/badge/100%25-Bash-blue.svg)](antivirus.sh)
[![Platform](https://img.shields.io/badge/Platform-Linux-orange.svg)](https://antivirus.sh)
[![Ubuntu](https://img.shields.io/badge/Ubuntu-any%20version-E95420.svg)](https://antivirus.sh)

🌐 **Sitio web y documentación completa: [antivirus.sh](https://antivirus.sh/es/)**

[English](README.md) | [Русский](README.ru.md) | [中文](README.zh.md) | [한국어](README.ko.md) | [日本語](README.ja.md) | [Italiano](README.it.md) | [Español](README.es.md) | [Deutsch](README.de.md) | [العربية](README.ar.md) | [Français](README.fr.md)

</div>

---

`antivirus.sh` es un único script Bash autocontenido que escanea un servidor Linux en busca de malware, audita la seguridad de su red y de su sistema y — si tú quieres — corrige lo que encuentra. Está diseñado para llevar una **VM recién creada a un estado endurecido en una sola ejecución**, y para auditar máquinas existentes sin cambiar nada.

Sin dependencias. Sin agentes. Sin demonios. Solo Bash: funcionamiento garantizado en **todas las versiones de Ubuntu**, y en modo best-effort en Debian, RHEL/CentOS/Alma/Rocky, Fedora, Arch, openSUSE y otros.

## ⚡ Inicio rápido

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

Funciona como **root** (cobertura completa) y como **usuario normal** (cobertura reducida, claramente indicada en el informe).

## 🔍 Qué comprueba — más de 70 comprobaciones

**Malware y rootkits**
- nombres de procesos y líneas de comandos de malware y criptomineros conocidos (xmrig, kinsing, kdevtmpfsi, …)
- procesos ejecutándose desde `/tmp`, `/dev/shm`, binarios eliminados, ejecutables `memfd` sin archivo
- procesos ocultos (test de rootkit de kernel por ocultación en readdir), módulos de kernel sospechosos
- vectores de rootkit en espacio de usuario vía `/etc/ld.so.preload` y `LD_PRELOAD`
- reverse shells, droppers y patrones de mineros dentro de scripts, tareas cron, unidades systemd, perfiles de shell, reglas udev, scripts MOTD
- ejecutables ocultos en `/tmp`, `/var/tmp`, `/dev/shm`, `/dev`
- verificación de integridad de los binarios esenciales del sistema contra los checksums de los paquetes (`dpkg -V` / `rpm -V`)
- escaneos profundos opcionales con **ClamAV**, **rkhunter**, **chkrootkit** (autodetectados, se instalan con una sola opción)

**Red**
- cada puerto en escucha con su proceso, análisis de exposición (loopback vs todo Internet)
- servicios expuestos peligrosos: Telnet, Redis/Mongo/Elasticsearch sin autenticación, Docker API :2375, SMB, RDP, VNC, r-services…
- conexiones establecidas hacia puertos conocidos de pools de minería / botnets IRC
- estado del firewall: UFW, firewalld, nftables, iptables puro — incluida la cobertura IPv6
- interfaces en modo promiscuo, indicadores de ARP spoofing, resolutores DNS, secuestros de `/etc/hosts`

**Sistema**
- auditoría del demonio SSH: login de root, autenticación por contraseña, contraseñas vacías, X11, timeouts, reintentos
- cuentas: usuarios UID 0 adicionales, contraseñas vacías, UID duplicados, cuentas de sistema con shell, sudo NOPASSWD, evidencias de fuerza bruta
- actualizaciones de seguridad pendientes, unattended-upgrades, detección de versiones EOL, reinicio requerido
- hardening del kernel vía sysctl: ASLR, syncookies, redirects, source routing, ptrace scope, restricciones de dmesg/kptr…
- permisos de archivos: `/etc/shadow`, sudoers, claves de host SSH, crontab, GRUB; auditoría SUID/SGID contra una whitelist; archivos y directorios escribibles por cualquiera; archivos sin propietario; bloqueos de malware con flag de inmutabilidad
- barrido de persistencia: cron, unidades systemd, `rc.local`, `at`, archivos de arranque del shell, `authorized_keys` de cada usuario (incluidas las cuentas de sistema), repositorios APT de terceros
- AppArmor/SELinux, auditd, sincronización NTP, registro persistente, core dumps, opciones de montaje de `/dev/shm` y `/tmp`, mitigaciones de vulnerabilidades de CPU, seguridad de Docker (permisos del socket, contenedores privilegiados, grupo docker)

## 🧰 Modos

| Comando | Qué hace |
|---|---|
| `sudo bash antivirus.sh` | interactivo: cada corrección se muestra y se confirma |
| `--audit` | solo informe — cero cambios garantizado |
| `--fix` | aplica automáticamente todas las correcciones seguras |
| `--harden` | hardening completo de una VM nueva: firewall, SSH, fail2ban, sysctl, actualizaciones automáticas, auditd, políticas + ofrece crear un usuario administrador |
| `--create-user` | creación guiada de un usuario sudo con clave SSH |
| `--scan /path` | escanea en busca de malware un directorio concreto |
| `--network` / `--system` / `--malware` | ejecuta una sola área |
| `--rollback` | deshace todos los cambios de la última ejecución |
| `--quick` / `--full` | escaneo más rápido / más profundo |
| `--report file.txt` | guarda el informe |

## 🛟 Diseñado para no dejarte fuera

Las correcciones que podrían cortar el acceso remoto **nunca se aplican en silencio**:

- al habilitar el firewall, **primero se permiten tus puertos SSH** (detectados a partir de sshd, los sockets activos y `$SSH_CONNECTION`);
- `PasswordAuthentication no` se **rechaza** salvo que un usuario con permisos sudo tenga realmente una clave SSH;
- cada nueva configuración de sshd se valida con `sshd -t` **antes** del reload — las configuraciones inválidas se revierten automáticamente, y las sesiones existentes nunca se cortan;
- cada archivo modificado se respalda; `--rollback` lo restaura todo;
- los archivos sospechosos se ponen **en cuarentena** (se mueven + `chmod 000`), nunca se eliminan.

Códigos de salida: `0` limpio · `1` advertencias · `2` hallazgos críticos — ideal para cron/CI.

## 📊 Ejemplo de salida

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

## 📚 Documentación completa

Catálogo detallado de comprobaciones, FAQ, guía de hardening y ejemplos: **[https://antivirus.sh/es/](https://antivirus.sh/es/)**

## ⚠️ Aviso legal

`antivirus.sh` es una herramienta defensiva de auditoría y hardening. Reduce la superficie de ataque y detecta patrones de compromiso habituales; no es una garantía contra todas las amenazas. Para una máquina con un compromiso confirmado a nivel de kernel, la única solución segura es reconstruirla desde una imagen limpia.

## 📄 Licencia

[MIT](LICENSE) — libre para uso personal y comercial.

**Si esta herramienta te ha ayudado, dale una ⭐ al repositorio y comparte [antivirus.sh](https://antivirus.sh).**

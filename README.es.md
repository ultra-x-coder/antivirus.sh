# antivirus.sh

<div align="center">

**Antivirus y escáner de malware para Linux en un solo script Bash.**

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

[English](README.md) | [Русский](README.ru.md) | Español | [中文](README.zh.md) | [日本語](README.ja.md) | [한국어](README.ko.md) | [Deutsch](README.ge.md) | [العربية](README.ar.md) | [Français](README.fr.md) | [Italiano](README.it.md)

</div>

---

`antivirus.sh` es un escáner Bash autocontenido para servidores Linux. Se centra en detección de malware, comprobaciones de persistencia, inspección de procesos, integridad de paquetes, indicadores básicos de red y cuarentena segura. Este repositorio contiene solo la parte antivirus extraída del conjunto de seguridad más amplio `antivirus.sh`.

La estructura de este README toma como referencia el estilo del proyecto: <https://github.com/ultra-x-coder/antivirus.sh/>

## Inicio rápido

```bash
chmod +x antivirus.sh
sudo bash antivirus.sh
sudo bash antivirus.sh --audit
sudo bash antivirus.sh --fix
sudo bash antivirus.sh --scan /var/www
sudo bash antivirus.sh --full
```

## Que comprueba

- Shells reversas, droppers, mineros y patrones de puertas traseras
- Ejecutables ocultos en `/tmp`, `/var/tmp` y `/dev/shm`
- Nombres de procesos maliciosos conocidos y procesos `memfd`
- Persistencia en cron, systemd, `rc.local`, perfiles de shell, udev y `authorized_keys`
- Conexiones salientes a puertos típicos de pools de minería o botnets IRC
- Integridad de binarios críticos mediante `dpkg -V` o `rpm -V`
- Escaneos opcionales con ClamAV, rkhunter y chkrootkit

## Modos

| Comando | Descripción |
| --- | --- |
| `sudo bash antivirus.sh` | Modo interactivo. Confirma cada corrección. |
| `sudo bash antivirus.sh --audit` | Solo informe. No modifica nada. |
| `sudo bash antivirus.sh --fix` | Aplica correcciones seguras automáticamente. |
| `sudo bash antivirus.sh --install-tools` | Instala ClamAV, rkhunter y chkrootkit. |

## Opciones

`--scan PATH`, `--exclude PATH`, `--quick`, `--full`, `--yes`, `--no-external`, `--report FILE`, `--no-color`, `--version`, `--help`

## Seguridad

- Los archivos sospechosos se ponen en cuarentena, no se eliminan.
- `--audit` es el modo seguro para hosts en producción.
- Ejecutar como `root` ofrece la cobertura completa.

## Salida

- Códigos de salida: `0` limpio, `1` advertencias, `2` hallazgos críticos
- Informes como `root`: `/var/log/antivirus-whole/`
- Cuarentena como `root`: `/var/lib/antivirus-whole/quarantine/`
- Sin `root`: `~/.antivirus-whole/log/` y `~/.antivirus-whole/quarantine/`

## Licencia

MIT, según la cabecera del script.

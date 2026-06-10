<div align="center">

# 🛡️ antivirus.sh

**Один скрипт. Полная безопасность Linux: поиск вредоносного ПО, аудит сети, усиление защиты системы.**

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Shell](https://img.shields.io/badge/100%25-Bash-blue.svg)](antivirus.sh)
[![Platform](https://img.shields.io/badge/Platform-Linux-orange.svg)](https://antivirus.sh)
[![Ubuntu](https://img.shields.io/badge/Ubuntu-any%20version-E95420.svg)](https://antivirus.sh)

🌐 **Сайт и полная документация: [antivirus.sh/ru](https://antivirus.sh/ru/)**

[English](README.md) | [Русский](README.ru.md) | [中文](README.zh.md) | [한국어](README.ko.md) | [日本語](README.ja.md) | [Italiano](README.it.md) | [Español](README.es.md) | [Deutsch](README.de.md) | [العربية](README.ar.md) | [Français](README.fr.md)

</div>

---

`antivirus.sh` — это один самодостаточный Bash-скрипт, который сканирует Linux-сервер на вредоносное ПО, проводит аудит сетевой и системной безопасности и — если вы захотите — исправляет найденное. Он создан, чтобы **за один запуск довести свежую VM до защищённого состояния**, а существующие машины проверять, не меняя в них ничего.

Никаких зависимостей. Никаких агентов. Никаких демонов. Только Bash — гарантированно работает на **любой версии Ubuntu**, а в режиме best effort — на Debian, RHEL/CentOS/Alma/Rocky, Fedora, Arch, openSUSE и других.

## ⚡ Быстрый старт

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

Работает и от **root** (полное покрытие), и от **обычного пользователя** (покрытие меньше, и это явно отражается в отчёте).

## 🔍 Что проверяется — 70+ проверок

**Вредоносное ПО и руткиты**
- известные имена процессов и командные строки вредоносов и криптомайнеров (xmrig, kinsing, kdevtmpfsi, …)
- процессы, запущенные из `/tmp`, `/dev/shm`, процессы с удалёнными бинарниками, бесфайловые исполняемые объекты `memfd`
- скрытые процессы (тест на ядерные руткиты, прячущиеся от readdir), подозрительные модули ядра
- векторы userland-руткитов `/etc/ld.so.preload` и `LD_PRELOAD`
- реверс-шеллы, дропперы и сигнатуры майнеров в скриптах, cron-заданиях, юнитах systemd, профилях шелла, правилах udev, MOTD-скриптах
- скрытые исполняемые файлы в `/tmp`, `/var/tmp`, `/dev/shm`, `/dev`
- проверка целостности ключевых системных бинарников по контрольным суммам пакетов (`dpkg -V` / `rpm -V`)
- опциональные глубокие проверки с помощью **ClamAV**, **rkhunter**, **chkrootkit** (определяются автоматически, ставятся одним флагом)

**Сеть**
- каждый прослушиваемый порт с процессом и анализом доступности (loopback или весь мир)
- опасные открытые наружу сервисы: Telnet, Redis/Mongo/Elasticsearch без аутентификации, Docker API на :2375, SMB, RDP, VNC, r-сервисы…
- установленные соединения с известными портами майнинг-пулов и IRC-ботнетов
- состояние фаервола: UFW, firewalld, nftables, «голый» iptables — включая покрытие IPv6
- интерфейсы в promiscuous-режиме, признаки ARP-спуфинга, DNS-резолверы, подмены в `/etc/hosts`

**Система**
- аудит SSH-демона: вход под root, парольная аутентификация, пустые пароли, X11, таймауты, число попыток
- учётные записи: лишние пользователи с UID 0, пустые пароли, дублирующиеся UID, системные аккаунты с шеллом, sudo с NOPASSWD, следы брутфорса
- ожидающие обновления безопасности, unattended-upgrades, обнаружение EOL-релизов, необходимость перезагрузки
- усиление ядра через sysctl: ASLR, syncookies, редиректы, source routing, область действия ptrace, ограничения dmesg/kptr…
- права на файлы: `/etc/shadow`, sudoers, хост-ключи SSH, crontab, GRUB; аудит SUID/SGID по белому списку; файлы и каталоги, доступные на запись всем; файлы без владельца; вредоносные блокировки флагом immutable
- ревизия точек закрепления: cron, юниты systemd, `rc.local`, `at`, файлы автозапуска шелла, `authorized_keys` каждого пользователя (включая системные аккаунты), сторонние APT-репозитории
- AppArmor/SELinux, auditd, синхронизация NTP, постоянное журналирование, core-дампы, опции монтирования `/dev/shm` и `/tmp`, митигации уязвимостей CPU, безопасность Docker (права на сокет, привилегированные контейнеры, группа docker)

## 🧰 Режимы

| Команда | Что делает |
|---|---|
| `sudo bash antivirus.sh` | интерактивный режим: каждое исправление показывается и подтверждается |
| `--audit` | только отчёт — гарантированно ноль изменений |
| `--fix` | автоматически применить все безопасные исправления |
| `--harden` | полное усиление защиты свежей VM: фаервол, SSH, fail2ban, sysctl, автообновления, auditd, политики + предложение создать пользователя-администратора |
| `--create-user` | пошаговое создание sudo-пользователя с SSH-ключом |
| `--scan /path` | проверить на вредоносное ПО конкретный каталог |
| `--network` / `--system` / `--malware` | запустить только одну область |
| `--rollback` | откатить все изменения последнего запуска |
| `--quick` / `--full` | быстрее / максимально глубоко |
| `--report file.txt` | сохранить отчёт |

## 🛟 Принципы безопасности

Исправления, способные отрезать удалённый доступ, **никогда не применяются молча**:

- перед включением фаервола **заранее разрешаются ваши SSH-порты** (определяются из конфигурации sshd, активных сокетов и `$SSH_CONNECTION`);
- `PasswordAuthentication no` **отклоняется**, если ни у одного пользователя с правами sudo на самом деле нет SSH-ключа;
- каждая новая конфигурация sshd проверяется через `sshd -t` **до** перезагрузки сервиса — некорректные конфигурации откатываются автоматически, а существующие сессии никогда не разрываются;
- каждый изменяемый файл резервируется; `--rollback` восстанавливает всё;
- подозрительные файлы **отправляются в карантин** (перемещение + `chmod 000`), а не удаляются.

Коды возврата: `0` — чисто · `1` — предупреждения · `2` — критические находки; удобно для cron и CI.

## 📊 Пример вывода

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

## 📚 Полная документация

Подробный каталог проверок, FAQ, руководство по усилению защиты и примеры: **[https://antivirus.sh/ru/](https://antivirus.sh/ru/)**

## ⚠️ Отказ от ответственности

`antivirus.sh` — это защитный инструмент аудита и харденинга. Он сокращает поверхность атаки и обнаруживает типичные признаки компрометации, но не гарантирует защиту от любой угрозы. Если машина скомпрометирована на уровне ядра, единственное надёжное решение — пересборка из чистого образа.

## 📄 Лицензия

[MIT](LICENSE) — свободно для личного и коммерческого использования.

**Если инструмент вам помог, поставьте ⭐ репозиторию и расскажите про [antivirus.sh](https://antivirus.sh).**

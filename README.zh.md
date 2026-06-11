# antivirus.sh

<div align="center">

**单个 Bash 脚本实现的 Linux 杀毒与恶意软件扫描器。**

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

[English](README.md) | [Русский](README.ru.md) | [Español](README.es.md) | 中文 | [日本語](README.ja.md) | [한국어](README.ko.md) | [Deutsch](README.ge.md) | [العربية](README.ar.md) | [Français](README.fr.md) | [Italiano](README.it.md)

</div>

---

`antivirus.sh` 是一个面向 Linux 服务器的自包含 Bash 扫描器。它主要检查恶意文件、持久化点、可疑进程、软件包完整性、基础网络指标，并将可疑文件安全隔离。本仓库仅包含从更大 `antivirus.sh` 安全套件中拆分出的杀毒部分。

README 结构参考项目：<https://github.com/ultra-x-coder/antivirus.sh/>

## 快速开始

```bash
chmod +x antivirus.sh
sudo bash antivirus.sh
sudo bash antivirus.sh --audit
sudo bash antivirus.sh --fix
sudo bash antivirus.sh --scan /var/www
sudo bash antivirus.sh --full
```

## 检查内容

- 反弹 shell、下载器、矿工程序和常见后门模式
- `/tmp`、`/var/tmp`、`/dev/shm` 中的隐藏或可执行载荷
- 已知恶意进程名、矿工命令行、`memfd` 无文件进程
- cron、systemd、`rc.local`、shell 启动文件、udev、`authorized_keys` 持久化
- 指向矿池或 IRC 僵尸网络常见端口的外连
- 通过 `dpkg -V` 或 `rpm -V` 校验关键系统二进制完整性
- 已安装时可调用 ClamAV、rkhunter、chkrootkit 深度扫描

## 模式

| 命令 | 说明 |
| --- | --- |
| `sudo bash antivirus.sh` | 交互模式，逐项确认修复。 |
| `sudo bash antivirus.sh --audit` | 只读审计，不做任何修改。 |
| `sudo bash antivirus.sh --fix` | 自动应用安全修复。 |
| `sudo bash antivirus.sh --install-tools` | 安装 ClamAV、rkhunter、chkrootkit。 |

## 选项

`--scan PATH`、`--exclude PATH`、`--quick`、`--full`、`--yes`、`--no-external`、`--report FILE`、`--no-color`、`--version`、`--help`

## 安全说明

- 可疑文件会进入隔离区，不会直接删除。
- 生产环境建议先使用 `--audit`。
- 以 `root` 运行可获得完整覆盖。

## 输出位置

- 退出码：`0` 干净，`1` 警告，`2` 严重发现
- `root` 报告：`/var/log/antivirus-whole/`
- `root` 隔离区：`/var/lib/antivirus-whole/quarantine/`
- 非 root：`~/.antivirus-whole/log/` 与 `~/.antivirus-whole/quarantine/`

## 许可证

MIT，以脚本头部声明为准。

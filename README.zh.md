<div align="center">

# 🛡️ antivirus.sh

**一个脚本，搞定 Linux 全面安全：恶意软件扫描、网络审计、系统加固。**

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Shell](https://img.shields.io/badge/100%25-Bash-blue.svg)](antivirus.sh)
[![Platform](https://img.shields.io/badge/Platform-Linux-orange.svg)](https://antivirus.sh)
[![Ubuntu](https://img.shields.io/badge/Ubuntu-any%20version-E95420.svg)](https://antivirus.sh)

🌐 **官网与完整文档：[antivirus.sh](https://antivirus.sh/zh/)**

[English](README.md) | [Русский](README.ru.md) | [中文](README.zh.md) | [한국어](README.ko.md) | [日本語](README.ja.md) | [Italiano](README.it.md) | [Español](README.es.md) | [Deutsch](README.de.md) | [العربية](README.ar.md) | [Français](README.fr.md)

</div>

---

`antivirus.sh` 是一个完全独立的 Bash 脚本：扫描 Linux 服务器上的恶意软件，审计网络与系统安全，并且——只要你愿意——直接修复发现的问题。它的目标是**一次运行就把全新虚拟机带入加固状态**，同时也能在不做任何改动的前提下审计现有机器。

零依赖、无 agent、无守护进程，纯 Bash——保证在**所有 Ubuntu 版本**上可用，并在 Debian、RHEL/CentOS/Alma/Rocky、Fedora、Arch、openSUSE 等发行版上尽力兼容。

## ⚡ 快速开始

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

以 **root** 运行可获得完整覆盖，以**普通用户**运行时覆盖范围会缩小（并会明确标注哪些项被跳过）。

## 🔍 检查内容 —— 70+ 项检查

**恶意软件与 rootkit**
- 已知恶意软件/挖矿进程的名称与命令行特征（xmrig、kinsing、kdevtmpfsi……）
- 从 `/tmp`、`/dev/shm` 运行的进程、二进制已被删除的进程、无文件 `memfd` 可执行体
- 隐藏进程（readdir 隐藏型内核 rootkit 测试）、可疑内核模块
- `/etc/ld.so.preload` 与 `LD_PRELOAD` 用户态 rootkit 注入向量
- 脚本、cron 任务、systemd 单元、shell 配置文件、udev 规则、MOTD 脚本中的反弹 shell、dropper 与挖矿特征
- `/tmp`、`/var/tmp`、`/dev/shm`、`/dev` 中的隐藏可执行文件
- 核心系统二进制与软件包校验和的完整性比对（`dpkg -V` / `rpm -V`）
- 可选的深度扫描：**ClamAV**、**rkhunter**、**chkrootkit**（自动检测，一个参数即可安装）

**网络**
- 列出每个监听端口及其所属进程，并分析暴露面（仅回环 vs 对外开放）
- 危险的对外暴露服务：Telnet、未鉴权的 Redis/Mongo/Elasticsearch、Docker API :2375、SMB、RDP、VNC、r-services……
- 与已知矿池/IRC 僵尸网络端口建立的连接
- 防火墙状态：UFW、firewalld、nftables、原生 iptables——包括 IPv6 覆盖情况
- 混杂模式网卡、ARP 欺骗迹象、DNS 解析器、`/etc/hosts` 劫持

**系统**
- SSH 服务审计：root 登录、密码认证、空密码、X11、超时、重试次数
- 账户：多余的 UID 0 用户、空密码、重复 UID、带 shell 的系统账户、NOPASSWD sudo、暴力破解痕迹
- 待安装的安全更新、unattended-upgrades、EOL 版本检测、reboot-required
- sysctl 内核加固：ASLR、syncookies、重定向、源路由、ptrace scope、dmesg/kptr 限制……
- 文件权限：`/etc/shadow`、sudoers、SSH 主机密钥、crontab、GRUB；基于白名单的 SUID/SGID 审计；全局可写的文件与目录；无主文件；immutable 标志型恶意软件锁定
- 持久化排查：cron、systemd 单元、`rc.local`、`at`、shell 启动文件、所有用户（含系统账户）的 `authorized_keys`、第三方 APT 仓库
- AppArmor/SELinux、auditd、NTP 同步、持久化日志、core dump、`/dev/shm` 与 `/tmp` 挂载选项、CPU 漏洞缓解、Docker 安全（socket 权限、特权容器、docker 用户组）

## 🧰 运行模式

| 命令 | 作用 |
|---|---|
| `sudo bash antivirus.sh` | 交互模式：每项修复都先展示、再确认 |
| `--audit` | 仅生成报告——保证零改动 |
| `--fix` | 自动应用所有安全的修复 |
| `--harden` | 全面加固全新虚拟机：防火墙、SSH、fail2ban、sysctl、自动更新、auditd、安全策略，并可顺带创建管理员用户 |
| `--create-user` | 引导式创建带 SSH 密钥的 sudo 用户 |
| `--scan /path` | 对指定目录做恶意软件扫描 |
| `--network` / `--system` / `--malware` | 只运行某一类检查 |
| `--rollback` | 撤销上次运行的全部改动 |
| `--quick` / `--full` | 更快 / 最深入的扫描 |
| `--report file.txt` | 保存报告 |

## 🛟 安全设计

凡是可能切断远程访问的修复，**绝不会被静默执行**：

- 启用防火墙前会**先放行你的 SSH 端口**（综合解析 sshd 配置、实时套接字与 `$SSH_CONNECTION`）；
- 除非确有具备 sudo 权限的用户配置了 SSH 密钥，否则**拒绝**设置 `PasswordAuthentication no`；
- 每份新的 sshd 配置都会在重载**之前**用 `sshd -t` 校验——无效配置自动回退，现有会话绝不掉线；
- 每个被修改的文件都有备份；`--rollback` 可恢复一切；
- 可疑文件只做**隔离**（移走并 `chmod 000`），绝不删除。

退出码：`0` 干净 · `1` 有警告 · `2` 发现严重问题——便于接入 cron/CI。

## 📊 输出示例

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

## 📚 完整文档

详尽的检查目录、FAQ、加固指南与示例：**[https://antivirus.sh/zh/](https://antivirus.sh/zh/)**

## ⚠️ 免责声明

`antivirus.sh` 是一款防御性的审计与加固工具。它能缩小攻击面、检测常见的入侵特征，但并不能保证抵御所有威胁。对于已确认存在内核级入侵的机器，唯一安全的处置方式是用干净镜像重建系统。

## 📄 许可证

[MIT](LICENSE) —— 个人和商业使用均免费。

**如果这个工具帮到了你，请给仓库点个 ⭐ Star，并把 [antivirus.sh](https://antivirus.sh) 分享出去。**
